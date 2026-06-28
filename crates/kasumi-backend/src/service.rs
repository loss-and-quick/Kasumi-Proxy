//! The `Service`: one owner of the data-path lifecycle, shared by both shells.
//!
//! It serializes lifecycle jobs through a single lock so a restart can't interleave
//! with a concurrent start/stop, drives the headless sub-updater, auto-starts on
//! boot, re-pins on uplink changes, and watchdogs a dead data-path. There is no
//! control socket — lifecycle commands are in-process calls. It also owns the
//! status/`subApplied` event stream both
//! transports subscribe to (desktop re-emits via Tauri, Android over WS).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::sync::{broadcast, Mutex};

use kasumi_core::contract::{FetchMode, PushFrame, RunState, ServiceStatus, SubAppliedEvent};
use kasumi_core::state::{AppState, DEFAULT_DELAY_TEST_URL};

use crate::commands::{self, Command, CommandError, Response};
use crate::fs::read_text;
use crate::fsjson::read_json;
use crate::lifecycle::resolve_and_write_config;
use crate::net::{fetch_url, FetchUrlOptions};
use crate::platform::{Platform, StartDataPath, StopDataPath};
use crate::sub_update::{self, LifecycleControl};

/// Result of the latest end-to-end connectivity probe (a fetch through the active
/// core's SOCKS). `Unknown` until the first probe lands after the core comes up.
#[derive(Debug, Clone, PartialEq)]
enum Connectivity {
    Unknown,
    Reachable,
    Unreachable(String),
}

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);
const EVENT_CHANNEL_CAP: usize = 64;

/// The lifecycle operations, run directly (no locking) by [`Service`]. Callers that
/// need serialization take the lock first.
#[derive(Debug, Clone)]
enum LifecycleCmd {
    Start(Option<String>),
    Stop,
    Restart(Option<String>),
    ReloadAppFilter,
}

pub struct Service {
    platform: Arc<dyn Platform>,
    /// The single in-flight lifecycle chain; held across a start/stop/restart.
    serialize: Mutex<()>,
    /// Serializes `Mutate` writes so two concurrent edits (both transports dispatch
    /// each command on its own task) can't read-modify-write over each other.
    state_write: Mutex<()>,
    events: broadcast::Sender<PushFrame>,
    /// Installed core version labels, probed once at construction.
    cores: crate::platform::InstalledCores,
    /// Per-subscription last fetch attempt (ms), for the updater's backoff.
    sub_attempts: Mutex<HashMap<String, i64>>,
    auto_started: AtomicBool,
    /// Latest connectivity-probe result; the watchdog refreshes it, `current_status`
    /// overlays it onto a process-up state to tell Connected from NoInternet.
    connectivity: StdMutex<Connectivity>,
}

impl Service {
    /// Build a service over `platform`, probing core versions once for status labels.
    pub async fn new(platform: Arc<dyn Platform>) -> Arc<Self> {
        let cores = platform
            .capabilities()
            .await
            .map(|c| c.cores)
            .unwrap_or_default();
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAP);
        Arc::new(Self {
            platform,
            serialize: Mutex::new(()),
            state_write: Mutex::new(()),
            events,
            cores,
            sub_attempts: Mutex::new(HashMap::new()),
            auto_started: AtomicBool::new(false),
            connectivity: StdMutex::new(Connectivity::Unknown),
        })
    }

    pub fn platform(&self) -> &dyn Platform {
        &*self.platform
    }

    /// Subscribe to the status / `subApplied` event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<PushFrame> {
        self.events.subscribe()
    }

    /// Run one command. Lifecycle commands go through the serialized chain; every
    /// other command is the stateless dispatch.
    pub async fn dispatch(&self, cmd: Command) -> Result<Response, CommandError> {
        match cmd {
            Command::Start { profile_id } => self.serialized(LifecycleCmd::Start(profile_id)).await,
            Command::Stop => self.serialized(LifecycleCmd::Stop).await,
            Command::Restart { profile_id } => {
                self.serialized(LifecycleCmd::Restart(profile_id)).await
            }
            Command::ReloadAppFilter => self.serialized(LifecycleCmd::ReloadAppFilter).await,
            Command::Mutate { intent } => {
                // Hold the state-write lock across the whole read-modify-write so
                // concurrent edits serialize into one consistent result.
                let _g = self.state_write.lock().await;
                let state = commands::run_mutation(&*self.platform, &intent).await?;
                Ok(Response::State(Box::new(state)))
            }
            Command::ApplySubscription { sub_id } => {
                let state = sub_update::update_subscription(
                    &*self.platform,
                    self,
                    &self.serialize,
                    &sub_id,
                )
                .await
                .map_err(CommandError)?;
                self.emit_status().await;
                Ok(Response::State(Box::new(state)))
            }
            other => commands::dispatch(&*self.platform, other).await,
        }
    }

    /// Run a lifecycle command under the serializer, then emit the new status.
    async fn serialized(&self, lc: LifecycleCmd) -> Result<Response, CommandError> {
        {
            let _g = self.serialize.lock().await;
            self.run_lifecycle(lc).await.map_err(CommandError)?;
        }
        self.emit_status().await;
        Ok(Response::Ok)
    }

    /// The lifecycle switch, run without the lock (the caller holds it).
    async fn run_lifecycle(&self, cmd: LifecycleCmd) -> Result<(), String> {
        match cmd {
            LifecycleCmd::Start(id) | LifecycleCmd::Restart(id) => {
                self.platform
                    .stop_data_path(StopDataPath {
                        keep_service_state: true,
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                let (engine, socks_port) = resolve_and_write_config(&*self.platform, id.as_deref())
                    .await
                    .map_err(|e| e.0)?;
                self.platform
                    .start_data_path(StartDataPath { engine, socks_port })
                    .await
                    .map_err(|e| e.to_string())
            }
            LifecycleCmd::Stop => self
                .platform
                .stop_data_path(StopDataPath::default())
                .await
                .map_err(|e| e.to_string()),
            LifecycleCmd::ReloadAppFilter => {
                // xray reloads per-uid rules live; sing-box bakes them into the
                // config and needs a full restart.
                let engine = read_text(&self.platform.paths().engine_file)
                    .await
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default();
                if engine == "sing-box" {
                    self.platform
                        .stop_data_path(StopDataPath {
                            keep_service_state: true,
                        })
                        .await
                        .map_err(|e| e.to_string())?;
                    let (engine, socks_port) = resolve_and_write_config(&*self.platform, None)
                        .await
                        .map_err(|e| e.0)?;
                    self.platform
                        .start_data_path(StartDataPath { engine, socks_port })
                        .await
                        .map_err(|e| e.to_string())
                } else if let Some(f) = self.platform.app_filter() {
                    f.reload_app_filter().await.map_err(|e| e.to_string())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Build the full status frame (runtime facts + active id + running-core label).
    /// `None` when the platform's state probe fails. Both shells use it for the
    /// initial frame a client gets on connect.
    pub async fn current_status(&self) -> Option<ServiceStatus> {
        let mut service = self.platform.service_state().await.ok()?;
        // The platform reports process-truth (Connecting once the core is up). Refine
        // it with the latest connectivity probe: a running core that actually reaches
        // the internet is Connected; one that can't is NoInternet; before the first
        // probe lands it stays Connecting.
        if service.state == RunState::Connecting && service.engine.is_some() {
            match &*self.connectivity.lock().unwrap() {
                Connectivity::Reachable => service.state = RunState::Connected,
                Connectivity::Unreachable(reason) => {
                    service.state = RunState::NoInternet;
                    service.error = Some(reason.clone());
                }
                Connectivity::Unknown => {}
            }
        }
        let active_id = read_json::<AppState>(&self.platform.paths().app_state)
            .await
            .and_then(|s| s.active_id);
        let core = match service.engine {
            Some(kasumi_core::enums::CoreEngine::Xray) => self.cores.xray.clone(),
            Some(kasumi_core::enums::CoreEngine::SingBox) => self.cores.singbox.clone(),
            None => None,
        }
        .unwrap_or_default();
        Some(ServiceStatus {
            service,
            active_id,
            core,
        })
    }

    async fn emit_status(&self) {
        if let Some(status) = self.current_status().await {
            let _ = self.events.send(PushFrame::Status { value: status });
        }
    }

    /// One end-to-end connectivity probe through the active core's SOCKS — the same
    /// fetch a real client would do, so it tells whether the proxy actually reaches
    /// the internet (Connected) or only looks up (NoInternet). Engine-agnostic.
    async fn probe_connectivity(&self) -> Connectivity {
        let proxy = match self.platform.proxy_status().await {
            Ok(p) if p.running => p,
            _ => return Connectivity::Unknown,
        };
        let url = read_json::<AppState>(&self.platform.paths().app_state)
            .await
            .and_then(|s| s.settings.delay_test_url)
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_DELAY_TEST_URL.to_owned());
        match fetch_url(
            &url,
            FetchUrlOptions {
                mode: FetchMode::Proxy,
                proxy: Some(proxy),
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .await
        {
            Ok(_) => Connectivity::Reachable,
            Err(e) => {
                // Root cause, capped — e.g. "connection timed out", "connection refused".
                let reason = e.to_string();
                let reason = reason.chars().take(120).collect::<String>();
                Connectivity::Unreachable(reason)
            }
        }
    }

    /// Store the connectivity verdict; returns whether it changed (so a caller only
    /// re-emits status when there's something new).
    fn set_connectivity(&self, c: Connectivity) -> bool {
        let mut guard = self.connectivity.lock().unwrap();
        if *guard != c {
            *guard = c;
            true
        } else {
            false
        }
    }

    /// Start the active profile once on boot, if `autoStart` allows. Caller holds
    /// the lifecycle lock.
    async fn maybe_auto_start(&self) {
        if self.auto_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(state) = read_json::<AppState>(&self.platform.paths().app_state).await else {
            return;
        };
        if state.active_id.is_none() || !state.settings.auto_start {
            return;
        }
        let _ = self.run_lifecycle(LifecycleCmd::Start(None)).await;
    }

    /// Spawn the daemon loops: auto-start, network re-pin, watchdog, sub-updater and
    /// the 1 Hz status push. Both shells call this after construction.
    pub fn spawn_background(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            {
                let _g = this.serialize.lock().await;
                this.maybe_auto_start().await;
            }
            this.emit_status().await;
        });

        self.spawn_network_watch();
        self.spawn_resume_watch();
        self.spawn_watchdog();
        self.spawn_sub_updater();
        self.spawn_status_push();
    }

    /// Restart the data-path if it's up or coming up — re-pinning routing and rebuilding
    /// the core after the network or system changed under it. Returns whether it ran, so
    /// a caller can fall back to the boot auto-start. Takes the lifecycle lock itself.
    async fn restart_if_up(&self) -> bool {
        let _g = self.serialize.lock().await;
        let coming_up = self
            .platform
            .service_state()
            .await
            .ok()
            .map(|s| s.engine.is_some() || s.state == RunState::Connecting)
            .unwrap_or(false);
        if coming_up {
            let _ = self.run_lifecycle(LifecycleCmd::Restart(None)).await;
        }
        coming_up
    }

    fn spawn_network_watch(self: &Arc<Self>) {
        let Some(mut rx) = self.platform.watch_network_change() else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                // Re-pin if the data-path is up; otherwise try the boot auto-start.
                if !this.restart_if_up().await {
                    let _g = this.serialize.lock().await;
                    this.maybe_auto_start().await;
                    drop(_g);
                }
                this.emit_status().await;
            }
        });
    }

    /// Restart the data-path each time the machine wakes from suspend/hibernate: a core
    /// left running across a sleep can hold stale routing/DNS state, and the uplink
    /// watcher doesn't fire when the default route survives the sleep. Driven by the
    /// platform's resume signal (logind `PrepareForSleep(false)` on Linux, a power
    /// notification on Windows); `None` where the platform has no such signal.
    fn spawn_resume_watch(self: &Arc<Self>) {
        let Some(mut rx) = self.platform.watch_system_resume() else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                if this.restart_if_up().await {
                    this.emit_status().await;
                }
            }
        });
    }

    fn spawn_watchdog(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(WATCHDOG_INTERVAL).await;
                let up = this
                    .platform
                    .service_state()
                    .await
                    .map(|s| s.engine.is_some())
                    .unwrap_or(false);
                if !up {
                    if this.set_connectivity(Connectivity::Unknown) {
                        this.emit_status().await;
                    }
                    continue;
                }
                // A dead data-path (core/tun2socks pid gone) is torn down so the UI
                // doesn't show a zombie "connected".
                if this.platform.data_path_healthy().await == Some(false) {
                    let _g = this.serialize.lock().await;
                    let _ = this.platform.stop_data_path(StopDataPath::default()).await;
                    drop(_g);
                    this.set_connectivity(Connectivity::Unknown);
                    this.emit_status().await;
                    continue;
                }
                // Process is up: probe end-to-end connectivity (outside the lifecycle
                // lock — it can take seconds) and re-emit only when the verdict changes.
                let verdict = this.probe_connectivity().await;
                if this.set_connectivity(verdict) {
                    this.emit_status().await;
                }
            }
        });
    }

    fn spawn_sub_updater(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(sub_update::TICK).await;
                let events = this.events.clone();
                let on_applied = move |info: SubAppliedEvent| {
                    let _ = events.send(PushFrame::SubApplied { value: info });
                };
                let mut attempts = this.sub_attempts.lock().await;
                sub_update::tick(
                    &*this.platform,
                    this.as_ref(),
                    &this.serialize,
                    &mut attempts,
                    &on_applied,
                )
                .await;
            }
        });
    }

    fn spawn_status_push(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut last = String::new();
            loop {
                tokio::time::sleep(STATUS_INTERVAL).await;
                if let Some(status) = this.current_status().await {
                    if let Ok(json) = serde_json::to_string(&status) {
                        if json != last {
                            last = json;
                            let _ = this.events.send(PushFrame::Status { value: status });
                        }
                    }
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl LifecycleControl for Service {
    async fn start(&self, profile_id: Option<String>) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::Start(profile_id)).await
    }
    async fn stop(&self) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::Stop).await
    }
    async fn restart(&self, profile_id: Option<String>) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::Restart(profile_id)).await
    }
    async fn reload_app_filter(&self) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::ReloadAppFilter).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        BackendPaths, Engine, InstalledCores, PlatformCapabilities, StartDataPath, StopDataPath,
    };
    use crate::testutil::sample_vless;
    use kasumi_core::contract::ServiceState;
    use kasumi_core::enums::CoreEngine;
    use kasumi_core::state::default_app_state;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    /// Records lifecycle calls and reports a running state on demand.
    struct RecordingPlatform {
        paths: BackendPaths,
        calls: StdMutex<Vec<String>>,
        running: AtomicBool,
    }

    impl RecordingPlatform {
        fn new() -> (Arc<Self>, TempDir) {
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path().to_path_buf();
            let paths = BackendPaths {
                data_dir: d.clone(),
                srs_dir: d.join("srs"),
                dat_dir: d.join("dat"),
                app_state: d.join("app-state.json"),
                profiles: d.join("profiles.json"),
                xray_config: d.join("xray.json"),
                singbox_config: d.join("singbox.json"),
                engine_file: d.join("engine"),
                run_dir: d.join("run"),
                ws_info: d.join("ws.json"),
                webroot: None,
            };
            (
                Arc::new(Self {
                    paths,
                    calls: StdMutex::new(vec![]),
                    running: AtomicBool::new(false),
                }),
                dir,
            )
        }
        fn log(&self, s: &str) {
            self.calls.lock().unwrap().push(s.into());
        }
    }

    #[async_trait::async_trait]
    impl Platform for RecordingPlatform {
        fn paths(&self) -> &BackendPaths {
            &self.paths
        }
        async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
            self.log(&format!("start:{:?}", opts.engine));
            self.running.store(true, Ordering::SeqCst);
            Ok(())
        }
        async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()> {
            self.log(&format!("stop:keep={}", opts.keep_service_state));
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
        async fn service_state(&self) -> anyhow::Result<ServiceState> {
            let running = self.running.load(Ordering::SeqCst);
            Ok(ServiceState {
                // Process-up truth; current_status refines it via the connectivity probe.
                state: if running {
                    RunState::Connecting
                } else {
                    RunState::Stopped
                },
                error: None,
                upload_bytes: 0,
                download_bytes: 0,
                uptime_sec: 0,
                engine: running.then_some(CoreEngine::Xray),
            })
        }
        async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
            Ok(PlatformCapabilities {
                cores: InstalledCores {
                    xray: Some("Xray 1.0".into()),
                    singbox: None,
                },
                tun: true,
                bridge: "test".into(),
            })
        }
        fn core_path(&self, _engine: Engine) -> PathBuf {
            PathBuf::new()
        }
        async fn proxy_status(&self) -> anyhow::Result<crate::net::ProxyStatus> {
            Ok(crate::net::ProxyStatus {
                running: false,
                socks_port: 0,
                http_port: 0,
                force_port: 0,
            })
        }
    }

    async fn seed_active(platform: &RecordingPlatform) {
        let prof = sample_vless();
        let mut state = default_app_state();
        state.active_id = Some(prof.meta().id.clone());
        crate::state::write_app_state(platform, &{
            let mut s = state.clone();
            s.profiles = vec![prof];
            s
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn start_stops_first_then_writes_config_and_starts() {
        let (platform, _d) = RecordingPlatform::new();
        seed_active(&platform).await;
        let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

        let r = svc
            .dispatch(Command::Start { profile_id: None })
            .await
            .unwrap();
        assert!(matches!(r, Response::Ok));
        {
            let calls = platform.calls.lock().unwrap();
            // A start always tears down first (keep_service_state) then spawns the core.
            assert_eq!(calls[0], "stop:keep=true");
            assert!(calls.iter().any(|c| c.starts_with("start:")));
        }
        // Config + engine marker were written.
        assert_eq!(
            read_text(&platform.paths.engine_file).await.as_deref(),
            Some("xray")
        );
    }

    #[tokio::test]
    async fn stop_tears_down_without_keep() {
        let (platform, _d) = RecordingPlatform::new();
        seed_active(&platform).await;
        let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
        svc.dispatch(Command::Stop).await.unwrap();
        assert!(platform
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "stop:keep=false"));
    }

    #[tokio::test]
    async fn status_event_carries_core_label_after_start() {
        let (platform, _d) = RecordingPlatform::new();
        seed_active(&platform).await;
        let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
        let mut rx = svc.subscribe();
        svc.dispatch(Command::Start { profile_id: None })
            .await
            .unwrap();
        // dispatch emits a status frame after the lifecycle change.
        let frame = rx.recv().await.unwrap();
        let PushFrame::Status { value } = frame else {
            panic!("expected status")
        };
        // Process up + no connectivity probe yet → Connecting (refined later).
        assert_eq!(value.service.state, RunState::Connecting);
        assert_eq!(value.core, "Xray 1.0");
        assert!(value.active_id.is_some());
    }

    #[tokio::test]
    async fn concurrent_mutations_serialize_without_lost_update() {
        use kasumi_core::mutate::MutationIntent;
        let (platform, _d) = RecordingPlatform::new();
        crate::state::write_app_state(&*platform, &default_app_state())
            .await
            .unwrap();
        let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

        let mut a = sample_vless();
        a.meta_mut().id = "a".into();
        let mut b = sample_vless();
        b.meta_mut().id = "b".into();

        // Two edits race; without the state-write lock both read the empty list and
        // one overwrites the other. The lock must settle them to both profiles.
        let (r1, r2) = tokio::join!(
            svc.dispatch(Command::Mutate {
                intent: Box::new(MutationIntent::AddProfiles { profiles: vec![a] }),
            }),
            svc.dispatch(Command::Mutate {
                intent: Box::new(MutationIntent::AddProfiles { profiles: vec![b] }),
            }),
        );
        r1.unwrap();
        r2.unwrap();

        let Response::State(state) = svc.dispatch(Command::ReadState).await.unwrap() else {
            panic!()
        };
        let mut ids: Vec<&str> = state
            .profiles
            .iter()
            .map(|p| p.meta().id.as_str())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn stateless_command_still_works_through_service() {
        let (platform, _d) = RecordingPlatform::new();
        let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
        let r = svc.dispatch(Command::Capabilities).await.unwrap();
        let Response::Capabilities(c) = r else {
            panic!()
        };
        assert_eq!(c.xray_version, "Xray 1.0");
    }
}
