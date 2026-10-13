use super::*;
use crate::fs::read_text;
use crate::platform::{
    BackendPaths, Engine, InstalledCores, PlatformCapabilities, StartDataPath, StopDataPath,
};
use crate::testutil::sample_vless;
use kasumi_core::contract::{RunState, ServiceState};
use kasumi_core::enums::CoreEngine;
use kasumi_core::state::{ProxyMode, default_app_state};
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tempfile::TempDir;

/// Records lifecycle calls and reports a running state on demand.
struct RecordingPlatform {
    paths: BackendPaths,
    calls: StdMutex<Vec<String>>,
    running: AtomicBool,
    /// When set, `start_data_path` parks until `release` so a test can act while
    /// a start is in flight.
    hold_start: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    /// The running core's `force-in` port the connectivity probe goes through;
    /// 0 = no proxy to probe.
    core_socks: AtomicU16,
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
                hold_start: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                core_socks: AtomicU16::new(0),
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
    fn supports_proxy_modes(&self) -> bool {
        true
    }
    async fn set_os_proxy(&self, mode: ProxyMode, _engine: Engine, _socks_port: u16) {
        self.log(&format!("os_proxy:{mode:?}"));
    }
    async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
        self.log(&format!("start:{:?}", opts.engine));
        if self.hold_start.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
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
            tether_offload_bypass: false,
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
        let port = self.core_socks.load(Ordering::SeqCst);
        Ok(crate::net::ProxyStatus {
            running: port != 0 && self.running.load(Ordering::SeqCst),
            socks_port: port,
            http_port: 0,
            force_port: port,
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
    assert!(
        platform
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "stop:keep=false")
    );
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

/// Mutate the persisted settings through the service (the UI's write path).
async fn set_settings(svc: &Service, edit: impl FnOnce(&mut kasumi_core::state::AdvancedSettings)) {
    let Response::State(state) = svc.dispatch(Command::ReadState).await.unwrap() else {
        panic!()
    };
    let mut settings = state.settings.clone();
    edit(&mut settings);
    svc.dispatch(Command::Mutate {
        intent: Box::new(kasumi_core::mutate::MutationIntent::SetSettings {
            settings: Box::new(settings),
        }),
    })
    .await
    .unwrap();
}

async fn pending_restart(svc: &Service) -> bool {
    svc.current_status().await.unwrap().pending_restart
}

#[tokio::test]
async fn config_mutation_flags_pending_restart_until_restart() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    assert!(!pending_restart(&svc).await);

    // A setting that lands in the built core config → the running path is stale.
    let mut rx = svc.subscribe();
    set_settings(&svc, |s| s.fragment = true).await;
    assert!(pending_restart(&svc).await);
    // The flag flip pushed a status frame immediately.
    let PushFrame::Status { value } = rx.recv().await.unwrap() else {
        panic!("expected status")
    };
    assert!(value.pending_restart);

    // Reverting the edit settles the running path back to non-stale.
    set_settings(&svc, |s| s.fragment = false).await;
    assert!(!pending_restart(&svc).await);

    // Restart applies whatever is saved and clears the flag.
    set_settings(&svc, |s| s.fragment = true).await;
    assert!(pending_restart(&svc).await);
    svc.dispatch(Command::Restart { profile_id: None })
        .await
        .unwrap();
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn ui_only_mutation_keeps_pending_restart_clear() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();

    // None of these settings reaches the built config: no restart needed.
    set_settings(&svc, |s| {
        s.delay_test_url = Some("https://probe.example/gen".into())
    })
    .await;
    set_settings(&svc, |s| s.log_rotate_max_kb = 1024).await;
    set_settings(&svc, |s| s.connectivity_check = false).await;
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn mutation_while_stopped_keeps_pending_restart_clear() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

    // Nothing runs, so nothing can be stale — even for a config-level edit.
    set_settings(&svc, |s| s.fragment = true).await;
    assert!(!pending_restart(&svc).await);

    // A start from the mutated state runs it as saved: still nothing pending.
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    assert!(!pending_restart(&svc).await);

    // Stop drops the baseline and the flag stays down for later edits.
    svc.dispatch(Command::Stop).await.unwrap();
    set_settings(&svc, |s| s.fragment = false).await;
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn non_tun_mode_switch_applies_live_without_pending_restart() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

    set_settings(&svc, |s| s.proxy_mode = ProxyMode::ProxyOnly).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    platform.calls.lock().unwrap().clear();

    // proxy-only → system: identical build, no tun involved — re-point the OS
    // proxy live instead of demanding a restart.
    set_settings(&svc, |s| s.proxy_mode = ProxyMode::System).await;
    assert!(!pending_restart(&svc).await);
    assert!(
        platform
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "os_proxy:System")
    );

    // system → tun crosses the tun boundary: a restart is required.
    set_settings(&svc, |s| s.proxy_mode = ProxyMode::Tun).await;
    assert!(pending_restart(&svc).await);
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

/// Save two profiles, the first active and the second with id `b`.
async fn seed_two(platform: &RecordingPlatform) {
    let a = sample_vless();
    let mut b = crate::testutil::vless_at(8443);
    b.meta_mut().id = "b".into();
    let mut state = default_app_state();
    state.active_id = Some(a.meta().id.clone());
    state.profiles = vec![a, b];
    crate::state::write_app_state(platform, &state)
        .await
        .unwrap();
}

/// Save `id` as the active profile without restarting — the first half of a
/// UI profile switch.
async fn save_active(svc: &Service, id: &str) {
    svc.dispatch(Command::Mutate {
        intent: Box::new(kasumi_core::mutate::MutationIntent::SetActive {
            id: Some(id.into()),
        }),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn profile_switch_restart_never_shows_pending_restart() {
    let (platform, _d) = RecordingPlatform::new();
    seed_two(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();

    // The UI switches by saving the new active id, then starting it. On its own
    // the saved switch is stale against what runs.
    save_active(&svc, "b").await;
    assert!(pending_restart(&svc).await);

    // Once the switching start is under way nothing is pending — not even for
    // an edit that lands mid-start.
    platform.hold_start.store(true, Ordering::SeqCst);
    let starting = tokio::spawn({
        let svc = Arc::clone(&svc);
        async move {
            svc.dispatch(Command::Start {
                profile_id: Some("b".into()),
            })
            .await
        }
    });
    platform.entered.notified().await;
    assert!(!pending_restart(&svc).await);
    set_settings(&svc, |s| s.fragment = true).await;
    assert!(!pending_restart(&svc).await);

    // The start built its config before that edit, so once it lands the edit is
    // the one thing still unapplied.
    platform.release.notify_one();
    starting.await.unwrap().unwrap();
    assert!(pending_restart(&svc).await);

    // A plain switch-and-start with nothing else edited ends clean.
    platform.hold_start.store(false, Ordering::SeqCst);
    svc.dispatch(Command::Restart { profile_id: None })
        .await
        .unwrap();
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn reachable_verdict_carries_latency_until_restart() {
    let (_d, svc, _core) = running_first_of_two().await;

    svc.dispatch(Command::ProbeConnection).await.unwrap();
    let status = svc.current_status().await.unwrap();
    assert_eq!(status.service.state, RunState::Connected);
    assert!(status.latency_ms.is_some());

    // A restart replaces the core: the old verdict and its latency are dropped.
    svc.dispatch(Command::Restart { profile_id: None })
        .await
        .unwrap();
    let status = svc.current_status().await.unwrap();
    assert_eq!(status.service.state, RunState::Connecting);
    assert_eq!(status.latency_ms, None);
}

/// Stands in for the running core's SOCKS5 inbound: every CONNECT succeeds and
/// the tunnelled HTTP request gets a 204. With `hold` set, the reply waits for
/// `release` so a test can act while a probe is in flight.
struct FakeCoreSocks {
    port: u16,
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl FakeCoreSocks {
    /// Listen on a free port and point `platform`'s proxy status at it.
    async fn attach(platform: &RecordingPlatform) -> Arc<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let this = Arc::new(Self {
            port: listener.local_addr().unwrap().port(),
            hold: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        platform.core_socks.store(this.port, Ordering::SeqCst);
        let server = Arc::clone(&this);
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let server = Arc::clone(&server);
                tokio::spawn(async move {
                    let _ = server.serve(&mut conn).await;
                });
            }
        });
        this
    }

    async fn serve(&self, s: &mut tokio::net::TcpStream) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        // Greeting: VER NMETHODS METHODS… → no auth.
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await?;
        s.read_exact(&mut vec![0u8; head[1].into()]).await?;
        s.write_all(&[5, 0]).await?;
        // Request: VER CMD RSV ATYP ADDR PORT → succeeded.
        let mut req = [0u8; 4];
        s.read_exact(&mut req).await?;
        let addr_len = match req[3] {
            1 => 4,
            4 => 16,
            _ => usize::from(s.read_u8().await?),
        };
        s.read_exact(&mut vec![0u8; addr_len + 2]).await?;
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut http = Vec::new();
        while !http.ends_with(b"\r\n\r\n") {
            http.push(s.read_u8().await?);
        }
        if self.hold.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
    }
}

/// Two saved profiles with the first one running behind a [`FakeCoreSocks`].
async fn running_first_of_two() -> (TempDir, Arc<Service>, Arc<FakeCoreSocks>) {
    let (platform, dir) = RecordingPlatform::new();
    seed_two(&platform).await;
    let core = FakeCoreSocks::attach(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    set_settings(&svc, |s| {
        s.delay_test_url = Some("http://probe.example/generate_204".into())
    })
    .await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    (dir, svc, core)
}

#[tokio::test]
async fn saved_switch_does_not_inherit_the_running_profiles_ping() {
    let (_d, svc, _core) = running_first_of_two().await;
    let mut rx = svc.subscribe();

    assert!(matches!(
        svc.dispatch(Command::ProbeConnection).await.unwrap(),
        Response::Ping(Some(_))
    ));
    let status = svc.current_status().await.unwrap();
    assert_eq!(status.service.state, RunState::Connected);
    assert!(status.latency_ms.is_some());

    // The switch is saved, the old profile's core still runs: nothing measured
    // the new one yet — not in the frame the save pushes, nor after re-probing
    // the old core.
    save_active(&svc, "b").await;
    let pushed = loop {
        if let PushFrame::Status { value } = rx.recv().await.unwrap()
            && value.active_id.as_deref() == Some("b")
        {
            break value;
        }
    };
    assert_eq!(pushed.latency_ms, None);
    assert_eq!(pushed.service.state, RunState::Connecting);
    svc.dispatch(Command::ProbeConnection).await.unwrap();
    let status = svc.current_status().await.unwrap();
    assert_eq!(status.active_id.as_deref(), Some("b"));
    assert_eq!(status.latency_ms, None);
    assert_eq!(status.service.state, RunState::Connecting);

    // Once the new profile runs, its own probe is reported.
    svc.dispatch(Command::Start {
        profile_id: Some("b".into()),
    })
    .await
    .unwrap();
    svc.dispatch(Command::ProbeConnection).await.unwrap();
    let status = svc.current_status().await.unwrap();
    assert_eq!(status.service.state, RunState::Connected);
    assert!(status.latency_ms.is_some());
}

#[tokio::test]
async fn probe_in_flight_across_a_saved_switch_is_not_reported_for_the_new_profile() {
    let (_d, svc, core) = running_first_of_two().await;

    core.hold.store(true, Ordering::SeqCst);
    let probing = tokio::spawn({
        let svc = Arc::clone(&svc);
        async move { svc.dispatch(Command::ProbeConnection).await }
    });
    tokio::time::timeout(Duration::from_secs(5), core.entered.notified())
        .await
        .expect("probe reached the core");
    save_active(&svc, "b").await;
    core.release.notify_one();
    probing.await.unwrap().unwrap();

    let status = svc.current_status().await.unwrap();
    assert_eq!(status.active_id.as_deref(), Some("b"));
    assert_eq!(status.latency_ms, None);
    assert_eq!(status.service.state, RunState::Connecting);
}

#[tokio::test]
async fn check_off_trusts_the_process_state() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    set_settings(&svc, |s| s.connectivity_check = false).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();

    let status = svc.current_status().await.unwrap();
    assert_eq!(status.service.state, RunState::Connected);
    assert_eq!(status.latency_ms, None);
}

#[tokio::test]
async fn probe_connection_without_a_running_proxy_is_no_result() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    let reply = svc.dispatch(Command::ProbeConnection).await.unwrap();
    assert!(matches!(reply, Response::Ping(None)));
}
