use super::*;
use crate::fs::read_text;
use crate::platform::{BackendPaths, Engine, InstalledCores, PlatformCapabilities, StopDataPath};
use crate::testutil::sample_vless;
use kasumi_core::contract::{ConnectionProbe, RunState, ServiceState};
use kasumi_core::data_path_plan::{AppRouting, DataPathPlan, HostTraits};
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
    /// The plan of the last start.
    started: StdMutex<Option<DataPathPlan>>,
    /// Handed out once by `watch_network_change`.
    network: StdMutex<Option<tokio::sync::mpsc::Receiver<()>>>,
    uplink_restarts: AtomicBool,
    /// When set, `stop_data_path` fails and leaves the data path running.
    fail_stop: AtomicBool,
    /// The recorded data path still claims to run but its core process is gone, as
    /// after a crash or an OOM kill.
    core_dead: AtomicBool,
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
                started: StdMutex::new(None),
                network: StdMutex::new(None),
                uplink_restarts: AtomicBool::new(true),
                fail_stop: AtomicBool::new(false),
                core_dead: AtomicBool::new(false),
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
    fn host_traits(&self) -> HostTraits {
        HostTraits {
            proxy_modes: true,
            app_routing: AppRouting::PerProcess,
            pinned_singbox_stack: None,
        }
    }
    async fn set_os_proxy(&self, mode: ProxyMode, _plan: &DataPathPlan) {
        self.log(&format!("os_proxy:{mode:?}"));
    }
    async fn start_data_path(&self, plan: &DataPathPlan) -> anyhow::Result<()> {
        self.log(&format!("start:{:?}", plan.engine));
        *self.started.lock().unwrap() = Some(plan.clone());
        if self.hold_start.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()> {
        self.log(&format!("stop:keep={}", opts.keep_service_state));
        if self.fail_stop.load(Ordering::SeqCst) {
            anyhow::bail!("stop failed");
        }
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
            engine: (running && !self.core_dead.load(Ordering::SeqCst)).then_some(CoreEngine::Xray),
            tether_offload_bypass: false,
        })
    }
    async fn data_path_healthy(&self) -> Option<bool> {
        self.core_dead.load(Ordering::SeqCst).then_some(false)
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
    fn watch_network_change(&self) -> Option<tokio::sync::mpsc::Receiver<()>> {
        self.network.lock().unwrap().take()
    }
    fn uplink_change_restarts(&self, plan: Option<&DataPathPlan>) -> bool {
        let seen = match plan {
            None => "no-plan",
            Some(p) if self.started.lock().unwrap().as_ref() == Some(p) => "running-plan",
            Some(_) => "other-plan",
        };
        self.log(&format!("uplink-check:{seen}"));
        self.uplink_restarts.load(Ordering::SeqCst)
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
    let cfg = read_text(&platform.paths.xray_config).await.unwrap();
    assert!(cfg.contains("outbounds"));
}

/// The lifecycle calls a running data-path gets for one uplink change.
async fn calls_on_uplink_change(restarts: bool) -> Vec<String> {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    platform.uplink_restarts.store(restarts, Ordering::SeqCst);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    *platform.network.lock().unwrap() = Some(rx);
    let svc = Arc::new(Service::new(platform.clone() as Arc<dyn Platform>).await);
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    svc.spawn_network_watch();
    platform.calls.lock().unwrap().clear();
    tx.send(()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(platform.running.load(Ordering::SeqCst));
    platform.calls.lock().unwrap().clone()
}

#[tokio::test]
async fn uplink_change_keeps_the_data_path_where_the_platform_repins_it() {
    let calls = calls_on_uplink_change(false).await;
    assert!(
        !calls
            .iter()
            .any(|c| c.starts_with("stop:") || c.starts_with("start:")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn uplink_change_rebuilds_the_data_path_elsewhere() {
    let calls = calls_on_uplink_change(true).await;
    assert!(calls.iter().any(|c| c.starts_with("stop:")), "{calls:?}");
    assert!(calls.iter().any(|c| c.starts_with("start:")), "{calls:?}");
}

#[tokio::test]
async fn an_uplink_change_waits_for_a_lifecycle_in_flight() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    *platform.network.lock().unwrap() = Some(rx);
    let svc = Arc::new(Service::new(platform.clone() as Arc<dyn Platform>).await);
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    svc.spawn_network_watch();

    // A start holds the lock: the plan it is about to run decides, not the old one.
    let start = svc.serialize.lock().await;
    platform.calls.lock().unwrap().clear();
    tx.send(()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(platform.calls.lock().unwrap().is_empty());
    drop(start);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let calls = platform.calls.lock().unwrap().clone();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("uplink-check:running-plan")
    );
}

#[tokio::test]
async fn the_platform_decides_on_the_plan_that_runs() {
    let calls = calls_on_uplink_change(false).await;
    assert_eq!(
        calls.first().map(String::as_str),
        Some("uplink-check:running-plan")
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

#[tokio::test]
async fn importing_a_backup_reports_the_profiles_left_out() {
    let (platform, _d) = RecordingPlatform::new();
    crate::state::write_app_state(&*platform, &default_app_state())
        .await
        .unwrap();
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    let mut backup = serde_json::to_value(default_app_state()).unwrap();
    backup["profiles"] = serde_json::json!([
        serde_json::to_value(sample_vless()).unwrap(),
        { "protocol": "vless", "meta": { "id": "broken" } },
    ]);
    let cmd: Command = serde_json::from_value(serde_json::json!({
        "cmd": "importBackup", "backup": backup, "mode": "merge"
    }))
    .unwrap();
    let Response::BackupRestored(restored) = svc.dispatch(cmd).await.unwrap() else {
        panic!("expected backupRestored")
    };
    assert_eq!(restored.skipped_profiles, 1);
    assert_eq!(restored.state.profiles.len(), 1);
    let Response::State(state) = svc.dispatch(Command::ReadState).await.unwrap() else {
        panic!()
    };
    assert_eq!(state.profiles.len(), 1);
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
async fn changed_geo_data_flags_pending_restart_until_the_next_start() {
    use crate::updater::LifecycleControl;
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    platform.calls.lock().unwrap().clear();

    let mut rx = svc.subscribe();
    svc.note_assets_changed().await;
    assert!(pending_restart(&svc).await);
    let PushFrame::Status { value } = rx.recv().await.unwrap() else {
        panic!("expected status")
    };
    assert!(value.pending_restart);
    // Nothing was restarted behind the user's back.
    assert!(platform.calls.lock().unwrap().is_empty());

    // A settings edit that settles back to the running build keeps the geo flag.
    set_settings(&svc, |s| s.fragment = true).await;
    set_settings(&svc, |s| s.fragment = false).await;
    assert!(pending_restart(&svc).await);

    svc.dispatch(Command::Restart { profile_id: None })
        .await
        .unwrap();
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn a_failed_stop_keeps_the_geo_flag() {
    use crate::updater::LifecycleControl;
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    svc.note_assets_changed().await;

    platform.fail_stop.store(true, Ordering::SeqCst);
    assert!(svc.dispatch(Command::Stop).await.is_err());
    // The core still runs on the old data.
    assert!(pending_restart(&svc).await);

    platform.fail_stop.store(false, Ordering::SeqCst);
    svc.dispatch(Command::Stop).await.unwrap();
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn a_manual_geo_download_flags_pending_restart_only_when_it_changes() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    platform.calls.lock().unwrap().clear();
    tokio::fs::create_dir_all(&platform.paths.dat_dir)
        .await
        .unwrap();
    let (base, _) = crate::testutil::serve(vec![
        crate::testutil::http_response(200, &[], b"geo-v1"),
        crate::testutil::http_response(200, &[], b"geo-v1"),
    ])
    .await;
    let download = || Command::DownloadAsset {
        filename: "geoip.dat".into(),
        url: format!("{base}/geoip.dat"),
        mode: Default::default(),
    };

    svc.dispatch(download()).await.unwrap();
    assert!(pending_restart(&svc).await);
    assert!(platform.calls.lock().unwrap().is_empty());

    // The same bytes again leave a fresh start with nothing pending.
    svc.dispatch(Command::Restart { profile_id: None })
        .await
        .unwrap();
    svc.dispatch(download()).await.unwrap();
    assert!(!pending_restart(&svc).await);
}

#[tokio::test]
async fn tun_engine_tuning_flags_pending_restart() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();

    // The xray core runs behind tun2socks, which reads its MTU only at start.
    set_settings(&svc, |s| s.tun_mtu = 1280).await;
    assert!(pending_restart(&svc).await);

    let defaults = kasumi_core::state::AdvancedSettings::default();
    set_settings(&svc, |s| s.tun_mtu = defaults.tun_mtu).await;
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

/// Save profiles `a` (active) and `b`.
async fn seed_two(platform: &RecordingPlatform) {
    let mut a = sample_vless();
    a.meta_mut().id = "a".into();
    let mut b = crate::testutil::vless_at(8443);
    b.meta_mut().id = "b".into();
    let mut state = default_app_state();
    state.active_id = Some("a".into());
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

fn as_probe(reply: Response) -> ConnectionProbe {
    let Response::Probe(p) = reply else {
        panic!("expected a probe reply, got {reply:?}")
    };
    p
}

async fn probe(svc: &Service) -> ConnectionProbe {
    as_probe(svc.dispatch(Command::ProbeConnection).await.unwrap())
}

#[tokio::test]
async fn probe_reply_names_the_running_profile() {
    let (_d, svc, _core) = running_first_of_two().await;
    let reply = probe(&svc).await;
    assert_eq!(reply.profile_id.as_deref(), Some("a"));
    assert!(reply.latency_ms.is_some());

    // A saved switch doesn't change what runs: the answer is still the old
    // profile's, never attributed to the new active one.
    save_active(&svc, "b").await;
    assert_eq!(probe(&svc).await.profile_id.as_deref(), Some("a"));

    svc.dispatch(Command::Start {
        profile_id: Some("b".into()),
    })
    .await
    .unwrap();
    assert_eq!(probe(&svc).await.profile_id.as_deref(), Some("b"));
}

#[tokio::test]
async fn saved_switch_does_not_inherit_the_running_profiles_ping() {
    let (_d, svc, _core) = running_first_of_two().await;
    let mut rx = svc.subscribe();

    assert!(probe(&svc).await.latency_ms.is_some());
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
async fn a_running_profile_recreated_under_a_new_id_keeps_its_verdict() {
    let (_d, svc, _core) = running_first_of_two().await;
    assert!(probe(&svc).await.latency_ms.is_some());

    // A subscription refresh re-creates the running profile under a new id and
    // moves the selection to it, without a restart: the build is the same.
    let mut state = crate::state::read_app_state(svc.platform()).await.unwrap();
    state.profiles[0].meta_mut().id = "a2".into();
    state.active_id = Some("a2".into());
    crate::state::write_app_state(svc.platform(), &state)
        .await
        .unwrap();
    svc.note_state_saved(&state).await;

    let status = svc.current_status().await.unwrap();
    assert_eq!(status.active_id.as_deref(), Some("a2"));
    assert_eq!(status.service.state, RunState::Connected);
    assert!(status.latency_ms.is_some());
    assert!(!status.pending_restart);
    assert_eq!(probe(&svc).await.profile_id.as_deref(), Some("a2"));
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
    let reply = as_probe(probing.await.unwrap().unwrap());
    assert_eq!(reply.profile_id.as_deref(), Some("a"));

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
    assert_eq!(probe(&svc).await.latency_ms, None);
}

#[tokio::test]
async fn status_request_carries_the_probe_verdict() {
    let (_d, svc, _core) = running_first_of_two().await;
    let state_of = |r: Response| match r {
        Response::Status(s) => s.state,
        other => panic!("expected status, got {other:?}"),
    };

    // No verdict yet: the core is up but connectivity is unknown.
    let r = svc.dispatch(Command::Status).await.unwrap();
    assert_eq!(state_of(r), RunState::Connecting);

    svc.dispatch(Command::ProbeConnection).await.unwrap();
    let r = svc.dispatch(Command::Status).await.unwrap();
    assert_eq!(state_of(r), RunState::Connected);
}

#[tokio::test]
async fn start_hands_the_platform_the_baseline_plan() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    let started = platform.started.lock().unwrap().clone();
    let baseline = svc
        .running_config
        .lock()
        .unwrap()
        .as_ref()
        .map(|r| r.config.plan.clone());
    assert!(started.is_some());
    assert_eq!(started, baseline);
}

#[tokio::test]
async fn app_filter_reload_restarts_a_running_data_path() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    let starts = || {
        platform
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.starts_with("start:"))
            .count()
    };

    // Nothing running: the next start picks the filter up.
    svc.dispatch(Command::ReloadAppFilter).await.unwrap();
    assert_eq!(starts(), 0);

    // Running: the filter is part of what a start builds, so it restarts.
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    svc.dispatch(Command::ReloadAppFilter).await.unwrap();
    assert_eq!(starts(), 2);
}

/// One watchdog sample of the platform, as `spawn_watchdog` takes it.
async fn watchdog_sample(svc: &Service) -> ServiceState {
    svc.platform.service_state().await.unwrap()
}

#[tokio::test]
async fn watchdog_tears_down_a_data_path_whose_core_died() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;
    svc.dispatch(Command::Start { profile_id: None })
        .await
        .unwrap();
    platform.calls.lock().unwrap().clear();

    // The core is killed; the record still says the data path runs.
    platform.core_dead.store(true, Ordering::SeqCst);
    let sample = watchdog_sample(&svc).await;
    assert!(sample.engine.is_none());
    assert_eq!(sample.state, RunState::Connecting);

    assert!(svc.reap_dead_data_path(&sample).await);
    assert_eq!(*platform.calls.lock().unwrap(), ["stop:keep=false"]);
    assert!(svc.running_config.lock().unwrap().is_none());
}

#[tokio::test]
async fn watchdog_leaves_a_stopped_data_path_alone() {
    let (platform, _d) = RecordingPlatform::new();
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

    let sample = watchdog_sample(&svc).await;
    assert_eq!(sample.state, RunState::Stopped);
    assert!(!svc.reap_dead_data_path(&sample).await);
    assert!(platform.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn watchdog_leaves_a_start_in_progress_alone() {
    let (platform, _d) = RecordingPlatform::new();
    seed_active(&platform).await;
    let svc = Service::new(platform.clone() as Arc<dyn Platform>).await;

    // Mid-start the data path is recorded as connecting but the core is not up yet.
    platform.running.store(true, Ordering::SeqCst);
    platform.core_dead.store(true, Ordering::SeqCst);
    let sample = watchdog_sample(&svc).await;
    let start = svc.serialize.lock().await;

    let reaping = tokio::spawn({
        let svc = Arc::clone(&svc);
        async move { svc.reap_dead_data_path(&sample).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!reaping.is_finished(), "the watchdog waits for the start");

    // The start finishes with a live core and releases the lifecycle lock.
    platform.core_dead.store(false, Ordering::SeqCst);
    drop(start);
    assert!(!reaping.await.unwrap());
    assert!(platform.calls.lock().unwrap().is_empty());
    assert!(platform.running.load(Ordering::SeqCst));
}
