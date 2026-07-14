use super::*;
use crate::platform::{
    BackendPaths, Engine, InstalledCores, PlatformCapabilities, StartDataPath, StopDataPath,
};
use crate::testutil::sample_vless;
use kasumi_core::contract::{RunState, ServiceState};
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
    fn supports_proxy_modes(&self) -> bool {
        true
    }
    async fn set_os_proxy(&self, mode: ProxyMode, _engine: Engine, _socks_port: u16) {
        self.log(&format!("os_proxy:{mode:?}"));
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

    // Neither setting reaches the built config: no restart needed.
    set_settings(&svc, |s| {
        s.delay_test_url = Some("https://probe.example/gen".into())
    })
    .await;
    set_settings(&svc, |s| s.log_rotate_max_kb = 1024).await;
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
