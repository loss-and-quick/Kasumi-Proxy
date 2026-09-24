//! Shared test scaffolding: a [`Platform`] backed by a tempdir, and a couple of
//! sample profiles. Compiled only under `cfg(test)`.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use tempfile::TempDir;

use kasumi_core::contract::{RunState, ServiceState};
use kasumi_core::enums::CoreEngine;
use kasumi_core::profile::Profile;
use kasumi_core::share::parse_share_link;

use crate::net::ProxyStatus;
use crate::platform::{
    BackendPaths, Engine, InstalledCores, Platform, PlatformCapabilities, StartDataPath,
    StopDataPath,
};

/// A `Platform` whose paths live in a tempdir. `core_path` points under a `bin/`
/// dir that doesn't exist, so diagnostics that require a real core binary take
/// their failure path deterministically.
pub struct TestPlatform {
    paths: BackendPaths,
    bin_dir: PathBuf,
    /// Filenames handed to `convert_asset`, in call order.
    converted: Mutex<Vec<String>>,
    /// When set, `convert_asset` errors — for the asset-update rollback path.
    convert_fails: AtomicBool,
}

impl TestPlatform {
    /// Make `convert_asset` fail (or succeed again), so a test can drive the
    /// "downloaded but not converted" branch.
    pub fn fail_conversions(&self, yes: bool) {
        self.convert_fails.store(yes, Ordering::SeqCst);
    }

    /// Filenames `convert_asset` was called with, in order.
    pub fn converted(&self) -> Vec<String> {
        self.converted.lock().unwrap().clone()
    }

    pub fn new() -> (Self, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_path_buf();
        std::fs::create_dir_all(d.join("dat")).unwrap();
        std::fs::create_dir_all(d.join("srs")).unwrap();
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
        let bin_dir = d.join("bin");
        (
            Self {
                paths,
                bin_dir,
                converted: Mutex::new(Vec::new()),
                convert_fails: AtomicBool::new(false),
            },
            dir,
        )
    }
}

#[async_trait]
impl Platform for TestPlatform {
    fn paths(&self) -> &BackendPaths {
        &self.paths
    }
    async fn start_data_path(&self, _opts: StartDataPath) -> anyhow::Result<()> {
        Ok(())
    }
    async fn stop_data_path(&self, _opts: StopDataPath) -> anyhow::Result<()> {
        Ok(())
    }
    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        Ok(ServiceState {
            // Process-up truth; the Service refines this to Connected/NoInternet.
            state: RunState::Connecting,
            error: None,
            upload_bytes: 1,
            download_bytes: 2,
            uptime_sec: 3,
            engine: Some(CoreEngine::Xray),
        })
    }
    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
        Ok(PlatformCapabilities {
            cores: InstalledCores {
                xray: Some("Xray 25.5.16".into()),
                singbox: Some("1.10.0".into()),
            },
            tun: true,
            bridge: "test".into(),
        })
    }
    fn core_path(&self, engine: Engine) -> PathBuf {
        let name = match engine {
            CoreEngine::Xray => "xray",
            CoreEngine::SingBox => "sing-box",
        };
        self.bin_dir.join(name)
    }
    async fn convert_asset(&self, filename: &str) -> anyhow::Result<()> {
        if self.convert_fails.load(Ordering::SeqCst) {
            anyhow::bail!("convert_asset failed (test)");
        }
        self.converted.lock().unwrap().push(filename.to_owned());
        Ok(())
    }
    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
        Ok(ProxyStatus {
            running: false,
            socks_port: 1080,
            http_port: 1081,
            force_port: 1082,
        })
    }
}

/// A representative xray profile (vless/tcp/tls).
pub fn sample_vless() -> Profile {
    parse_share_link(
        "vless://11111111-1111-1111-1111-111111111111@e.example:443?type=tcp&security=tls&sni=s#Home",
        None,
    )
    .unwrap()
}

/// A vless profile whose endpoint is `127.0.0.1:port` (for TCP-ping tests).
pub fn vless_at(port: u16) -> Profile {
    parse_share_link(
        &format!(
            "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:{port}?type=tcp&security=tls&sni=s#Local"
        ),
        None,
    )
    .unwrap()
}
