//! The platform boundary: every OS-specific operation the orchestration layer
//! needs. This crate is platform-neutral; each shell (Android via the root module,
//! desktop via the native network stack) provides a [`Platform`] implementation.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use kasumi_core::contract::{LogTarget, ServiceState};
use kasumi_core::enums::{CoreEngine, TunEngine};
use kasumi_core::state::ProxyMode;
use kasumi_core::tun::TunOptions;

use crate::lifecycle::spawn_core;
use crate::net::ProxyStatus;

pub type Engine = CoreEngine;

/// A spawned on-demand test core, owned by whoever started it. `kill` (or dropping
/// the handle) tears the throwaway core down — the platform decides whether that
/// process lives in-process or behind a privileged helper.
#[async_trait]
pub trait TestCore: Send + Sync {
    /// Kill the core and reap it. Idempotent.
    async fn kill(&mut self);
}

/// A test core running in this very process — the Android root daemon, the desktop
/// privileged helper, or an in-process dev run. Kill-on-drop (set at spawn) means a
/// cancelled probe future tears it down without an explicit `kill`.
pub struct LocalTestCore {
    child: tokio::process::Child,
}

#[async_trait]
impl TestCore for LocalTestCore {
    async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

/// Spawn a test core in this process (kill-on-drop) and box it as a [`TestCore`].
/// The building block for [`Platform::spawn_test_core`] and any privileged override
/// that first rewrites the config (e.g. the desktop helper injecting an uplink bind).
/// On Unix the child is tied to its parent via `PR_SET_PDEATHSIG` (see
/// [`proc::spawn_logged`]); any capability it needs across exec comes from the
/// helper's ambient set, so there's no per-spawn `pre_exec` variant.
pub async fn spawn_local_test_core(
    bin: &str,
    cfg_path: &Path,
    log_path: &Path,
    dat_dir: &str,
) -> anyhow::Result<Box<dyn TestCore>> {
    let child = spawn_core(bin, &cfg_path.to_string_lossy(), log_path, dat_dir, true).await?;
    Ok(Box::new(LocalTestCore { child }))
}

/// Absolute on-disk locations the backend reads and writes.
#[derive(Debug, Clone)]
pub struct BackendPaths {
    pub data_dir: PathBuf,
    /// Directory of sing-box `.srs` rule-set files (the path is baked into its
    /// config). Distinct from `data_dir` so a platform can place geo assets anywhere.
    pub srs_dir: PathBuf,
    /// Directory of xray geoip/geosite `.dat` files (passed as `XRAY_LOCATION_ASSET`).
    pub dat_dir: PathBuf,
    pub app_state: PathBuf,
    pub profiles: PathBuf,
    pub xray_config: PathBuf,
    pub singbox_config: PathBuf,
    /// Marker recording which engine the active config was built for.
    pub engine_file: PathBuf,
    pub run_dir: PathBuf,
    /// JSON file the daemon writes its WS `{port, token}` to, for the UI to read.
    pub ws_info: PathBuf,
    /// Static UI root the daemon serves over HTTP. `None` where the host serves the
    /// UI itself (Android KSU WebUI) — there the daemon exposes only WS.
    pub webroot: Option<PathBuf>,
}

impl BackendPaths {
    /// Per-target log file, `<data_dir>/<target>.log`.
    pub fn log(&self, target: LogTarget) -> PathBuf {
        let name = match target {
            LogTarget::Daemon => "daemon",
            LogTarget::Xray => "xray",
            LogTarget::Singbox => "singbox",
            LogTarget::TunEngine => "tun-engine",
        };
        self.data_dir.join(format!("{name}.log"))
    }
}

/// Installed core versions probed off the host. `CoreEngine` isn't hashable, so the
/// two engines are explicit fields rather than a map.
#[derive(Debug, Clone, Default)]
pub struct InstalledCores {
    pub xray: Option<String>,
    pub singbox: Option<String>,
}

/// Raw platform probe (installed cores + runtime features); the `capabilities`
/// command shapes it into the wire `Capabilities` for the UI.
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    pub cores: InstalledCores,
    pub tun: bool,
    /// UI-runtime tag for this host (e.g. `"ksu"` on Android, `"desktop"` elsewhere).
    pub bridge: String,
}

/// One app in the per-app filter list. Android-shaped (a PackageManager uid matched
/// by `iptables --uid-owner`); the only cross-platform contract is the opaque
/// `appFilter` key in the core schema, interpreted solely by the platform's routing.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, specta::Type)]
pub struct AppInfo {
    pub pkg: String,
    pub uid: i32,
    pub system: bool,
}

/// Options for [`Platform::start_data_path`].
#[derive(Debug, Clone)]
pub struct StartDataPath {
    pub engine: Engine,
    /// The resolved TUN engine. `SingboxTun` uses the core's own tun (native for
    /// sing-box); `Tun2socks`/`Hev` front a socks-only core with an external tun.
    /// Ignored when `mode` runs no tun.
    pub tun: TunEngine,
    /// External-engine tuning (mtu, buffers, timeouts, …), resolved once from the
    /// settings so the data-path owner (incl. the desktop root helper, across the
    /// privilege boundary) needn't re-read the settings schema.
    pub tun_opts: TunOptions,
    pub socks_port: u16,
    /// How to capture traffic: `tun` brings up the tun device + routing; the other
    /// modes run the core on its local socks/http inbound alone. Already
    /// normalized to `Tun` for platforms without proxy-mode support.
    pub mode: ProxyMode,
}

/// Options for [`Platform::stop_data_path`].
#[derive(Debug, Clone, Default)]
pub struct StopDataPath {
    /// Skip the terminal "stopped" status so a restart doesn't blip the UI.
    pub keep_service_state: bool,
}

/// Per-app filtering — present only where the OS can route per app (Android).
#[async_trait]
pub trait AppFilterCapability: Send + Sync {
    /// Enumerate installed apps for the app-filter UI.
    async fn list_apps(&self) -> anyhow::Result<Vec<AppInfo>>;
    /// Re-apply per-app routing rules without restarting the core.
    async fn reload_app_filter(&self) -> anyhow::Result<()>;
}

/// OS-specific operations. The defaulted methods aren't meaningful on every
/// platform; a host overrides only the ones it supports.
#[async_trait]
pub trait Platform: Send + Sync {
    fn paths(&self) -> &BackendPaths;

    /// One-time boot setup before any command is served (sysctl locks, `/dev/net/tun`…).
    async fn boot_init(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Whether this platform honours the non-tun proxy modes (proxy-only / system /
    /// pac). Where it doesn't (the Android root module), config build and start
    /// normalize `proxyMode` to `tun` — so e.g. a restored desktop backup carrying
    /// a non-tun mode can't strip the tun inbound out from under the data path.
    fn supports_proxy_modes(&self) -> bool {
        false
    }

    /// Spawn the core for `engine` from the on-disk config and route traffic through
    /// it. Resolves once the core is confirmed up, or errors with a reason.
    async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()>;

    /// Stop the core/helpers and remove all routing. Idempotent.
    async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()>;

    /// Align the OS-level proxy with `mode` after a successful data-path start:
    /// point the OS at the core's local inbound where the mode asks for it
    /// (`system`/`pac`), clear any previously-set one otherwise — so a mode switch
    /// can't leave a stale OS proxy behind. Runs in the client process (GUI /
    /// daemon), never the privileged helper: the OS proxy lives in the logged-in
    /// user's session (gsettings / D-Bus / HKCU), which the helper's isn't.
    /// The first apply records the pre-existing OS proxy so [`Platform::clear_os_proxy`]
    /// can restore it rather than blank a proxy the user configured by hand.
    /// Default: no-op for platforms without an OS-proxy integration.
    async fn set_os_proxy(&self, _mode: ProxyMode, _engine: Engine, _socks_port: u16) {}

    /// Undo [`Platform::set_os_proxy`]: restore the OS proxy from the record it wrote,
    /// or leave the OS proxy untouched when there is no record (it isn't ours).
    /// Idempotent; called on every data-path stop whatever the mode. Default: no-op.
    async fn clear_os_proxy(&self) {}

    /// Current data-path status (liveness + traffic counters).
    async fn service_state(&self) -> anyhow::Result<ServiceState>;

    /// Probe installed cores and runtime features.
    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities>;

    /// Absolute path to a core binary, for spawning on-demand test cores.
    fn core_path(&self, engine: Engine) -> PathBuf;

    /// Whether a core is live and the local SOCKS port to reach it on, for the
    /// proxy-vs-direct decision in subscription/asset fetches.
    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus>;

    /// Post-process a downloaded asset (geoip/geosite → `.srs` for sing-box).
    async fn convert_asset(&self, _filename: &str) -> anyhow::Result<()> {
        Ok(())
    }

    /// Mutate a freshly built core config in place to apply OS-specific knobs the
    /// neutral builder must not assume (e.g. sing-box's root-binary tun needs
    /// `auto_redirect` + `strict_route` on Android).
    fn tune_config(&self, _engine: Engine, _config: &mut Value) {}

    /// Per-app filtering, where the OS supports it.
    fn app_filter(&self) -> Option<&dyn AppFilterCapability> {
        None
    }

    /// A receiver that yields once each time the active uplink changes, so the
    /// `Service` can re-pin routing. `None` where the platform can't watch links.
    fn watch_network_change(&self) -> Option<mpsc::Receiver<()>> {
        None
    }

    /// A receiver that yields once each time the machine wakes from suspend/hibernate,
    /// so the `Service` can restart the data-path: a core left running across a sleep can
    /// hold stale routing/DNS state that only a restart re-pins. `None` where the platform
    /// has no resume signal (e.g. Android, which handles wake another way).
    fn watch_system_resume(&self) -> Option<mpsc::Receiver<()>> {
        None
    }

    /// Whether all data-path processes are still alive (drives the watchdog).
    /// `None` where the platform can't report it.
    async fn data_path_healthy(&self) -> Option<bool> {
        None
    }

    /// Spawn a throwaway test core for `cfg_path`, logging to `log_path`. A platform
    /// that splits privilege overrides this to run the core in its root helper — so
    /// the core can bind its outbound to the physical uplink (`SO_BINDTODEVICE`,
    /// which needs `CAP_NET_RAW`) and escape an active tun. The default is the plain
    /// in-process spawn (kill-on-drop): right for the Android root daemon (its
    /// iptables mark chain already spares root test traffic) and in-process dev.
    async fn spawn_test_core(
        &self,
        engine: Engine,
        cfg_path: &Path,
        log_path: &Path,
    ) -> anyhow::Result<Box<dyn TestCore>> {
        let bin = self.core_path(engine);
        let dat = self.paths().dat_dir.to_string_lossy().into_owned();
        spawn_local_test_core(&bin.to_string_lossy(), cfg_path, log_path, &dat).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_core::contract::RunState;

    fn paths() -> BackendPaths {
        let d = PathBuf::from("/data");
        BackendPaths {
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
        }
    }

    #[test]
    fn log_paths_are_under_data_dir() {
        let p = paths();
        assert_eq!(p.log(LogTarget::Daemon), PathBuf::from("/data/daemon.log"));
        assert_eq!(
            p.log(LogTarget::Singbox),
            PathBuf::from("/data/singbox.log")
        );
        assert_eq!(
            p.log(LogTarget::TunEngine),
            PathBuf::from("/data/tun-engine.log")
        );
    }

    /// A minimal implementor: proves the trait is object-safe and the defaulted
    /// methods are usable as-is.
    struct Stub(BackendPaths);

    #[async_trait]
    impl Platform for Stub {
        fn paths(&self) -> &BackendPaths {
            &self.0
        }
        async fn start_data_path(&self, _opts: StartDataPath) -> anyhow::Result<()> {
            Ok(())
        }
        async fn stop_data_path(&self, _opts: StopDataPath) -> anyhow::Result<()> {
            Ok(())
        }
        async fn service_state(&self) -> anyhow::Result<ServiceState> {
            Ok(ServiceState {
                state: RunState::Stopped,
                error: None,
                upload_bytes: 0,
                download_bytes: 0,
                uptime_sec: 0,
                engine: None,
            })
        }
        async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
            Ok(PlatformCapabilities {
                cores: InstalledCores::default(),
                tun: false,
                bridge: "stub".into(),
            })
        }
        fn core_path(&self, _engine: Engine) -> PathBuf {
            PathBuf::new()
        }
        async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
            Ok(ProxyStatus {
                running: false,
                socks_port: 0,
                http_port: 0,
                force_port: 0,
            })
        }
    }

    #[tokio::test]
    async fn stub_uses_trait_defaults() {
        let p: Box<dyn Platform> = Box::new(Stub(paths()));
        p.boot_init().await.unwrap();
        p.convert_asset("geoip.dat").await.unwrap();
        assert!(p.app_filter().is_none());
        assert!(p.watch_network_change().is_none());
        assert!(p.watch_system_resume().is_none());
        assert_eq!(p.data_path_healthy().await, None);
        assert_eq!(p.service_state().await.unwrap().state, RunState::Stopped);
    }
}
