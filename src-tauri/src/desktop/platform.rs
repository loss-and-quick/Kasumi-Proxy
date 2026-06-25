//! The desktop `Platform`: thin orchestration over the neutral lifecycle steps,
//! shared by Linux and Windows. The bring-up flow, status reporting and teardown are
//! identical across both OSes; the handful of genuine differences (tun2socks fwmark,
//! tun-up wait, byte counters, tun capability, sing-box stack, the wintun precheck)
//! are funnelled through the [`DesktopOs`] seam, implemented per-OS in `linux::os` /
//! `windows::os`. The native tun + routing live in `routing`/`network`. Neutral
//! lifecycle steps (config build, geo sync, core/tun2socks spawn, liveness verify)
//! come from `kasumi-backend`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use kasumi_backend::fs::{exists, read_text, remove_file, write_text};
use kasumi_backend::fsjson::read_json;
use kasumi_backend::lifecycle::{random_tun_iface, spawn_core, spawn_tun2socks, verify_core_alive};
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    spawn_local_test_core, BackendPaths, Engine, InstalledCores, Platform, PlatformCapabilities,
    StartDataPath, StopDataPath, TestCore,
};
use kasumi_backend::proc::{kill_if_running, pid_matches_any, pid_matches_bin, read_pidfile};
use kasumi_core::contract::{RunState, ServiceState};
use kasumi_core::enums::CoreEngine;
use kasumi_core::state::{AppState, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT};

use crate::desktop::paths::DesktopPaths;
use crate::desktop::singbox::prepare_singbox_config;
use crate::desktop::{network, routing, OsSeam};

/// The per-OS seam: only the parts of the data-path that genuinely differ between
/// Linux and Windows. Everything else lives in the shared [`DesktopPlatform`].
#[async_trait]
pub(crate) trait DesktopOs: Send + Sync {
    fn new() -> anyhow::Result<Self>
    where
        Self: Sized;

    /// fwmark stamped on tun2socks' upstream socket so it stays out of the tunnel.
    /// Linux pins one; Windows uses a host route instead and returns `None`.
    fn tun2socks_fwmark(&self) -> Option<u32>;

    /// Extra precheck before the xray/tun2socks path (Windows: the bundled
    /// `wintun.dll` must be on disk). Linux has nothing to check.
    async fn precheck_xray(&self, p: &DesktopPaths) -> anyhow::Result<()>;

    /// Wait for the freshly-created tun `name` to come up before addressing/routing.
    /// Linux is best-effort (proceeds even on timeout, matching its `ip` flow);
    /// Windows errors if the wintun adapter never appears.
    async fn await_tun_up(&self, name: &str) -> anyhow::Result<()>;

    /// RX/TX byte counters for `iface`, or `(0, 0)` where unsupported (Windows has
    /// no `/proc/net/dev`).
    async fn iface_traffic(&self, iface: Option<&str>) -> (u64, u64);

    /// Whether a tun is creatable right now (Linux checks `/dev/net/tun`; Windows
    /// always can — sing-box embeds wintun, the xray path checks the DLL at start).
    async fn tun_capable(&self) -> bool;

    /// The sing-box tun stack to pin: `"gvisor"` for the Linux root-binary path,
    /// `"system"` for Windows (wintun + kernel stack).
    fn singbox_stack(&self) -> &'static str;
}

pub struct DesktopPlatform {
    p: DesktopPaths,
    os: OsSeam,
}

impl DesktopPlatform {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            p: DesktopPaths::resolve()?,
            os: OsSeam::new()?,
        })
    }

    fn core_bin(&self, engine: CoreEngine) -> &str {
        match engine {
            CoreEngine::SingBox => &self.p.singbox_bin,
            CoreEngine::Xray => &self.p.xray_bin,
        }
    }

    async fn set_service_state(&self, value: &str) {
        let _ = write_text(&self.p.service_state_file, value).await;
    }

    async fn fail(&self, reason: &str) -> anyhow::Result<()> {
        log::error!("data-path start failed: {reason}");
        self.set_service_state(&format!("failed:{reason}")).await;
        anyhow::bail!("{reason}")
    }

    async fn http_port(&self) -> u16 {
        read_json::<AppState>(&self.p.backend.app_state)
            .await
            .and_then(|s| s.settings.local_http_port)
            .unwrap_or(DEFAULT_LOCAL_HTTP_PORT)
    }

    async fn core_version(&self, engine: CoreEngine) -> Option<String> {
        let bin = self.core_bin(engine);
        if !exists(bin).await {
            return None;
        }
        let (code, out) = crate::desktop::run_out(&[bin, "version"]).await;
        if code != 0 {
            return None;
        }
        out.lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Which core is actually running (PID truth), or `None`.
    async fn running_engine(&self) -> Option<CoreEngine> {
        let pid = read_pidfile(&self.p.pidfile).await;
        if pid <= 0 {
            return None;
        }
        if pid_matches_bin(pid, &self.p.xray_bin).await {
            return Some(CoreEngine::Xray);
        }
        if pid_matches_bin(pid, &self.p.singbox_bin).await {
            return Some(CoreEngine::SingBox);
        }
        None
    }

    /// sing-box bring-up: it owns its own tun (auto_route) — no tun2socks/manual
    /// routing. The proxy-server bypass is baked into the config as
    /// `route_exclude_address` by `prepare_singbox_config`. On Windows the tun comes
    /// up from sing-box's embedded wintun (no DLL on disk needed, unlike xray).
    async fn start_singbox(&self) -> anyhow::Result<()> {
        let cfg = self.p.backend.singbox_config.to_string_lossy().into_owned();
        let log = self
            .p
            .backend
            .log(kasumi_core::contract::LogTarget::Singbox);
        if !exists(&self.p.singbox_bin).await {
            return self.fail("sing-box binary missing").await;
        }
        if !exists(&cfg).await {
            return self.fail("config missing").await;
        }

        let cfg_text = read_text(&cfg).await.unwrap_or_default();
        let needed = kasumi_backend::lifecycle::referenced_srs(&cfg_text);
        let geo = Path::new(&self.p.geodat2srs_bin);
        let dat = self.p.backend.dat_dir.as_path();
        let srs = self.p.backend.srs_dir.as_path();
        kasumi_backend::lifecycle::sync_geo_asset("geoip", dat, srs, geo, &needed).await;
        kasumi_backend::lifecycle::sync_geo_asset("geosite", dat, srs, geo, &needed).await;
        if !kasumi_backend::lifecycle::missing_rule_sets(&cfg_text)
            .await
            .is_empty()
        {
            return self.fail("missing rule_set assets").await;
        }

        prepare_singbox_config(&cfg, &self.p.tun_iface_file, &self.p.tun2_iface_file).await?;

        let dat_dir = self.p.backend.dat_dir.to_string_lossy().into_owned();
        let child = spawn_core(&self.p.singbox_bin, &cfg, &log, &dat_dir, false).await?;
        let pid = child.id().unwrap_or(0) as i32;
        let _ = write_text(&self.p.pidfile, &pid.to_string()).await;
        if !verify_core_alive(pid, &self.p.singbox_bin, 6, Duration::from_millis(250)).await {
            return self
                .fail(&format!("core exited on startup — see {}", log.display()))
                .await;
        }
        Ok(())
    }

    /// xray bring-up: spawn xray (its own SOCKS), bridge a userspace tun to it via
    /// tun2socks, then install the OS routing (server bypass + split-default).
    async fn start_xray(&self, socks_port: u16) -> anyhow::Result<()> {
        let cfg = self.p.backend.xray_config.to_string_lossy().into_owned();
        let log = self.p.backend.log(kasumi_core::contract::LogTarget::Xray);
        if !exists(&self.p.xray_bin).await {
            return self.fail("xray binary missing").await;
        }
        self.os.precheck_xray(&self.p).await?;
        if !exists(&cfg).await {
            return self.fail("config missing").await;
        }

        // Resolve the server-bypass set before any tun route is up (needs DNS).
        let cfg_text = read_text(&cfg).await.unwrap_or_default();
        let bypass = routing::resolve_bypass_cidrs(&cfg_text).await;

        let dat_dir = self.p.backend.dat_dir.to_string_lossy().into_owned();
        let child = spawn_core(&self.p.xray_bin, &cfg, &log, &dat_dir, false).await?;
        let pid = child.id().unwrap_or(0) as i32;
        let _ = write_text(&self.p.pidfile, &pid.to_string()).await;
        if !verify_core_alive(pid, &self.p.xray_bin, 6, Duration::from_millis(250)).await {
            return self
                .fail(&format!("core exited on startup — see {}", log.display()))
                .await;
        }

        let tun = random_tun_iface();
        let _ = write_text(&self.p.tun_iface_file, &tun).await;
        let t2s_log = self
            .p
            .backend
            .log(kasumi_core::contract::LogTarget::Tun2socks);
        let t2s = spawn_tun2socks(
            &self.p.tun2socks_bin,
            &tun,
            socks_port,
            &t2s_log,
            self.os.tun2socks_fwmark(),
        )
        .await?;
        let _ = write_text(
            &self.p.tun2socks_pidfile,
            &t2s.id().unwrap_or(0).to_string(),
        )
        .await;
        // tun2socks creates the tun device; wait for it before addressing/routing.
        self.os.await_tun_up(&tun).await?;
        routing::apply_xray_routing(&tun, &bypass, &self.p.route_state_file).await?;
        Ok(())
    }
}

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self::new().expect("desktop paths resolve")
    }
}

/// Whether a test core spawned from *this* process will hold an effective
/// `CAP_NET_RAW`, so its uplink bind (`SO_BINDTODEVICE` / `bind_interface`) can
/// escape an active tun. Only the privileged data-path owner qualifies: the root
/// helper on Linux, the LocalSystem service on Windows. In-process dev on unix is
/// unprivileged and skips the bind.
///
/// This is the real precondition the test-core bind needs. It checks the effective
/// `CAP_NET_RAW` directly (which reads true under a root *or* caps-only helper
/// whose bounding set keeps `NET_RAW`, and false for unprivileged dev) instead of
/// the old `geteuid() == 0` proxy — so the gate stays honest once Phase 4 makes the
/// helper caps-only rather than root. Fails closed on a query error (see
/// [`capabilities::has_effective_net_raw`]).
fn test_core_can_bind() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::desktop::capabilities::has_effective_net_raw()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The Windows data-path runs in the LocalSystem service; there's no
        // unprivileged in-process tun path to distinguish.
        true
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[async_trait]
impl Platform for DesktopPlatform {
    fn paths(&self) -> &BackendPaths {
        &self.p.backend
    }

    async fn boot_init(&self) -> anyhow::Result<()> {
        // Unlike Android (RUN_DIR ⊂ DATADIR), the desktop runtime dir may live under
        // a different base (XDG_RUNTIME_DIR / %LOCALAPPDATA%), so both must be created
        // explicitly.
        let _ = tokio::fs::create_dir_all(&self.p.datadir).await;
        let _ = tokio::fs::create_dir_all(&self.p.run_dir).await;
        // Fresh start: seed the lifecycle state so a stale value can't make status
        // lie before the first command.
        self.set_service_state("stopped").await;
        remove_file(&self.p.service_started_file).await;
        Ok(())
    }

    async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
        let StartDataPath { engine, socks_port } = opts;
        log::info!("starting data-path: engine={engine:?} socks_port={socks_port}");
        self.set_service_state("connecting").await;
        let _ = write_text(&self.p.socks_port_file, &socks_port.to_string()).await;
        let result = if engine == CoreEngine::SingBox {
            self.start_singbox().await
        } else {
            self.start_xray(socks_port).await
        };
        match result {
            Ok(()) => {
                let _ = write_text(&self.p.service_started_file, &now_secs().to_string()).await;
                self.set_service_state("running").await;
                log::info!("data-path running ({engine:?})");
                Ok(())
            }
            Err(e) => {
                // Roll back a half-built data-path; keep any "failed:<reason>" label.
                let cur = read_text(&self.p.service_state_file)
                    .await
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if !cur.starts_with("failed") {
                    self.set_service_state(&format!("failed:{e}")).await;
                }
                let _ = self
                    .stop_data_path(StopDataPath {
                        keep_service_state: true,
                    })
                    .await;
                Err(e)
            }
        }
    }

    async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()> {
        log::info!(
            "stopping data-path (keep_state={})",
            opts.keep_service_state
        );
        // Stop the core first, gracefully: a sing-box auto_route core removes its
        // own routes + tun on terminate. Then tear down the xray manual routing
        // (no-op for sing-box — no route-state file) and the tun2socks helper.
        kill_if_running(
            read_pidfile(&self.p.pidfile).await,
            None,
            &self.p.pidfile,
            true,
        )
        .await;
        routing::clear_xray_routing(&self.p.route_state_file).await;
        kill_if_running(
            read_pidfile(&self.p.tun2socks_pidfile).await,
            Some(&self.p.tun2socks_bin),
            &self.p.tun2socks_pidfile,
            false,
        )
        .await;
        remove_file(&self.p.tun_iface_file).await;
        remove_file(&self.p.tun2_iface_file).await;
        if !opts.keep_service_state {
            self.set_service_state("stopped").await;
        }
        Ok(())
    }

    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        let raw = read_text(&self.p.service_state_file)
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "stopped".into());
        let mut state = RunState::Stopped;
        let mut error = None;
        if raw.starts_with("failed") {
            state = RunState::Failed;
            let reason = raw
                .find(':')
                .map(|i| raw[i + 1..].to_string())
                .unwrap_or_default();
            error = (!reason.is_empty()).then_some(reason);
        } else if raw == "connecting" || raw == "running" {
            // "running" = process up; the Service's connectivity probe refines this
            // to Connected / NoInternet.
            state = RunState::Connecting;
        }
        let tun = read_text(&self.p.tun_iface_file)
            .await
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let (rx, tx) = self.os.iface_traffic(tun.as_deref()).await;
        let started = read_pidfile(&self.p.service_started_file).await;
        let uptime_sec = if raw == "running" && started > 0 {
            now_secs().saturating_sub(started as u64)
        } else {
            0
        };
        Ok(ServiceState {
            state,
            error,
            download_bytes: rx,
            upload_bytes: tx,
            uptime_sec,
            engine: self.running_engine().await,
        })
    }

    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
        let xray = self.core_version(CoreEngine::Xray).await;
        let singbox = self.core_version(CoreEngine::SingBox).await;
        Ok(PlatformCapabilities {
            cores: InstalledCores { xray, singbox },
            tun: self.os.tun_capable().await,
            bridge: "desktop".into(),
        })
    }

    fn core_path(&self, engine: Engine) -> PathBuf {
        PathBuf::from(self.core_bin(engine))
    }

    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
        let port = read_text(&self.p.socks_port_file)
            .await
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
        let pid = read_pidfile(&self.p.pidfile).await;
        let running = pid > 0 && pid_matches_any(pid, &self.p.core_bins()).await;
        Ok(ProxyStatus {
            running,
            socks_port: port,
            http_port: self.http_port().await,
        })
    }

    fn tune_config(&self, engine: Engine, config: &mut Value) {
        if engine != CoreEngine::SingBox {
            return;
        }
        // Pin the sing-box tun stack so a config built for another platform can't
        // leave a stack we don't support here (gvisor for the Linux root-binary path
        // terminating from the tun fd; system/wintun on Windows).
        let stack = self.os.singbox_stack();
        if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
            for ib in inbounds {
                if ib.get("type").and_then(Value::as_str) == Some("tun") {
                    ib["stack"] = Value::String(stack.into());
                }
            }
        }
    }

    fn watch_network_change(&self) -> Option<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(network::run_watcher(tx));
        Some(rx)
    }

    async fn data_path_healthy(&self) -> Option<bool> {
        let core_pid = read_pidfile(&self.p.pidfile).await;
        if !(core_pid > 0 && pid_matches_any(core_pid, &self.p.core_bins()).await) {
            return Some(false);
        }
        // xray relies on a tun2socks helper; sing-box runs the tun itself.
        let engine = read_text(&self.p.engine_file)
            .await
            .map(|s| s.trim().to_string());
        if engine.as_deref() != Some("sing-box") {
            let t = read_pidfile(&self.p.tun2socks_pidfile).await;
            if !(t > 0 && pid_matches_bin(t, &self.p.tun2socks_bin).await) {
                return Some(false);
            }
        }
        Some(true)
    }

    async fn spawn_test_core(
        &self,
        engine: Engine,
        cfg_path: &Path,
        log_path: &Path,
    ) -> anyhow::Result<Box<dyn TestCore>> {
        // Running as root (the helper), bind the test core's outbound to the physical
        // uplink so it escapes an active tun at the socket layer (SO_BINDTODEVICE) —
        // no per-test OS routing, no collision with the active server's routes. When
        // no tun is up the uplink *is* the default route, so the bind is a harmless
        // no-op. (In-process dev runs unprivileged: skip the bind — it'd need
        // CAP_NET_RAW and there's no managed tun to escape anyway.)
        if test_core_can_bind() {
            if let Some(dev) = routing::uplink_device().await {
                if let Some(text) = read_text(cfg_path).await {
                    if let Ok(mut cfg) = serde_json::from_str::<Value>(&text) {
                        crate::desktop::net::bind_proxy_outbound(engine, &mut cfg, &dev);
                        if let Ok(s) = serde_json::to_string(&cfg) {
                            let _ = write_text(cfg_path, &s).await;
                        }
                    }
                }
            }
        }
        let bin = self.core_bin(engine).to_owned();
        let dat = self.p.backend.dat_dir.to_string_lossy().into_owned();
        spawn_local_test_core(&bin, cfg_path, log_path, &dat).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_is_nonzero() {
        assert!(now_secs() > 0);
    }
}
