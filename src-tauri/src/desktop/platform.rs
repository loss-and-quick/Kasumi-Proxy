//! The desktop `Platform`: thin orchestration over the neutral lifecycle steps,
//! shared by Linux and Windows. The bring-up flow, status reporting and teardown are
//! identical across both OSes; the handful of genuine differences (tun-up wait, byte
//! counters, tun capability, sing-box stack, the wintun precheck) are funnelled
//! through the [`DesktopOs`] seam, implemented per-OS in `linux::os` /
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
use kasumi_backend::lifecycle::{
    engine_label, missing_rule_sets, random_tun_iface, referenced_srs, running_external_engine,
    spawn_core, sync_geo_asset, verify_core_alive,
};
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    BackendPaths, Engine, InstalledCores, Platform, PlatformCapabilities, StartDataPath,
    StopDataPath, TestCore, spawn_local_test_core,
};
use kasumi_backend::proc::{kill_if_running, pid_matches_any, pid_matches_bin, read_pidfile};
use kasumi_core::contract::{LogTarget, RunState, ServiceState};
use kasumi_core::enums::{CoreEngine, TunEngine};
use kasumi_core::state::{
    AppState, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT, force_socks_port,
};
use kasumi_core::tun::TunOptions;

use crate::desktop::paths::DesktopPaths;
use crate::desktop::singbox::prepare_singbox_config;
use crate::desktop::{OsSeam, network, resume, routing, tun_engine};

/// The per-OS seam: only the parts of the data-path that genuinely differ between
/// Linux and Windows. Everything else lives in the shared [`DesktopPlatform`].
#[async_trait]
pub(crate) trait DesktopOs: Send + Sync {
    fn new() -> anyhow::Result<Self>
    where
        Self: Sized;

    /// Extra precheck before the external-tun path (Windows: the bundled
    /// `wintun.dll` must be on disk). Linux has nothing to check.
    async fn precheck_external_tun(&self, p: &DesktopPaths) -> anyhow::Result<()>;

    /// Wait for the freshly-created tun `name` to come up before addressing/routing.
    /// Linux is best-effort (proceeds even on timeout, matching its `ip` flow);
    /// Windows errors if the wintun adapter never appears.
    async fn await_tun_up(&self, name: &str) -> anyhow::Result<()>;

    /// RX/TX byte counters for `iface`, or `(0, 0)` where unsupported (Windows has
    /// no `/proc/net/dev`).
    async fn iface_traffic(&self, iface: Option<&str>) -> (u64, u64);

    /// Whether a tun is creatable right now (Linux checks `/dev/net/tun`; Windows
    /// always can — sing-box embeds wintun, the external-tun path checks the DLL at
    /// start).
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

    /// The external tun helper binary the *running* data-path expects, or `None` when
    /// the core owns its tun natively. The marker/engine decision is single-sourced in
    /// [`running_external_engine`] (shared with the Android daemon); this shell only
    /// supplies the inputs — the marker file and the live core — and maps the
    /// resolved engine to its binary via [`tun_engine`]. Used by the watchdog and
    /// teardown to decide whether a live helper is required.
    async fn expected_helper_bin(&self) -> Option<String> {
        let marker = read_text(&self.p.tun_engine_file).await;
        let engine = self.running_engine().await.map(engine_label);
        let tun = running_external_engine(marker.as_deref(), engine)?;
        tun_engine::helper_bin(tun, &self.p).map(str::to_owned)
    }

    /// Keep sing-box's geo `.srs` rule-sets in step with their `.dat` sources and
    /// fail fast if any referenced rule-set is still missing. Shared by the native
    /// and the socks-only (external-tun) sing-box paths.
    async fn singbox_geo_prep(&self, cfg_text: &str) -> anyhow::Result<()> {
        let needed = referenced_srs(cfg_text);
        let geo = Path::new(&self.p.geodat2srs_bin);
        let dat = self.p.backend.dat_dir.as_path();
        let srs = self.p.backend.srs_dir.as_path();
        sync_geo_asset("geoip", dat, srs, geo, &needed).await;
        sync_geo_asset("geosite", dat, srs, geo, &needed).await;
        if !missing_rule_sets(cfg_text).await.is_empty() {
            return self.fail("missing rule_set assets").await;
        }
        Ok(())
    }

    /// Spawn the proxy core (`<bin> run -c <cfg>`), persist its pid and confirm it
    /// stayed up. Shared by the native and external-tun bring-ups.
    async fn spawn_core_verify(&self, bin: &str, cfg: &str, log: &Path) -> anyhow::Result<()> {
        let dat_dir = self.p.backend.dat_dir.to_string_lossy().into_owned();
        let child = spawn_core(bin, cfg, log, &dat_dir, false).await?;
        let pid = child.id().unwrap_or(0) as i32;
        let _ = write_text(&self.p.pidfile, &pid.to_string()).await;
        if !verify_core_alive(pid, bin, 6, Duration::from_millis(250)).await {
            return self
                .fail(&format!("core exited on startup — see {}", log.display()))
                .await;
        }
        Ok(())
    }

    /// Bring up the data-path for a `(core, tun engine)` pair. The shared steps
    /// (binary/config checks, geo prep, core spawn) live here; the two genuinely
    /// different shapes are the native sing-box tun (the core owns it) and an
    /// external userspace tun (a helper fronts a socks-only core). Engine-specific
    /// spawn details live solely in [`super::tun_engine`].
    async fn start_proxy(
        &self,
        engine: CoreEngine,
        tun: TunEngine,
        tun_opts: &TunOptions,
        socks_port: u16,
    ) -> anyhow::Result<()> {
        let is_singbox = engine == CoreEngine::SingBox;
        let core_bin = self.core_bin(engine).to_owned();
        let cfg = if is_singbox {
            self.p.backend.singbox_config.to_string_lossy().into_owned()
        } else {
            self.p.backend.xray_config.to_string_lossy().into_owned()
        };
        let log = self.p.backend.log(if is_singbox {
            LogTarget::Singbox
        } else {
            LogTarget::Xray
        });
        if !exists(&core_bin).await {
            return self.fail("core binary missing").await;
        }
        if !exists(&cfg).await {
            return self.fail("config missing").await;
        }
        // Record which TUN engine this data-path runs (teardown/watchdog read it).
        let _ = write_text(&self.p.tun_engine_file, &tun_engine::marker(tun)).await;

        let cfg_text = read_text(&cfg).await.unwrap_or_default();
        if is_singbox {
            self.singbox_geo_prep(&cfg_text).await?;
        }

        if !tun_engine::is_external(tun) {
            // Native sing-box tun: the core owns the tun; the server bypass is baked
            // into the config (route_exclude_address) by prepare_singbox_config.
            prepare_singbox_config(&cfg, &self.p.tun_iface_file, &self.p.tun2_iface_file).await?;

            // Defensive sweep before bring-up: if a previous core crashed (so
            // stop_data_path never ran its teardown), its orphaned auto_route rules
            // would otherwise survive and black-hole the fresh tun. Idempotent —
            // clears nothing on a clean start.
            routing::clear_singbox_autoroute(&self.p.tun_iface_file, &self.p.tun2_iface_file).await;

            self.spawn_core_verify(&core_bin, &cfg, &log).await?;
            return Ok(());
        }

        // External userspace tun in front of a socks-only core.
        self.os.precheck_external_tun(&self.p).await?;
        // Resolve the server-bypass set before any tun route is up (needs DNS).
        let bypass = routing::resolve_bypass_cidrs(&cfg_text).await;

        // Bind the core's own egress outbounds (proxy + direct) to the physical
        // uplink so they escape the tun at the socket layer instead of looping back
        // through the external tun helper. Without this, the `direct` outbound
        // carrying geo-`direct` (e.g. RU) traffic is captured by the split-default
        // and loops. Gated on CAP_NET_RAW (the privileged data-path owner); a
        // harmless no-op in unprivileged in-process dev, where there's no managed
        // tun to escape. (sing-box's native `auto_route` path escapes via its own
        // `auto_detect_interface` and is bound elsewhere.)
        if can_bind_uplink() {
            inject_uplink_bind(engine, Path::new(&cfg)).await;
        }

        self.spawn_core_verify(&core_bin, &cfg, &log).await?;

        let iface = random_tun_iface();
        let _ = write_text(&self.p.tun_iface_file, &iface).await;
        let helper_log = self.p.backend.log(LogTarget::Tun2socks);
        // Desktop binds the core's own outbounds to the uplink (see above) to escape
        // the tun, so the helper needs no fwmark — its upstream is loopback (the
        // core's SOCKS) and never hits routing anyway. (Android still marks it; that
        // param is load-bearing there, not here.)
        let helper = tun_engine::spawn(
            tun,
            &self.p,
            &iface,
            socks_port,
            &helper_log,
            None,
            tun_opts,
        )
        .await?;
        let _ = write_text(
            &self.p.tun2socks_pidfile,
            &helper.id().unwrap_or(0).to_string(),
        )
        .await;
        // The helper creates the tun device; wait for it before addressing/routing.
        self.os.await_tun_up(&iface).await?;
        routing::apply_external_tun_routing(&iface, &bypass, &self.p.route_state_file).await?;
        Ok(())
    }
}

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self::new().expect("desktop paths resolve")
    }
}

/// Whether a core spawned from *this* process will hold an effective `CAP_NET_RAW`,
/// so its uplink bind (`SO_BINDTODEVICE` / `bind_interface`) can escape an active tun.
/// Gates both the main bridged core's bind and the test-core bind. Only the
/// privileged data-path owner qualifies: the root helper on Linux, the LocalSystem
/// service on Windows. In-process dev on unix is unprivileged and skips the bind
/// (there's no managed tun to escape there anyway).
///
/// It checks the effective `CAP_NET_RAW` directly (which reads true under a root *or*
/// caps-only helper whose bounding set keeps `NET_RAW`, and false for unprivileged
/// dev) instead of the old `geteuid() == 0` proxy — so the gate stays honest whether
/// the helper is launched as root (pkexec) or as the GUI uid with file caps (NixOS
/// wrappers). Fails closed on a query error (see
/// [`capabilities::has_effective_net_raw`]).
fn can_bind_uplink() -> bool {
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
        let StartDataPath {
            engine,
            tun,
            tun_opts,
            socks_port,
        } = opts;
        log::info!("starting data-path: engine={engine:?} tun={tun:?} socks_port={socks_port}");
        self.set_service_state("connecting").await;
        let _ = write_text(&self.p.socks_port_file, &socks_port.to_string()).await;
        let result = self.start_proxy(engine, tun, &tun_opts, socks_port).await;
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
        // The external tun helper this data-path used (None for a native sing-box
        // tun).
        // Stop the core first, gracefully: a sing-box auto_route core removes its
        // own routes + tun on terminate. Then tear down the manual routing (no-op
        // for a native sing-box — no route-state file) and the external tun helper.
        kill_if_running(
            read_pidfile(&self.p.pidfile).await,
            None,
            &self.p.pidfile,
            true,
        )
        .await;
        routing::clear_external_tun_routing(&self.p.route_state_file).await;
        // Fallback: a native sing-box core that didn't exit cleanly (crash / SIGKILL)
        // leaves its auto_route ip-rules/tables behind; sweep them so they don't
        // wedge the next bring-up. No-op for external-tun cores (no rules at those
        // priorities).
        routing::clear_singbox_autoroute(&self.p.tun_iface_file, &self.p.tun2_iface_file).await;
        // Kill the tun helper only if the pidfile's pid still belongs to a known
        // helper binary. A stale pidfile from an unclean external-tun exit whose pid
        // was recycled by an unrelated process must never be signalled — the
        // data-path runs privileged, so an unguarded kill could take down an
        // arbitrary process as root. (The old always-`Some(tun2socks_bin)` guard was
        // lost when the marker-based helper resolution went in.)
        let helper_pid = read_pidfile(&self.p.tun2socks_pidfile).await;
        if helper_pid > 0 && pid_matches_any(helper_pid, &self.p.helper_bins()).await {
            kill_if_running(helper_pid, None, &self.p.tun2socks_pidfile, false).await;
        } else {
            remove_file(&self.p.tun2socks_pidfile).await;
        }
        remove_file(&self.p.tun_engine_file).await;
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
        let http_port = self.http_port().await;
        Ok(ProxyStatus {
            running,
            socks_port: port,
            http_port,
            force_port: force_socks_port(port, http_port),
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

    fn watch_system_resume(&self) -> Option<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(resume::run_watcher(tx));
        Some(rx)
    }

    async fn data_path_healthy(&self) -> Option<bool> {
        let core_pid = read_pidfile(&self.p.pidfile).await;
        if !(core_pid > 0 && pid_matches_any(core_pid, &self.p.core_bins()).await) {
            return Some(false);
        }
        // An external-tun data-path also relies on its helper process; a native
        // sing-box runs the tun itself, so there's nothing extra to check. When a
        // helper is expected (marker, or an xray core with no marker after an
        // upgrade) its pid must be present AND alive — a missing pidfile means the
        // helper never came up, which is unhealthy, so the watchdog rebuilds it.
        if let Some(helper_bin) = self.expected_helper_bin().await {
            let t = read_pidfile(&self.p.tun2socks_pidfile).await;
            if !(t > 0 && pid_matches_bin(t, &helper_bin).await) {
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
        // Running privileged (the helper), bind the test core's outbound to the
        // physical uplink so it escapes an active tun at the socket layer
        // (SO_BINDTODEVICE / bind_interface) — no per-test OS routing, no collision
        // with the active server's routes. When no tun is up the uplink *is* the
        // default route, so the bind is a harmless no-op. (In-process dev runs
        // unprivileged: skip the bind — it'd need CAP_NET_RAW and there's no managed
        // tun to escape anyway.)
        //
        // CAP_NET_RAW for the bind is inherited from the helper's ambient set (raised
        // once at startup), so there's no per-spawn cap handling here: under root the
        // child already has every cap; under the caps-only launcher it gets NET_RAW
        // from the ambient set; unprivileged dev skips the bind entirely (above).
        let _bound = can_bind_uplink() && inject_uplink_bind(engine, cfg_path).await;
        let bin = self.core_bin(engine).to_owned();
        let dat = self.p.backend.dat_dir.to_string_lossy().into_owned();
        spawn_local_test_core(&bin, cfg_path, log_path, &dat).await
    }
}

/// Rewrite a core's config to bind its egress outbounds (proxy + direct) to the
/// physical uplink (`SO_BINDTODEVICE` / `bind_interface`) so its traffic escapes an
/// active tun. Used for both the main bridged core (so its `direct` outbound doesn't
/// loop the split-default tun) and helper-spawned test cores. Returns whether a bind
/// was actually written (needs a resolved uplink device and a writable JSON config);
/// for a test core the caller grants the matching `CAP_NET_RAW` only when this is
/// true, so the test core never carries the cap without using it.
async fn inject_uplink_bind(engine: Engine, cfg_path: &Path) -> bool {
    let Some(dev) = routing::uplink_device().await else {
        return false;
    };
    // Pin the source address too, so the device bind escapes the tun deterministically
    // on a multi-homed host (see `bind_uplink_outbounds`). `None` on platforms/paths
    // that can't resolve it keeps the device-only behaviour.
    let source = routing::uplink_source().await;
    let Some(text) = read_text(cfg_path).await else {
        return false;
    };
    let Ok(mut cfg) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    kasumi_core::outbound_bind::bind_uplink_outbounds(engine, &mut cfg, &dev, source.as_deref());
    match serde_json::to_string(&cfg) {
        Ok(s) => write_text(cfg_path, &s).await.is_ok(),
        Err(_) => false,
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
