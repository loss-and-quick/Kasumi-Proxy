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
use kasumi_backend::fsjson::{read_data_path_state, write_data_path_state};
use kasumi_backend::lifecycle::{
    missing_rule_sets, random_tun_iface, referenced_srs, spawn_core, sync_geo_asset,
    verify_core_alive,
};
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    AppFilterCapability, AppInfo, BackendPaths, Engine, InstalledCores, Platform,
    PlatformCapabilities, StopDataPath, TestCore, spawn_local_test_core,
};
use kasumi_backend::proc::{kill_if_running, pid_matches_any, pid_matches_bin, read_pidfile};
use kasumi_core::contract::{LogTarget, RunState, ServiceState};
use kasumi_core::data_path_plan::{AppRouting, DataPathPlan, HostTraits, TunPlan};
use kasumi_core::data_path_state::DataPathState;
use kasumi_core::enums::{CoreEngine, wire_value};
use kasumi_core::request_identity::DeviceFacts;
use kasumi_core::state::{
    DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT, ProxyMode, SingboxStack, force_socks_port,
};

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

    /// The sing-box tun stack to pin: gvisor for the Linux root-binary path, system
    /// for Windows (wintun + kernel stack).
    fn singbox_stack(&self) -> SingboxStack;

    /// The host id: `/etc/machine-id` on Linux, `MachineGuid` on Windows.
    async fn machine_id(&self) -> Option<String>;

    /// OS name and release, a generic model and the UI locale.
    async fn device_facts(&self) -> DeviceFacts;
}

pub struct DesktopPlatform {
    p: DesktopPaths,
    os: OsSeam,
    /// This in-process data-path runs unprivileged because the saved proxy mode needs
    /// no privileges, so no privileged helper was brought up. A live switch to tun
    /// then can't succeed and is refused with a restart-required error (see
    /// [`Platform::start_data_path`]); the helper-backed and skip-elevation instances
    /// leave this `false` and behave exactly as before.
    gated_unprivileged: bool,
}

impl DesktopPlatform {
    pub fn new() -> anyhow::Result<Self> {
        Self::build(false)
    }

    /// An in-process platform for a session that came up with no privileged helper
    /// (the saved proxy mode needs none). It serves the non-tun modes fully but
    /// refuses a live switch to tun, which the helper-less process can't bring up.
    pub fn new_gated() -> anyhow::Result<Self> {
        Self::build(true)
    }

    fn build(gated_unprivileged: bool) -> anyhow::Result<Self> {
        Self::with_paths(DesktopPaths::resolve()?, gated_unprivileged)
    }

    /// Construct over prebuilt paths, bypassing the env/exe reads in
    /// [`DesktopPaths::resolve`] (tests inject a tempdir layout).
    pub(crate) fn with_paths(p: DesktopPaths, gated_unprivileged: bool) -> anyhow::Result<Self> {
        Ok(Self {
            p,
            os: OsSeam::new()?,
            gated_unprivileged,
        })
    }

    fn core_bin(&self, engine: CoreEngine) -> &str {
        match engine {
            CoreEngine::SingBox => &self.p.singbox_bin,
            CoreEngine::Xray => &self.p.xray_bin,
        }
    }

    async fn read_state(&self) -> Option<DataPathState> {
        read_data_path_state(&self.p.data_path_state_file).await
    }

    async fn write_state(&self, state: &DataPathState) {
        let _ = write_data_path_state(&self.p.data_path_state_file, state).await;
    }

    /// Mark the running data-path failed, keeping the engine/tun it recorded so
    /// teardown still reaps the right helper. No bail (the caller decides).
    async fn set_failed(&self, reason: &str) {
        let mut state = self.read_state().await.unwrap_or_default();
        state.run = RunState::Failed;
        state.failure_reason = Some(reason.to_owned());
        state.started_at = None;
        self.write_state(&state).await;
    }

    async fn fail(&self, reason: &str) -> anyhow::Result<()> {
        log::error!("data-path start failed: {reason}");
        self.set_failed(reason).await;
        anyhow::bail!("{reason}")
    }

    async fn http_port(&self) -> u16 {
        kasumi_backend::state::read_state_shell(&self.p.backend.app_state)
            .await
            .and_then(|s| s.settings.local_http_port)
            .unwrap_or(DEFAULT_LOCAL_HTTP_PORT)
    }

    /// The user's TUN-exclude CIDRs (e.g. docker bridge networks) from the saved
    /// settings, parsed into a list. Empty when unset — the proxy-server bypass
    /// still applies on its own.
    async fn tun_exclude_cidrs(&self) -> Vec<String> {
        kasumi_backend::state::read_state_shell(&self.p.backend.app_state)
            .await
            .map(|s| s.settings.tun_exclude_cidrs())
            .unwrap_or_default()
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
    /// the core owns its tun natively (or no document is recorded — nothing is up).
    /// The tun/engine → helper decision is a lookup on the recorded document
    /// ([`DataPathState::helpers`]); this shell only maps the resolved engine to
    /// its binary via [`tun_engine`]. Used by the watchdog and teardown.
    async fn expected_helper_bin(&self) -> Option<String> {
        let state = self.read_state().await?;
        expected_helper(&state, &self.p).map(str::to_owned)
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

    /// Bring up the data-path a plan describes. The shared steps (binary/config
    /// checks, geo prep, core spawn) live here; the genuinely different shapes are
    /// the plan's tun: none (the core's local inbound is the whole data path), native
    /// (the sing-box core owns it), or external (a helper fronts a socks-only core).
    /// Engine-specific spawn details live solely in [`super::tun_engine`].
    async fn start_proxy(&self, plan: &DataPathPlan) -> anyhow::Result<()> {
        let engine = plan.engine;
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

        let cfg_text = read_text(&cfg).await.unwrap_or_default();
        if is_singbox {
            self.singbox_geo_prep(&cfg_text).await?;
        }

        let ext = match &plan.tun {
            TunPlan::None => {
                // proxy-only/system/pac: the core's local socks/http inbound is the
                // whole data path — no tun device, no routing rewrite, and nothing to
                // escape (the core's own egress rides the physical default route).
                return self.spawn_core_verify(&core_bin, &cfg, &log).await;
            }
            TunPlan::Native { force_tun } => {
                // Native sing-box tun: the core owns the tun; the server bypass is baked
                // into the config (route_exclude_address) by prepare_singbox_config.
                prepare_singbox_config(
                    &cfg,
                    &self.p.tun_iface_file,
                    &self.p.tun2_iface_file,
                    *force_tun,
                )
                .await?;

                // Defensive sweep before bring-up: if a previous core crashed (so
                // stop_data_path never ran its teardown), its orphaned auto_route rules
                // would otherwise survive and black-hole the fresh tun. Idempotent —
                // clears nothing on a clean start.
                routing::clear_singbox_autoroute(&self.p.tun_iface_file, &self.p.tun2_iface_file)
                    .await;

                // The escape rule must exist before the core dials anything: its very
                // first connections (DNS bring-up, the server uplink) already carry the
                // egress mark. Everything unmarked — any uid, root included — stays
                // captured by the tun.
                routing::apply_singbox_escape_rule().await;

                return self.spawn_core_verify(&core_bin, &cfg, &log).await;
            }
            TunPlan::External(ext) => ext,
        };

        // External userspace tun in front of a socks-only core.
        self.os.precheck_external_tun(&self.p).await?;
        // Resolve the proxy servers before any tun route is up (needs DNS). They,
        // plus the user's TUN-exclude CIDRs (e.g. docker networks), route straight
        // out instead of through the proxy.
        let servers = crate::desktop::net::resolve_servers(&cfg_text).await;
        // An xray core whose egress is bound to the uplink takes the system's DNS
        // through the tun too, so it follows the core's DNS settings instead of
        // going straight to the network's resolver. It reaches its own servers
        // through the addresses pinned below, not through that DNS. A socks-only
        // sing-box resolves server names through the system resolver itself, so its
        // resolvers stay off the tun.
        let bound = can_bind_uplink();
        let capture_dns = bound && engine == CoreEngine::Xray;
        let bypass =
            routing::bypass_cidrs(&servers, &self.tun_exclude_cidrs().await, !capture_dns).await;

        // Bind every outbound the core dials the network with (servers + direct)
        // to the physical uplink so they escape the tun at the socket layer instead
        // of looping back through the external tun helper. Without this, the
        // `direct` outbound carrying geo-`direct` (e.g. RU) traffic, or a server
        // other than `proxy`, is captured by the split-default and loops. Gated on
        // CAP_NET_RAW (the privileged data-path owner); a harmless no-op in
        // unprivileged in-process dev, where there's no managed tun to escape.
        // (sing-box's native `auto_route` path escapes via its own
        // `auto_detect_interface` and is bound elsewhere.) It runs after the DNS
        // pinning so the `dns` outbound that adds is bound too.
        if capture_dns {
            pin_xray_servers(Path::new(&cfg), &servers).await;
        }
        if bound {
            inject_uplink_bind(engine, Path::new(&cfg)).await;
        }

        self.spawn_core_verify(&core_bin, &cfg, &log).await?;

        let iface = random_tun_iface();
        let _ = write_text(&self.p.tun_iface_file, &iface).await;
        let helper_log = self.p.backend.log(LogTarget::TunEngine);
        // Desktop binds the core's own outbounds to the uplink (see above) to escape
        // the tun, so the helper needs no fwmark — its upstream is loopback (the
        // core's SOCKS) and never hits routing anyway. (Android still marks it; that
        // param is load-bearing there, not here.)
        let helper = tun_engine::spawn(
            ext.engine,
            &self.p,
            &iface,
            plan.ports.socks,
            &helper_log,
            None,
            &wire_value(&ext.stack),
            &ext.opts,
        )
        .await?;
        let _ = write_text(
            &self.p.tun2socks_pidfile,
            &helper.id().unwrap_or(0).to_string(),
        )
        .await;
        // The helper creates the tun device; wait for it before addressing/routing.
        self.os.await_tun_up(&iface).await?;
        routing::apply_external_tun_routing(
            &iface,
            &bypass,
            capture_dns,
            &core_bin,
            &self.p.route_state_file,
        )
        .await?;
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

/// The helper binary a recorded data path runs, if any.
fn expected_helper<'a>(state: &DataPathState, p: &'a DesktopPaths) -> Option<&'a str> {
    let helper = state.helpers().into_iter().next()?;
    tun_engine::helper_bin(helper.engine, p)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Desktop per-app filter: the launcher's programs, matched by process name in the
/// core's own routing (`kasumi_core::app_process`). The filter is baked into the
/// built config, so a change shows up as a pending restart.
#[async_trait]
impl AppFilterCapability for DesktopPlatform {
    async fn list_apps(&self) -> anyhow::Result<Vec<AppInfo>> {
        Ok(crate::desktop::apps::list_apps().await)
    }
}

#[async_trait]
impl Platform for DesktopPlatform {
    fn paths(&self) -> &BackendPaths {
        &self.p.backend
    }

    fn host_traits(&self) -> HostTraits {
        HostTraits {
            proxy_modes: true,
            app_routing: AppRouting::PerProcess,
            pinned_singbox_stack: Some(self.os.singbox_stack()),
        }
    }

    async fn set_os_proxy(&self, mode: ProxyMode, plan: &DataPathPlan) {
        let ports = &plan.ports;
        crate::desktop::apply_os_proxy(mode, ports.socks, plan.os_proxy_http_port(), ports.pac)
            .await;
    }

    async fn clear_os_proxy(&self) {
        crate::desktop::clear_os_proxy().await;
    }

    async fn boot_init(&self) -> anyhow::Result<()> {
        use anyhow::Context;
        // Unlike Android (RUN_DIR ⊂ DATADIR), the desktop runtime dir may live under
        // a different base (XDG_RUNTIME_DIR / %LOCALAPPDATA%), so both must be created
        // explicitly. Propagate failures: a run-dir that can't be created surfaces as a
        // `failed:` state instead of silently misbehaving downstream.
        tokio::fs::create_dir_all(&self.p.datadir)
            .await
            .with_context(|| format!("create data dir {}", self.p.datadir))?;
        tokio::fs::create_dir_all(&self.p.run_dir)
            .await
            .with_context(|| format!("create run dir {}", self.p.run_dir))?;
        // Fresh start: seed a stopped document so a stale value can't make status lie
        // before the first command. Drop the pre-document `service-started` marker.
        self.write_state(&DataPathState::default()).await;
        remove_file(&format!("{}/service-started", self.p.run_dir)).await;
        Ok(())
    }

    async fn start_data_path(&self, plan: &DataPathPlan) -> anyhow::Result<()> {
        let engine = plan.engine;
        log::info!(
            "starting data-path: engine={engine:?} tun={:?} ports={:?} mode={:?}",
            plan.tun,
            plan.ports,
            plan.mode
        );
        // A helper-less in-process session can't bring up a tun; refuse the switch with
        // an actionable reason before any bring-up, so the UI shows a `failed:<reason>`
        // rather than a cryptic tun-creation error. Only the tun direction needs this —
        // the reverse (a helper-backed session running a non-tun mode) works fine, since
        // the mode rides the plan and the privileged path serves every mode.
        if self.gated_unprivileged && plan.mode == ProxyMode::Tun {
            return self
                .fail("tun mode needs an app restart (the privileged helper is not running)")
                .await;
        }
        // Record the bring-up (no started_at yet) so teardown/status know the engine +
        // tun before the core is even up. A no-tun mode records `NoTun`, so no helper
        // is ever expected.
        self.write_state(&plan.state(RunState::Connecting)).await;
        let result = self.start_proxy(plan).await;
        match result {
            Ok(()) => {
                let mut state = self.read_state().await.unwrap_or_default();
                // Process-up: `started_at` marks it (vs the bring-up `connecting`) and
                // drives uptime; the wire state stays Connecting until the Service's
                // connectivity probe refines it to Connected / NoInternet.
                state.started_at = Some(now_secs());
                self.write_state(&state).await;
                log::info!("data-path running ({engine:?})");
                Ok(())
            }
            Err(e) => {
                // Roll back a half-built data-path; keep any recorded failure reason.
                let already_failed = self
                    .read_state()
                    .await
                    .is_some_and(|s| s.run == RunState::Failed);
                if !already_failed {
                    self.set_failed(&e.to_string()).await;
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
        // Drop the pre-document `tun-engine` marker if an old version left one.
        remove_file(&format!("{}/tun-engine", self.p.run_dir)).await;
        remove_file(&self.p.tun_iface_file).await;
        remove_file(&self.p.tun2_iface_file).await;
        if !opts.keep_service_state {
            self.write_state(&DataPathState::default()).await;
        }
        Ok(())
    }

    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        // The recorded document is authoritative for the base state; the Service's
        // connectivity probe later refines a running Connecting → Connected / NoInternet.
        let doc = self.read_state().await;
        let state = doc.as_ref().map(|d| d.run).unwrap_or(RunState::Stopped);
        let error = doc.as_ref().and_then(|d| d.failure_reason.clone());
        let tun = read_text(&self.p.tun_iface_file)
            .await
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let (rx, tx) = self.os.iface_traffic(tun.as_deref()).await;
        // `started_at` is set only once the core is up, so uptime counts from there.
        let uptime_sec = doc
            .as_ref()
            .and_then(|d| d.started_at)
            .map(|s| now_secs().saturating_sub(s))
            .unwrap_or(0);
        Ok(ServiceState {
            state,
            error,
            download_bytes: rx,
            upload_bytes: tx,
            uptime_sec,
            engine: self.running_engine().await,
            tether_offload_bypass: false,
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
        let port = self
            .read_state()
            .await
            .map(|d| d.socks_port)
            .filter(|&p| p != 0)
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

    fn app_filter(&self) -> Option<&dyn AppFilterCapability> {
        Some(self)
    }

    async fn open_url(&self, url: &str) -> anyhow::Result<()> {
        // This runs in the GUI process, inside the user's session.
        open::that_detached(url)?;
        Ok(())
    }

    async fn device_facts(&self) -> DeviceFacts {
        self.os.device_facts().await
    }

    async fn machine_id(&self) -> Option<String> {
        self.os.machine_id().await
    }

    fn tune_config(&self, engine: Engine, config: &mut Value) {
        if engine != CoreEngine::SingBox {
            return;
        }
        // Pin the sing-box tun stack so a config built for another platform can't
        // leave a stack we don't support here (gvisor for the Linux root-binary path
        // terminating from the tun fd; system/wintun on Windows).
        let stack = wire_value(&self.os.singbox_stack());
        if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
            for ib in inbounds {
                if ib.get("type").and_then(Value::as_str) == Some("tun") {
                    ib["stack"] = Value::String(stack.clone());
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

    async fn tcp_ping(&self, host: &str, port: u16, timeout: Duration) -> Option<u64> {
        // Same escape as the test cores above; an unprivileged in-process run has
        // no managed tun to escape.
        if can_bind_uplink() {
            crate::desktop::net::uplink_tcp_ping(host, port, timeout).await
        } else {
            kasumi_backend::net::tcp_ping(host, port, timeout).await
        }
    }
}

/// Rewrite a core's config to bind every outbound that dials the network (see
/// `bind_uplink_outbounds`) to the physical uplink (`SO_BINDTODEVICE` /
/// `bind_interface`) so its traffic escapes an active tun. Used for both the main bridged core (so its `direct` outbound doesn't
/// loop the split-default tun) and helper-spawned test cores. Returns whether a bind
/// was actually written (needs a resolved uplink device and a writable JSON config);
/// for a test core the caller grants the matching `CAP_NET_RAW` only when this is
/// true, so the test core never carries the cap without using it.
async fn inject_uplink_bind(engine: Engine, cfg_path: &Path) -> bool {
    let Some(dev) = routing::uplink_device().await else {
        return false;
    };
    // Pin the source addresses too, so the device bind escapes the tun deterministically
    // on a multi-homed host (see `bind_uplink_outbounds`). A family that can't be
    // resolved keeps the device-only behaviour.
    let source = routing::uplink_source(&dev).await;
    let Some(text) = read_text(cfg_path).await else {
        return false;
    };
    let Ok(mut cfg) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    kasumi_core::outbound_bind::bind_uplink_outbounds(engine, &mut cfg, &dev, &source);
    match serde_json::to_string(&cfg) {
        Ok(s) => write_text(cfg_path, &s).await.is_ok(),
        Err(_) => false,
    }
}

/// Prepare the on-disk xray config for DNS sent through the tun: pin the proxy
/// servers' pre-resolved addresses (see
/// `kasumi_core::outbound_bind::pin_xray_server_hosts`) and answer inbound DNS
/// with the core's DNS module.
async fn pin_xray_servers(
    cfg_path: &Path,
    servers: &std::collections::BTreeMap<String, Vec<String>>,
) -> bool {
    let Some(text) = read_text(cfg_path).await else {
        return false;
    };
    let Ok(mut cfg) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    kasumi_core::outbound_bind::pin_xray_server_hosts(&mut cfg, servers);
    // The system's DNS now arrives at the core addressed to whatever the network
    // resolver is (often the LAN router, which the proxy server can't reach), so
    // answer it with xray's DNS module rather than forwarding it there.
    kasumi_core::xray_config::hijack_inbound_dns(&mut cfg);
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

    #[test]
    fn start_and_watchdog_expect_the_same_helper() {
        use kasumi_core::enums::TunEngine;
        use kasumi_core::state::AdvancedSettings;
        use strum::IntoEnumIterator;

        let p = DesktopPaths::from_bases("data".into(), "run".into(), "bin", false, None);
        let host = HostTraits {
            proxy_modes: true,
            app_routing: AppRouting::PerProcess,
            pinned_singbox_stack: Some(SingboxStack::Gvisor),
        };
        for engine in CoreEngine::iter() {
            for tun in TunEngine::iter() {
                for mode in [ProxyMode::Tun, ProxyMode::System] {
                    let mut s = AdvancedSettings {
                        proxy_mode: mode,
                        ..Default::default()
                    };
                    s.tun_by_core.insert(engine, tun);
                    let plan = DataPathPlan::resolve(engine, &s, host);
                    let spawned = plan
                        .external()
                        .and_then(|e| tun_engine::helper_bin(e.engine, &p));
                    let doc = plan.state(RunState::Connecting).to_json();
                    let recorded = DataPathState::from_json(doc.as_bytes()).unwrap();
                    assert_eq!(
                        expected_helper(&recorded, &p),
                        spawned,
                        "{engine:?} + {tun:?}, {mode:?}"
                    );
                }
            }
        }
    }
}
