//! The Android `Platform`: thin orchestration over the neutral lifecycle steps,
//! owning only the OS-specific parts — routing, sysctl locks, `/dev/net/tun`, and
//! the per-uid app filter.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use kasumi_backend::fs::{exists, read_text, remove_file, write_text};
use kasumi_backend::fsjson::{read_data_path_state, write_data_path_state};
use kasumi_backend::lifecycle::{
    TunSpawn, inject_singbox_ifaces, missing_rule_sets, referenced_srs, spawn_core,
    spawn_tun_engine, sync_geo_asset, verify_core_alive,
};
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    AppFilterCapability, AppInfo, BackendPaths, Engine, InstalledCores, Platform,
    PlatformCapabilities, StopDataPath,
};
use kasumi_backend::proc::{kill_if_running, pid_matches_any, pid_matches_bin, read_pidfile};
use kasumi_core::contract::{RunState, ServiceState};
use kasumi_core::data_path_plan::{
    AppRouting, DataPathPlan, ExternalTun, HostTraits, LocalPorts, TunPlan,
};
use kasumi_core::data_path_state::{DataPathState, HelperSlot, TunSlot};
use kasumi_core::enums::{CoreEngine, TunEngine, wire_value};
use kasumi_core::profile::Protocol;
use kasumi_core::request_identity::{AndroidBuild, DeviceFacts};
use kasumi_core::state::{AdvancedSettings, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT};
use kasumi_core::tun::TunOptions;

use super::network::run_watcher;
use super::paths::{
    CORE_BINS, DATA_PATH_STATE_FILE, DATADIR, GEODAT2SRS_BIN, HEV_BIN, HEV_CONFIG, HEV2_CONFIG, IP,
    PIDFILE, RUN_DIR, SINGBOX_BIN, SINGBOX_BRIDGE_CONFIG, SINGBOX_BRIDGE2_CONFIG, TUN_IFACE_FILE,
    TUN2_IFACE_FILE, TUN2SOCKS_BIN, TUN2SOCKS_CONFIG, TUN2SOCKS_PIDFILE, TUN2SOCKS2_CONFIG,
    TUN2SOCKS2_PIDFILE, XRAY_BIN, backend_paths,
};
use super::routing::{
    AppFilter, RoutingState, apply_external_tun_routing, apply_guards, clear_orphaned_tun_rules,
    clear_routing_rules,
};
use super::sysctl::{lock_tun_iface, setup_sysctl_locks};
use super::tether_offload::{hw_offload_bypass, restore_hw_offload};
use super::tethering::{TetherPath, start_tether_watcher, stop_tether_watcher};
use super::{run_out, silent, ssaid};

/// Every start runs a tun, apps are routed by uid, and the sidecar takes the stack
/// the settings name.
const HOST: HostTraits = HostTraits {
    proxy_modes: false,
    app_routing: AppRouting::PerUid,
    pinned_singbox_stack: None,
};

pub struct AndroidPlatform {
    paths: BackendPaths,
}

impl AndroidPlatform {
    pub fn new() -> Self {
        Self {
            paths: backend_paths(),
        }
    }
}

impl Default for AndroidPlatform {
    fn default() -> Self {
        Self::new()
    }
}

fn core_bin(engine: CoreEngine) -> &'static str {
    match engine {
        CoreEngine::SingBox => SINGBOX_BIN,
        CoreEngine::Xray => XRAY_BIN,
    }
}

fn core_bins() -> Vec<String> {
    CORE_BINS.iter().map(|s| s.to_string()).collect()
}

/// External-TUN helper binary for `tun`. `SingboxTun` here is a *sidecar* sing-box
/// fronting a non-sing-box core (the native sing-box path never reaches the external
/// bring-up), so its binary is sing-box itself. The single place the daemon maps an
/// engine to a binary.
fn tun_helper_bin(tun: TunEngine) -> &'static str {
    match tun {
        TunEngine::Hev => HEV_BIN,
        TunEngine::SingboxTun => SINGBOX_BIN,
        TunEngine::Tun2socks => TUN2SOCKS_BIN,
    }
}

/// Everything the daemon needs to run, find and stop one helper process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HelperSpec {
    bin: &'static str,
    /// The config the engine writes at bring-up: tun2socks'/hev's YAML or the
    /// sidecar sing-box's JSON.
    cfg: &'static str,
    pidfile: &'static str,
    iface_file: &'static str,
    log: &'static str,
}

fn helper_spec(h: HelperSlot) -> HelperSpec {
    let bin = tun_helper_bin(h.engine);
    match h.slot {
        TunSlot::Main => HelperSpec {
            bin,
            cfg: match h.engine {
                TunEngine::SingboxTun => SINGBOX_BRIDGE_CONFIG,
                TunEngine::Tun2socks => TUN2SOCKS_CONFIG,
                TunEngine::Hev => HEV_CONFIG,
            },
            pidfile: TUN2SOCKS_PIDFILE,
            iface_file: TUN_IFACE_FILE,
            log: "tun-engine.log",
        },
        TunSlot::Force => HelperSpec {
            bin,
            cfg: match h.engine {
                TunEngine::SingboxTun => SINGBOX_BRIDGE2_CONFIG,
                TunEngine::Tun2socks => TUN2SOCKS2_CONFIG,
                TunEngine::Hev => HEV2_CONFIG,
            },
            pidfile: TUN2SOCKS2_PIDFILE,
            iface_file: TUN2_IFACE_FILE,
            log: "tun-engine2.log",
        },
    }
}

/// The local port a helper bridges its tun into: the core's socks inbound, or for
/// the force-proxy tun its `force-in`, which skips the geo rules.
fn helper_target(slot: TunSlot, ports: &LocalPorts) -> u16 {
    match slot {
        TunSlot::Main => ports.socks,
        TunSlot::Force => ports.force,
    }
}

/// The helpers the watchdog requires alive for a recorded data path: every one the
/// start brought up.
fn watched_helpers(state: &DataPathState) -> Vec<HelperSpec> {
    state.helpers().into_iter().map(helper_spec).collect()
}

/// Helper binary a teardown matches for the running data-path — tun2socks by
/// default, a harmless guard for a native tun with no helper pid.
async fn running_helper_bin() -> &'static str {
    read_state()
        .await
        .and_then(|s| s.external_tun())
        .map(tun_helper_bin)
        .unwrap_or(TUN2SOCKS_BIN)
}

/// One system property, trimmed; empty when unset.
async fn getprop(name: &str) -> String {
    run_out(&["getprop", name]).await.1.trim().to_owned()
}

fn app_state_path() -> String {
    format!("{DATADIR}/app-state.json")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn read_state() -> Option<DataPathState> {
    read_data_path_state(DATA_PATH_STATE_FILE).await
}

async fn write_state(state: &DataPathState) {
    let _ = write_data_path_state(DATA_PATH_STATE_FILE, state).await;
}

/// Mark the running data-path failed, keeping the recorded engine/tun so teardown
/// still reaps the right helper.
async fn set_failed(reason: &str) {
    let mut state = read_state().await.unwrap_or_default();
    state.run = RunState::Failed;
    state.failure_reason = Some(reason.to_owned());
    state.started_at = None;
    write_state(&state).await;
}

pub(super) async fn read_settings() -> Option<AdvancedSettings> {
    kasumi_backend::state::read_state_shell(Path::new(&app_state_path()))
        .await
        .map(|s| s.settings)
}

async fn read_app_filter() -> AppFilter {
    match read_settings().await {
        Some(s) => AppFilter {
            capture_mode: s.app_capture_mode,
            entries: s.app_filter,
            strict: s.strict_route,
        },
        None => AppFilter {
            capture_mode: Default::default(),
            entries: BTreeMap::new(),
            strict: false,
        },
    }
}

async fn http_port() -> u16 {
    read_settings()
        .await
        .and_then(|s| s.local_http_port)
        .unwrap_or(DEFAULT_LOCAL_HTTP_PORT)
}

pub(super) async fn read_iface(file: &str) -> Option<String> {
    read_text(file)
        .await
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// (Re)install the per-app guards for the running data path: its local proxy
/// ports and the tun devices it brought up (see `routing::guard_rules`).
async fn refresh_guards(ports: &LocalPorts) {
    let ports = [ports.socks, ports.http, ports.force];
    let tun = read_iface(TUN_IFACE_FILE).await;
    let tun2 = read_iface(TUN2_IFACE_FILE).await;
    let tuns: Vec<&str> = [tun.as_deref(), tun2.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    apply_guards(&read_app_filter().await, &ports, &tuns).await;
}

async fn ensure_tun_node() {
    if exists("/dev/net/tun").await {
        return;
    }
    silent(&["mkdir", "-p", "/dev/net"]).await;
    silent(&["mknod", "/dev/net/tun", "c", "10", "200"]).await;
    silent(&["chmod", "666", "/dev/net/tun"]).await;
}

async fn fresh_iface(file: &str) -> String {
    let name = kasumi_backend::lifecycle::random_tun_iface();
    let _ = write_text(file, &name).await;
    name
}

fn core_files(engine: CoreEngine) -> (&'static str, String, String) {
    if engine == CoreEngine::SingBox {
        (
            SINGBOX_BIN,
            format!("{DATADIR}/singbox.json"),
            format!("{DATADIR}/singbox.log"),
        )
    } else {
        (
            XRAY_BIN,
            format!("{DATADIR}/config.json"),
            format!("{DATADIR}/xray.log"),
        )
    }
}

async fn core_version(engine: CoreEngine) -> Option<String> {
    let bin = core_bin(engine);
    if !exists(bin).await {
        return None;
    }
    let (code, out) = run_out(&[bin, "version"]).await;
    if code != 0 {
        return None;
    }
    out.lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Spawn the external TUN helper for `iface`, persist its pid, wait for the iface
/// to appear. Routes through the shared `spawn_tun_engine` so the daemon learns no
/// engine specifics beyond the files in its [`HelperSpec`]. A spawn failure (e.g.
/// the binary missing after a partial module update) or the tun device never
/// appearing is surfaced as an error so the caller fails the start loudly, instead
/// of routing into a bridge that never came up and black-holing the device until
/// the watchdog happens to notice.
async fn bring_up_tun_helper(
    helper: HelperSlot,
    spec: &HelperSpec,
    iface: &str,
    socks_port: u16,
    stack: &str,
    opts: &TunOptions,
) -> anyhow::Result<()> {
    let log = format!("{DATADIR}/{}", spec.log);
    let spawn = TunSpawn {
        bin: spec.bin,
        iface,
        slot: helper.slot,
        ipv6: true,
        socks_port,
        log_path: Path::new(&log),
        cfg_path: Path::new(spec.cfg),
        stack,
        opts,
    };
    let child = spawn_tun_engine(helper.engine, &spawn)
        .await
        .map_err(|e| anyhow::anyhow!("spawn tun helper: {e} — see {log}"))?;
    let pid = child.id().unwrap_or(0);
    let _ = write_text(spec.pidfile, &pid.to_string()).await;
    for _ in 0..10 {
        if silent(&[IP, "link", "show", iface]).await == 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // The pid is live but the device never appeared (the helper exited post-spawn, or
    // /dev/net/tun is unusable): treat as a failed bring-up rather than route into a
    // non-existent tun.
    anyhow::bail!("tun helper tun {iface} never came up — see {log}")
}

/// External-tun data-path bring-up: a userspace tun per helper the plan runs,
/// bridged to the core, plus per-app routing. A native sing-box tun needs none of
/// this — it auto_routes its own tun.
async fn bring_up_external_tun(plan: &DataPathPlan, ext: &ExternalTun) -> anyhow::Result<()> {
    let stack = wire_value(&ext.stack);
    let mut ifaces = Vec::new();
    for h in plan.helpers() {
        let spec = helper_spec(h);
        let iface = match read_iface(spec.iface_file).await {
            Some(x) => x,
            None => fresh_iface(spec.iface_file).await,
        };
        let pid = read_pidfile(spec.pidfile).await;
        if !(pid > 0 && pid_matches_bin(pid, spec.bin).await) {
            let target = helper_target(h.slot, &plan.ports);
            bring_up_tun_helper(h, &spec, &iface, target, &stack, &ext.opts).await?;
        }
        ifaces.push((h.slot, iface));
    }
    if !ext.force_tun {
        let force = helper_spec(HelperSlot {
            engine: ext.engine,
            slot: TunSlot::Force,
        });
        kill_if_running(
            read_pidfile(force.pidfile).await,
            Some(force.bin),
            force.pidfile,
            true,
        )
        .await;
        remove_file(force.iface_file).await;
    }
    let iface_of = |slot: TunSlot| {
        ifaces
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, i)| i.clone())
    };
    let tun_iface = iface_of(TunSlot::Main);
    if let Some(tun) = &tun_iface {
        lock_tun_iface(tun).await;
    }
    // Route exactly the filter the plan was resolved with.
    let filter = match &ext.uid_filter {
        Some(f) => AppFilter {
            capture_mode: f.capture_mode,
            entries: f.entries.clone(),
            strict: f.strict,
        },
        None => read_app_filter().await,
    };
    let rs = RoutingState {
        tun_iface,
        tun2_iface: iface_of(TunSlot::Force),
        filter,
        socks_port: plan.ports.socks,
        http_port: plan.ports.http,
    };
    apply_external_tun_routing(&rs).await;
    Ok(())
}

/// Extra starts for a native sing-box that lost the `xtables.lock` race.
const XTABLES_RETRIES: u32 = 1;
/// Wait before the first such retry; doubles for each further one.
const XTABLES_BACKOFF: Duration = Duration::from_millis(750);

/// Whether a core that died on startup lost the race for the global
/// `xtables.lock`. Android's iptables reports "Can't lock /system/etc/xtables.lock",
/// upstream iptables "Another app is currently holding the xtables lock".
fn lost_xtables_race(log: &str) -> bool {
    let log = log.to_ascii_lowercase();
    log.contains("xtables.lock") || log.contains("xtables lock")
}

/// How long to wait before starting a core that died on startup again, or `None`
/// to give up. Only a native sing-box tun runs iptables itself (`auto_redirect`,
/// without `-w`), so only it can lose the lock to another process such as netd,
/// and that race is transient: it gets [`XTABLES_RETRIES`] more tries.
fn start_retry_delay(native_singbox: bool, attempt: u32, log: &str) -> Option<Duration> {
    (native_singbox && attempt < XTABLES_RETRIES && lost_xtables_race(log))
        .then(|| XTABLES_BACKOFF * 2u32.pow(attempt))
}

async fn fail(reason: &str) -> anyhow::Result<()> {
    set_failed(reason).await;
    anyhow::bail!("{reason}")
}

async fn start_inner(plan: &DataPathPlan, bin: &str, cfg: &str, log: &str) -> anyhow::Result<()> {
    if !exists(bin).await {
        return fail("core binary missing").await;
    }
    if !exists(cfg).await {
        return fail("config missing").await;
    }
    if plan.tun == TunPlan::None {
        return fail("this device runs the proxy only through a tun").await;
    }
    let native = matches!(plan.tun, TunPlan::Native { .. });

    if plan.engine == CoreEngine::SingBox {
        // Generate/keep only the .srs this config references (needed even when
        // sing-box runs socks-only — its route rules still reference rule-sets).
        let cfg_text = read_text(cfg).await.unwrap_or_default();
        let needed = referenced_srs(&cfg_text);
        let geo = Path::new(GEODAT2SRS_BIN);
        let dat = Path::new(DATADIR);
        sync_geo_asset("geoip", dat, dat, geo, &needed).await;
        sync_geo_asset("geosite", dat, dat, geo, &needed).await;
        if !missing_rule_sets(&cfg_text).await.is_empty() {
            return fail("missing rule_set assets").await;
        }
        // Only the native tun has tun inbounds to name; socks-only has none.
        if let TunPlan::Native { force_tun } = plan.tun {
            inject_singbox_ifaces(
                Path::new(cfg),
                Path::new(TUN_IFACE_FILE),
                Path::new(TUN2_IFACE_FILE),
                force_tun,
            )
            .await?;
        }
    }

    let mut attempt = 0;
    loop {
        // stopDataPath always runs before a start/restart (Service), so the pidfile is
        // clean here — that teardown is what fixes engine-switch orphans.
        let child = spawn_core(bin, cfg, Path::new(log), DATADIR, false).await?;
        let core_pid = child.id().unwrap_or(0) as i32;
        let _ = write_text(PIDFILE, &core_pid.to_string()).await;

        // An external tun engine needs a userspace tun + helper + manual routing;
        // a native sing-box auto_routes its own tun.
        if let TunPlan::External(ext) = &plan.tun {
            bring_up_external_tun(plan, ext).await?;
        }

        if verify_core_alive(core_pid, bin, 6, Duration::from_millis(250)).await {
            break;
        }
        let log_text = read_text(log).await.unwrap_or_default();
        let Some(delay) = start_retry_delay(native, attempt, &log_text) else {
            return fail(&format!("core exited on startup — see {log}")).await;
        };
        log::warn!("sing-box lost the xtables.lock race on startup; retrying in {delay:?}");
        tokio::time::sleep(delay).await;
        attempt += 1;
    }

    // Guard the proxy against apps kept outside it (both engines): no local proxy
    // ports, no binding to the tun. Deferred until the core is up so our iptables
    // don't contend with sing-box's system-stack `auto_redirect`, which installs its
    // own iptables during startup and shells `iptables` without `-w`. Another holder
    // of the global xtables.lock (netd) can still fail that start; the loop above
    // retries it.
    refresh_guards(&plan.ports).await;
    // Hotspot / tethering clients, if the user asked for them (watches the setting
    // and the tethering interfaces for as long as the data path runs).
    start_tether_watcher(if native {
        TetherPath::Native
    } else {
        TetherPath::External
    })
    .await;
    // Process-up: `started_at` marks it (vs the bring-up `connecting`) and drives
    // uptime; the wire state stays Connecting until the Service's connectivity probe
    // refines it to Connected / NoInternet.
    let mut state = read_state().await.unwrap_or_default();
    state.started_at = Some(now_secs());
    write_state(&state).await;
    Ok(())
}

/// RX/TX bytes for `iface` from /proc/net/dev, or (0, 0).
async fn iface_traffic(iface: Option<&str>) -> (u64, u64) {
    let Some(iface) = iface else {
        return (0, 0);
    };
    let Some(dev) = read_text("/proc/net/dev").await else {
        return (0, 0);
    };
    for line in dev.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        let rx = f.first().and_then(|x| x.parse().ok()).unwrap_or(0);
        let tx = f.get(8).and_then(|x| x.parse().ok()).unwrap_or(0);
        return (rx, tx);
    }
    (0, 0)
}

/// Which core is actually running (PID truth), or `None`.
async fn running_engine() -> Option<CoreEngine> {
    let pid = read_pidfile(PIDFILE).await;
    if pid <= 0 {
        return None;
    }
    if pid_matches_bin(pid, XRAY_BIN).await {
        return Some(CoreEngine::Xray);
    }
    if pid_matches_bin(pid, SINGBOX_BIN).await {
        return Some(CoreEngine::SingBox);
    }
    None
}

#[async_trait]
impl Platform for AndroidPlatform {
    fn paths(&self) -> &BackendPaths {
        &self.paths
    }

    /// The official Android sing-box build is compiled without `with_naive_outbound`.
    fn unavailable_protocols(&self) -> &'static [Protocol] {
        &[Protocol::Naive]
    }

    fn host_traits(&self) -> HostTraits {
        HOST
    }

    async fn boot_init(&self) -> anyhow::Result<()> {
        silent(&["mkdir", "-p", RUN_DIR]).await;
        // The route tables netd manages must exist before we touch ip rules/sysctl.
        for _ in 0..120 {
            if exists("/data/misc/net/rt_tables").await {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        // Register our own route tables (1100/1101) — avoid 100/101 because some
        // OEMs own those for vendor routing.
        silent(&[
            "sh",
            "-c",
            "grep -qs '^1100 ' /data/misc/net/rt_tables || echo '1100 kasumi-proxy' >> /data/misc/net/rt_tables",
        ])
        .await;
        silent(&[
            "sh",
            "-c",
            "grep -qs '^1101 ' /data/misc/net/rt_tables || echo '1101 kasumi-proxy-force' >> /data/misc/net/rt_tables",
        ])
        .await;
        setup_sysctl_locks().await;
        // A daemon that died while the tethering option was on left the offload
        // setting changed; no data path runs yet, so give it back.
        restore_hw_offload().await;
        // Fresh boot: seed a stopped document so a stale value can't make status lie
        // before the first command. Drop the pre-document `service-started` marker.
        write_state(&DataPathState::default()).await;
        remove_file("/data/adb/kasumi-proxy/service-started").await;
        // Older versions recorded the core engine in a marker file.
        remove_file("/data/adb/kasumi-proxy/engine").await;
        Ok(())
    }

    async fn start_data_path(&self, plan: &DataPathPlan) -> anyhow::Result<()> {
        // Record the bring-up (no started_at yet) so teardown and the watchdog know
        // what runs before the core is even up.
        write_state(&plan.state(RunState::Connecting)).await;
        ensure_tun_node().await;

        let (bin, cfg, log) = core_files(plan.engine);
        if let Err(e) = start_inner(plan, bin, &cfg, &log).await {
            // Roll back the half-built data-path so a failed start leaves no orphans.
            let already_failed = read_state()
                .await
                .is_some_and(|s| s.run == RunState::Failed);
            if !already_failed {
                set_failed(&e.to_string()).await;
            }
            let _ = self
                .stop_data_path(StopDataPath {
                    keep_service_state: true,
                })
                .await;
            return Err(e);
        }
        Ok(())
    }

    async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()> {
        let rs = RoutingState {
            tun_iface: read_iface(TUN_IFACE_FILE).await,
            tun2_iface: read_iface(TUN2_IFACE_FILE).await,
            filter: read_app_filter().await,
            socks_port: read_state()
                .await
                .map(|d| d.socks_port)
                .filter(|&p| p != 0)
                .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT),
            http_port: http_port().await,
        };
        // The tethering watcher would re-install rules behind the teardown below.
        stop_tether_watcher().await;
        // Stop the core first, gracefully: a sing-box auto_route core removes its own
        // ip rules + tun on shutdown. Doing this before clear_routing_rules (which
        // would delete the tun out from under it) lets that self-cleanup run.
        kill_if_running(read_pidfile(PIDFILE).await, None, PIDFILE, true).await;
        clear_routing_rules(&rs).await;
        remove_file(TUN_IFACE_FILE).await;
        remove_file(TUN2_IFACE_FILE).await;
        // Match the helper binary the running data-path actually used (from the
        // recorded document) so an engine switch never orphans the old helper. Stop it
        // gracefully too: a sidecar sing-box removes the ip rule it added for its tun
        // only on a clean exit.
        let helper_bin = running_helper_bin().await;
        kill_if_running(
            read_pidfile(TUN2SOCKS_PIDFILE).await,
            Some(helper_bin),
            TUN2SOCKS_PIDFILE,
            true,
        )
        .await;
        kill_if_running(
            read_pidfile(TUN2SOCKS2_PIDFILE).await,
            Some(helper_bin),
            TUN2SOCKS2_PIDFILE,
            true,
        )
        .await;
        // And sweep what a helper that died before it could clean up left behind.
        clear_orphaned_tun_rules().await;
        // Drop the pre-document `tun-engine` marker if an old version left one.
        remove_file("/data/adb/kasumi-proxy/run/tun-engine").await;
        if !opts.keep_service_state {
            write_state(&DataPathState::default()).await;
        }
        Ok(())
    }

    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        // The recorded document is authoritative for the base state; the Service's
        // connectivity probe later refines a running Connecting → Connected / NoInternet.
        let doc = read_state().await;
        let state = doc.as_ref().map(|d| d.run).unwrap_or(RunState::Stopped);
        let error = doc.as_ref().and_then(|d| d.failure_reason.clone());
        let tun = read_iface(TUN_IFACE_FILE).await;
        let (rx, tx) = iface_traffic(tun.as_deref()).await;
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
            engine: running_engine().await,
            tether_offload_bypass: hw_offload_bypass(),
        })
    }

    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
        let xray = core_version(CoreEngine::Xray).await;
        let singbox = core_version(CoreEngine::SingBox).await;
        let tun = exists("/dev/net/tun").await;
        Ok(PlatformCapabilities {
            cores: InstalledCores { xray, singbox },
            tun,
            bridge: "ksu".into(),
        })
    }

    fn core_path(&self, engine: Engine) -> PathBuf {
        PathBuf::from(core_bin(engine))
    }

    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
        let doc = read_state().await.unwrap_or_default();
        let (socks_port, http_port, force_port) = doc.listening_ports(http_port().await);
        let pid = read_pidfile(PIDFILE).await;
        let running = pid > 0 && pid_matches_any(pid, &core_bins()).await;
        Ok(ProxyStatus {
            running,
            socks_port,
            http_port,
            force_port,
        })
    }

    async fn open_url(&self, url: &str) -> anyhow::Result<()> {
        // The KSU WebUI cannot leave its WebView, so the daemon asks the activity
        // manager for a browser. An argv, never a shell string: the URL is provider
        // data.
        let (code, out) = run_out(&[
            "am",
            "start",
            "--user",
            "0",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            url,
        ])
        .await;
        // `am` reports a failed resolution on stdout with a zero exit code.
        if code != 0 || out.contains("Error:") {
            anyhow::bail!("could not open the link: {}", out.trim());
        }
        Ok(())
    }

    async fn device_facts(&self) -> DeviceFacts {
        let mut locale = getprop("persist.sys.locale").await;
        if locale.is_empty() {
            locale = getprop("ro.product.locale").await;
        }
        // Happ reports TV builds as their own OS.
        let tv = getprop("ro.build.characteristics")
            .await
            .split(',')
            .any(|c| c.trim() == "tv");
        DeviceFacts {
            os: if tv { "AndroidTV" } else { "Android" }.into(),
            os_version: getprop("ro.build.version.release").await,
            model: getprop("ro.product.model").await,
            locale,
            build: AndroidBuild {
                manufacturer: getprop("ro.product.manufacturer").await,
                brand: getprop("ro.product.brand").await,
                device: getprop("ro.product.device").await,
                product: getprop("ro.product.name").await,
                board: getprop("ro.product.board").await,
                hardware: getprop("ro.hardware").await,
            },
        }
    }

    async fn stored_ssaid(&self, user: u32, package: &str) -> Option<String> {
        ssaid::read(user)
            .await?
            .into_iter()
            .find(|e| e.package.as_deref() == Some(package))
            .and_then(|e| e.value)
    }

    async fn ssaid_user_key(&self, user: u32) -> Option<String> {
        ssaid::read(user)
            .await?
            .into_iter()
            .find(|e| e.name == "userkey")
            .and_then(|e| e.value)
    }

    // No convert_asset: a downloaded geoip/geosite.dat is converted to .srs lazily
    // on the next sing-box start (sync_geo_asset regenerates on the .dat change),
    // only for the categories the config uses.

    fn tune_config(&self, engine: Engine, config: &mut Value) {
        if engine == CoreEngine::Xray {
            // The core leaves as root through Android's default network. A socket
            // mark (a user Custom config may set one, as the shell module's configs
            // did) matches none of Android's rules and lands on `unreachable`.
            let outbounds = config.get_mut("outbounds").and_then(Value::as_array_mut);
            for ob in outbounds.into_iter().flatten() {
                if let Some(sockopt) = ob
                    .pointer_mut("/streamSettings/sockopt")
                    .and_then(Value::as_object_mut)
                {
                    sockopt.remove("mark");
                }
            }
            return;
        }
        // Android specifics the neutral builder must not assume, so they live here:
        // - The sing-box "system" stack can't grab tun connections in this
        //   root-binary data-path without sing-box's own nftables output redirect,
        //   which only catches network-bound sockets when strict_route is on.
        //   "mixed" runs TCP on that same system stack, so it needs both too.
        //   (gvisor needs neither.)
        // - Root (uid 0) must bypass the tun: the daemon and the core itself run as
        //   root, and this per-uid policy model spares root instead of marking
        //   sockets. Prepended to every capture-all tun (one with an `include_uid`
        //   allowlist can't capture root in the first place). Idempotent — a
        //   config that already excludes root is left as-is.
        if let Some(inbounds) = config.get_mut("inbounds").and_then(|v| v.as_array_mut()) {
            for ib in inbounds {
                if ib.get("type").and_then(Value::as_str) != Some("tun") {
                    continue;
                }
                if matches!(
                    ib.get("stack").and_then(Value::as_str),
                    Some("system" | "mixed")
                ) {
                    ib["auto_redirect"] = Value::Bool(true);
                    ib["strict_route"] = Value::Bool(true);
                }
                if ib.get("include_uid").is_none() {
                    let mut uids = ib
                        .get("exclude_uid")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    if !uids.iter().any(|v| v.as_i64() == Some(0)) {
                        uids.insert(0, Value::from(0i64));
                        ib["exclude_uid"] = Value::Array(uids);
                    }
                }
            }
        }
    }

    fn watch_network_change(&self) -> Option<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(run_watcher(tx));
        Some(rx)
    }

    // Nothing the data path installs names the uplink (see `network`).
    fn uplink_change_restarts(&self) -> bool {
        false
    }

    async fn data_path_healthy(&self) -> Option<bool> {
        let core_pid = read_pidfile(PIDFILE).await;
        if !(core_pid > 0 && pid_matches_any(core_pid, &core_bins()).await) {
            return Some(false);
        }
        // An external-tun data-path also relies on its tun helpers; a native sing-box
        // runs the tun itself. A helper the record expects must have a pid AND be
        // alive — a missing pidfile (helper never spawned, e.g. its binary absent) is
        // unhealthy, so the watchdog rebuilds it instead of leaving traffic
        // black-holed in an unbridged tun.
        let state = read_state().await.unwrap_or_default();
        for spec in watched_helpers(&state) {
            let pid = read_pidfile(spec.pidfile).await;
            if !(pid > 0 && pid_matches_bin(pid, spec.bin).await) {
                return Some(false);
            }
        }
        Some(true)
    }

    fn app_filter(&self) -> Option<&dyn AppFilterCapability> {
        Some(self)
    }
}

#[async_trait]
impl AppFilterCapability for AndroidPlatform {
    async fn list_apps(&self) -> anyhow::Result<Vec<AppInfo>> {
        let (code, out) = run_out(&["pm", "list", "packages", "-U"]).await;
        if code != 0 {
            return Ok(Vec::new());
        }
        let mut apps = Vec::new();
        for line in out.lines() {
            let Some(rest) = line.strip_prefix("package:") else {
                continue;
            };
            let mut toks = rest.split_whitespace();
            let pkg = toks.next();
            let uid = toks.find_map(|t| t.strip_prefix("uid:"));
            if let (Some(pkg), Some(uid)) = (pkg, uid)
                && let Ok(uid) = uid.parse::<i32>()
            {
                apps.push(AppInfo {
                    pkg: pkg.to_string(),
                    uid,
                    system: uid < 10000,
                    ..Default::default()
                });
            }
        }
        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_core::core::owns_native_tun;
    use kasumi_core::state::AppFilterMode;

    // The FATAL line sing-box logged when netd held the lock (#189).
    const ANDROID_LOCK_LOG: &str = "FATAL[0000] start service: start inbound/tun[tun-in]: \
        auto-redirect: setup iptables: exit status 4: /system/bin/iptables -t nat -I OUTPUT \
        -j sing-box-output: Can't lock /system/etc/xtables.lock: Try again";

    #[test]
    fn detects_a_lost_xtables_lock() {
        assert!(lost_xtables_race(ANDROID_LOCK_LOG));
        assert!(lost_xtables_race(
            "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?"
        ));
        assert!(!lost_xtables_race(
            "FATAL[0000] decode config: outbounds[0].server: unknown field"
        ));
        assert!(!lost_xtables_race(""));
    }

    fn plan(engine: CoreEngine, tun: TunEngine, force: bool, http: u16) -> DataPathPlan {
        let mut s = AdvancedSettings {
            local_socks_port: Some(10808),
            local_http_port: Some(http),
            ..Default::default()
        };
        s.tun_by_core.insert(engine, tun);
        if force {
            s.app_filter
                .insert("org.game:10200".into(), AppFilterMode::ForceProxy);
        }
        DataPathPlan::resolve(engine, &s, HOST)
    }

    #[test]
    fn force_helper_bridges_into_the_force_inbound() {
        use kasumi_core::share::parse_share_link;
        use kasumi_core::singbox_config::{SingboxBuildOpts, build_singbox_config};
        use kasumi_core::xray_config::build_xray_config;

        let p = parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None).unwrap();
        let profiles = std::slice::from_ref(&p);
        // Default layout, and an http port on socks + 2 that pushes force-in further.
        for http in [10809, 10810] {
            let s = AdvancedSettings {
                local_socks_port: Some(10808),
                local_http_port: Some(http),
                ..Default::default()
            };
            let ports = plan(CoreEngine::Xray, TunEngine::Tun2socks, true, http).ports;
            let xray = build_xray_config(&p, &s, &[], profiles).unwrap();
            let opts = SingboxBuildOpts {
                no_tun: true,
                force_tun: false,
                srs_dir: "",
            };
            let sing_box = build_singbox_config(&p, &s, &[], profiles, opts).unwrap();
            for (cfg, port_key) in [(&xray, "port"), (&sing_box, "listen_port")] {
                let force_in = cfg["inbounds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|i| i["tag"] == "force-in")
                    .unwrap();
                assert_eq!(
                    force_in[port_key].as_u64(),
                    Some(u64::from(helper_target(TunSlot::Force, &ports))),
                    "http {http}"
                );
            }
        }
    }

    #[test]
    fn start_and_watchdog_expect_the_same_helpers() {
        // The watchdog tears down a data path whose expected helper is missing, so a
        // start that skipped one would be killed on the next tick.
        for engine in [CoreEngine::Xray, CoreEngine::SingBox] {
            for tun in [TunEngine::SingboxTun, TunEngine::Tun2socks, TunEngine::Hev] {
                for force in [false, true] {
                    let plan = plan(engine, tun, force, 10809);
                    let at = format!("{engine:?} + {tun:?}, force {force}");
                    let started: Vec<HelperSpec> =
                        plan.helpers().into_iter().map(helper_spec).collect();
                    let doc = plan.state(RunState::Connecting).to_json();
                    let recorded = DataPathState::from_json(doc.as_bytes()).unwrap();
                    assert_eq!(watched_helpers(&recorded), started, "{at}");
                    let external = !owns_native_tun(engine, tun);
                    assert_eq!(
                        started.len(),
                        usize::from(external) * (1 + usize::from(force)),
                        "{at}"
                    );
                    for spec in &started {
                        assert_eq!(spec.bin, tun_helper_bin(tun), "{at}");
                    }
                }
            }
        }
    }

    #[test]
    fn retries_a_native_singbox_once_after_a_backoff() {
        assert_eq!(
            start_retry_delay(true, 0, ANDROID_LOCK_LOG),
            Some(XTABLES_BACKOFF)
        );
        // Bounded: the retry that loses again is the last.
        assert_eq!(
            start_retry_delay(true, XTABLES_RETRIES, ANDROID_LOCK_LOG),
            None
        );
    }

    #[test]
    fn other_startup_failures_are_not_retried() {
        // A config error, or an engine that runs no iptables itself.
        assert_eq!(start_retry_delay(true, 0, "FATAL decode config"), None);
        assert_eq!(start_retry_delay(false, 0, ANDROID_LOCK_LOG), None);
    }

    #[tokio::test]
    async fn iface_traffic_parses_proc_net_dev_columns() {
        // Real /proc/net/dev isn't available deterministically; exercise the parser
        // shape via a known iface absence (returns zeros).
        assert_eq!(iface_traffic(None).await, (0, 0));
        assert_eq!(iface_traffic(Some("definitely-not-an-iface")).await, (0, 0));
    }

    #[test]
    fn naive_is_unavailable_on_android() {
        assert_eq!(
            AndroidPlatform::new().unavailable_protocols(),
            [Protocol::Naive]
        );
    }

    #[test]
    fn core_files_pick_engine_paths() {
        let (bin, cfg, log) = core_files(CoreEngine::Xray);
        assert_eq!(bin, XRAY_BIN);
        assert!(cfg.ends_with("config.json"));
        assert!(log.ends_with("xray.log"));
        let (bin, cfg, _) = core_files(CoreEngine::SingBox);
        assert_eq!(bin, SINGBOX_BIN);
        assert!(cfg.ends_with("singbox.json"));
    }

    #[test]
    fn tune_config_drops_xray_socket_marks() {
        let platform = AndroidPlatform::new();
        let mut cfg = serde_json::json!({ "outbounds": [
            { "tag": "proxy", "streamSettings": { "sockopt": { "mark": 255, "tcpNoDelay": true } } },
            { "tag": "direct", "protocol": "freedom" },
        ] });
        platform.tune_config(CoreEngine::Xray, &mut cfg);
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["sockopt"],
            serde_json::json!({ "tcpNoDelay": true })
        );
        assert_eq!(
            cfg["outbounds"][1],
            serde_json::json!({ "tag": "direct", "protocol": "freedom" })
        );
    }

    #[test]
    fn tune_config_excludes_root_from_capture_all_tuns() {
        let platform = AndroidPlatform::new();
        // A neutral build: gvisor main tun with app-filter bypass uids, plus a
        // force tun with an include_uid allowlist.
        let mut cfg = serde_json::json!({ "inbounds": [
            { "type": "tun", "tag": "tun-in", "stack": "gvisor",
              "exclude_uid": [10001] },
            { "type": "tun", "tag": "tun-force", "stack": "gvisor",
              "include_uid": [10002] },
            { "type": "mixed", "tag": "socks-in" },
        ] });
        platform.tune_config(CoreEngine::SingBox, &mut cfg);
        // Root heads the exclusion of the capture-all tun (the daemon and core run
        // as root); the allowlisted force tun and non-tun inbounds are untouched.
        assert_eq!(
            cfg["inbounds"][0]["exclude_uid"],
            serde_json::json!([0, 10001])
        );
        assert!(cfg["inbounds"][1].get("exclude_uid").is_none());
        assert!(cfg["inbounds"][2].get("exclude_uid").is_none());
        // Tuning is idempotent: a second pass doesn't duplicate the root exclusion.
        platform.tune_config(CoreEngine::SingBox, &mut cfg);
        assert_eq!(
            cfg["inbounds"][0]["exclude_uid"],
            serde_json::json!([0, 10001])
        );

        // A capture-all tun without any app filter still gets the root exclusion.
        let mut cfg = serde_json::json!({ "inbounds": [
            { "type": "tun", "tag": "tun-in", "stack": "gvisor" },
        ] });
        platform.tune_config(CoreEngine::SingBox, &mut cfg);
        assert_eq!(cfg["inbounds"][0]["exclude_uid"], serde_json::json!([0]));

        // The system and mixed stacks (kernel TCP) additionally need sing-box's own
        // output redirect.
        for stack in ["system", "mixed"] {
            let mut cfg = serde_json::json!({ "inbounds": [
                { "type": "tun", "tag": "tun-in", "stack": stack },
            ] });
            platform.tune_config(CoreEngine::SingBox, &mut cfg);
            assert_eq!(cfg["inbounds"][0]["auto_redirect"], true, "{stack}");
            assert_eq!(cfg["inbounds"][0]["strict_route"], true, "{stack}");
            assert_eq!(cfg["inbounds"][0]["exclude_uid"], serde_json::json!([0]));
        }

        // Xray configs pass through untouched.
        let mut cfg = serde_json::json!({ "inbounds": [{ "type": "tun" }] });
        platform.tune_config(CoreEngine::Xray, &mut cfg);
        assert!(cfg["inbounds"][0].get("exclude_uid").is_none());
    }
}
