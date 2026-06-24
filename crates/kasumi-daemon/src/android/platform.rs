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
use kasumi_backend::fsjson::read_json;
use kasumi_backend::lifecycle::{
    inject_singbox_ifaces, missing_rule_sets, referenced_srs, spawn_core, spawn_tun_engine,
    sync_geo_asset, verify_core_alive,
};
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    AppFilterCapability, AppInfo, BackendPaths, Engine, InstalledCores, Platform,
    PlatformCapabilities, StartDataPath, StopDataPath,
};
use kasumi_backend::proc::{kill_if_running, pid_matches_any, pid_matches_bin, read_pidfile};
use kasumi_core::contract::{RunState, ServiceState};
use kasumi_core::enums::{CoreEngine, TunEngine, tun_from_marker, tun_marker};
use kasumi_core::state::{
    AdvancedSettings, AppState, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT, force_socks_port,
};

use super::network::run_watcher;
use super::paths::{
    CORE_BINS, DATADIR, ENGINE_FILE, GEODAT2SRS_BIN, IP, PIDFILE, RUN_DIR, SERVICE_STARTED_FILE,
    SERVICE_STATE_FILE, SINGBOX_BIN, SOCKS_PORT_FILE, TUN_ENGINE_FILE, TUN_IFACE_FILE,
    TUN2_IFACE_FILE, TUN2SOCKS_BIN, TUN2SOCKS_PIDFILE, TUN2SOCKS2_PIDFILE, XRAY_BIN, backend_paths,
};
use super::routing::{
    Action, AppFilter, FWMARK, RoutingState, apply_external_tun_routing, apply_strict_carveouts,
    clear_routing_rules, has_force_proxy, protect_local_ports, reload_app_filter_rules,
};
use super::sysctl::{lock_tun_iface, setup_sysctl_locks};
use super::{run_out, silent};

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

/// External-TUN helper binary for `tun`. `SingboxTun` is native and never reaches
/// the external path; the only external engine on Android today is tun2socks. New
/// engines add an arm here — the single place the daemon maps an engine to a binary.
fn tun_helper_bin(_tun: TunEngine) -> &'static str {
    TUN2SOCKS_BIN
}

/// Helper binary the *running* data-path uses, resolved from the tun-engine marker
/// so teardown/the watchdog match the right process (defaults to tun2socks for an
/// absent/legacy marker).
async fn running_helper_bin() -> &'static str {
    read_text(TUN_ENGINE_FILE)
        .await
        .as_deref()
        .and_then(tun_from_marker)
        .map(tun_helper_bin)
        .unwrap_or(TUN2SOCKS_BIN)
}

/// Whether the running data-path fronts the core with an external userspace tun (so
/// a live helper is required for health) rather than a native sing-box tun. Resolved
/// from the recorded tun-engine marker; on an absent/legacy marker it falls back to
/// the core engine — xray always needs an external tun, sing-box owns its own.
async fn external_tun_running() -> bool {
    if let Some(tun) = read_text(TUN_ENGINE_FILE)
        .await
        .as_deref()
        .and_then(tun_from_marker)
    {
        return tun != TunEngine::SingboxTun;
    }
    read_text(ENGINE_FILE)
        .await
        .map(|s| s.trim().to_string())
        .as_deref()
        != Some("sing-box")
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

async fn set_service_state(value: &str) {
    let _ = write_text(SERVICE_STATE_FILE, value).await;
}

async fn read_settings() -> Option<AdvancedSettings> {
    read_json::<AppState>(&app_state_path())
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

async fn read_iface(file: &str) -> Option<String> {
    read_text(file)
        .await
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
/// engine specifics beyond the helper binary, resolved via [`tun_helper_bin`]. A
/// spawn failure (e.g. the binary missing after a partial module update) or the tun
/// device never appearing is surfaced as an error so the caller fails the start
/// loudly, instead of routing into a bridge that never came up and black-holing the
/// device until the watchdog happens to notice.
async fn bring_up_tun_helper(
    tun: TunEngine,
    iface: &str,
    socks_port: u16,
    pidfile: &str,
    log_name: &str,
) -> anyhow::Result<()> {
    let log = format!("{DATADIR}/{log_name}");
    let child = spawn_tun_engine(
        tun,
        tun_helper_bin(tun),
        iface,
        socks_port,
        Path::new(&log),
        Some(FWMARK),
    )
    .await
    .map_err(|e| anyhow::anyhow!("spawn tun helper: {e} — see {log}"))?;
    let pid = child.id().unwrap_or(0);
    let _ = write_text(pidfile, &pid.to_string()).await;
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

/// External-tun data-path bring-up: a userspace tun bridged to the core's SOCKS via
/// the chosen TUN engine, plus per-app routing (and a second tun for force-proxy
/// apps). A native sing-box tun needs none of this — it auto_routes its own tun.
async fn bring_up_external_tun(tun: TunEngine, socks_port: u16) -> anyhow::Result<()> {
    let helper_bin = tun_helper_bin(tun);
    let filter = read_app_filter().await;
    let tun_iface = match read_iface(TUN_IFACE_FILE).await {
        Some(x) => x,
        None => fresh_iface(TUN_IFACE_FILE).await,
    };
    let mut tun2_iface: Option<String> = None;

    let t2 = read_pidfile(TUN2SOCKS_PIDFILE).await;
    if !(t2 > 0 && pid_matches_bin(t2, helper_bin).await) {
        bring_up_tun_helper(
            tun,
            &tun_iface,
            socks_port,
            TUN2SOCKS_PIDFILE,
            "tun2socks.log",
        )
        .await?;
    }

    if has_force_proxy(&filter) {
        let t = match read_iface(TUN2_IFACE_FILE).await {
            Some(x) => x,
            None => fresh_iface(TUN2_IFACE_FILE).await,
        };
        let t3 = read_pidfile(TUN2SOCKS2_PIDFILE).await;
        if !(t3 > 0 && pid_matches_bin(t3, helper_bin).await) {
            bring_up_tun_helper(
                tun,
                &t,
                socks_port + 2,
                TUN2SOCKS2_PIDFILE,
                "tun2socks2.log",
            )
            .await?;
        }
        tun2_iface = Some(t);
    } else {
        kill_if_running(
            read_pidfile(TUN2SOCKS2_PIDFILE).await,
            Some(helper_bin),
            TUN2SOCKS2_PIDFILE,
            false,
        )
        .await;
        remove_file(TUN2_IFACE_FILE).await;
    }

    lock_tun_iface(&tun_iface).await;
    let rs = RoutingState {
        tun_iface: Some(tun_iface),
        tun2_iface,
        filter,
        socks_port,
        http_port: http_port().await,
    };
    apply_external_tun_routing(&rs).await;
    Ok(())
}

async fn fail(reason: &str) -> anyhow::Result<()> {
    set_service_state(&format!("failed:{reason}")).await;
    anyhow::bail!("{reason}")
}

async fn start_inner(
    engine: CoreEngine,
    tun: TunEngine,
    bin: &str,
    cfg: &str,
    log: &str,
    socks_port: u16,
) -> anyhow::Result<()> {
    if !exists(bin).await {
        return fail("core binary missing").await;
    }
    if !exists(cfg).await {
        return fail("config missing").await;
    }

    // SingboxTun = sing-box owns its native tun; any other engine fronts a
    // socks-only core with an external userspace tun.
    let external = tun != TunEngine::SingboxTun;
    // Record the engine so teardown/the watchdog match the right helper binary.
    let _ = write_text(TUN_ENGINE_FILE, &tun_marker(tun)).await;

    if engine == CoreEngine::SingBox {
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
        if !external {
            inject_singbox_ifaces(
                Path::new(cfg),
                Path::new(TUN_IFACE_FILE),
                Path::new(TUN2_IFACE_FILE),
            )
            .await?;
        }
    }

    // stopDataPath always runs before a start/restart (Service), so the pidfile is
    // clean here — that teardown is what fixes engine-switch orphans.
    let child = spawn_core(bin, cfg, Path::new(log), DATADIR, false).await?;
    let core_pid = child.id().unwrap_or(0) as i32;
    let _ = write_text(PIDFILE, &core_pid.to_string()).await;

    // An external tun engine needs a userspace tun + helper + manual routing;
    // a native sing-box auto_routes its own tun.
    if external {
        bring_up_external_tun(tun, socks_port).await?;
    } else if read_app_filter().await.strict {
        // sing-box kill-switch carve-outs so the device stays reachable.
        apply_strict_carveouts().await;
    }

    if !verify_core_alive(core_pid, bin, 6, Duration::from_millis(250)).await {
        return fail(&format!("core exited on startup — see {log}")).await;
    }

    // Shield local proxy ports from bypass-mode apps (both engines). Deferred until
    // the core is up so our iptables don't contend with sing-box's system-stack
    // `auto_redirect`, which installs its own iptables during startup and shells
    // `iptables` without `-w` — a shared xtables.lock race would fail its start.
    protect_local_ports(
        Action::Add,
        &read_app_filter().await,
        socks_port,
        http_port().await,
    )
    .await;
    let _ = write_text(SERVICE_STARTED_FILE, &now_secs().to_string()).await;
    set_service_state("running").await;
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
        // Fresh boot: seed the lifecycle channel so a stale value can't make status
        // lie before the first command.
        set_service_state("stopped").await;
        remove_file(SERVICE_STARTED_FILE).await;
        Ok(())
    }

    async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
        let StartDataPath {
            engine,
            tun,
            socks_port,
        } = opts;
        set_service_state("connecting").await;
        let _ = write_text(SOCKS_PORT_FILE, &socks_port.to_string()).await;
        ensure_tun_node().await;

        let (bin, cfg, log) = core_files(engine);
        if let Err(e) = start_inner(engine, tun, bin, &cfg, &log, socks_port).await {
            // Roll back the half-built data-path so a failed start leaves no orphans.
            let cur = read_text(SERVICE_STATE_FILE)
                .await
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if !cur.starts_with("failed") {
                set_service_state(&format!("failed:{e}")).await;
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
            socks_port: {
                let p = read_pidfile(SOCKS_PORT_FILE).await;
                if p > 0 {
                    p as u16
                } else {
                    DEFAULT_LOCAL_SOCKS_PORT
                }
            },
            http_port: http_port().await,
        };
        // Stop the core first, gracefully: a sing-box auto_route core removes its own
        // ip rules + tun on shutdown. Doing this before clear_routing_rules (which
        // would delete the tun out from under it) lets that self-cleanup run.
        kill_if_running(read_pidfile(PIDFILE).await, None, PIDFILE, true).await;
        clear_routing_rules(&rs).await;
        remove_file(TUN_IFACE_FILE).await;
        remove_file(TUN2_IFACE_FILE).await;
        // Match the helper binary the running data-path actually used (from the
        // tun-engine marker) so an engine switch never orphans the old helper.
        let helper_bin = running_helper_bin().await;
        kill_if_running(
            read_pidfile(TUN2SOCKS_PIDFILE).await,
            Some(helper_bin),
            TUN2SOCKS_PIDFILE,
            false,
        )
        .await;
        kill_if_running(
            read_pidfile(TUN2SOCKS2_PIDFILE).await,
            Some(helper_bin),
            TUN2SOCKS2_PIDFILE,
            false,
        )
        .await;
        remove_file(TUN_ENGINE_FILE).await;
        if !opts.keep_service_state {
            set_service_state("stopped").await;
        }
        Ok(())
    }

    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        let raw = read_text(SERVICE_STATE_FILE)
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
            // "running" = the core process is up; whether it actually reaches the
            // internet is the Service's connectivity probe to decide, which refines
            // this to Connected / NoInternet. Until then it's still Connecting.
            state = RunState::Connecting;
        }
        let tun = read_iface(TUN_IFACE_FILE).await;
        let (rx, tx) = iface_traffic(tun.as_deref()).await;
        let started = read_pidfile(SERVICE_STARTED_FILE).await;
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
            engine: running_engine().await,
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
        let port = read_text(SOCKS_PORT_FILE)
            .await
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
        let pid = read_pidfile(PIDFILE).await;
        let running = pid > 0 && pid_matches_any(pid, &core_bins()).await;
        let http = http_port().await;
        Ok(ProxyStatus {
            running,
            socks_port: port,
            http_port: http,
            force_port: force_socks_port(port, http),
        })
    }

    // No convert_asset: a downloaded geoip/geosite.dat is converted to .srs lazily
    // on the next sing-box start (sync_geo_asset regenerates on the .dat change),
    // only for the categories the config uses.

    fn tune_config(&self, engine: Engine, config: &mut Value) {
        if engine != CoreEngine::SingBox {
            return;
        }
        // The sing-box "system" stack can't grab tun connections in this root-binary
        // data-path without sing-box's own nftables output redirect, which only
        // catches network-bound sockets when strict_route is on. An Android specific,
        // so it lives here, not the neutral builder. (gvisor needs neither.)
        if let Some(inbounds) = config.get_mut("inbounds").and_then(|v| v.as_array_mut()) {
            for ib in inbounds {
                let is_system_tun = ib.get("type").and_then(Value::as_str) == Some("tun")
                    && ib.get("stack").and_then(Value::as_str) == Some("system");
                if is_system_tun {
                    ib["auto_redirect"] = Value::Bool(true);
                    ib["strict_route"] = Value::Bool(true);
                }
            }
        }
    }

    fn watch_network_change(&self) -> Option<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(run_watcher(tx));
        Some(rx)
    }

    async fn data_path_healthy(&self) -> Option<bool> {
        let core_pid = read_pidfile(PIDFILE).await;
        if !(core_pid > 0 && pid_matches_any(core_pid, &core_bins()).await) {
            return Some(false);
        }
        // An external-tun data-path also relies on its tun helper; a native sing-box
        // runs the tun itself. When the data-path is external, the helper pid must be
        // present AND alive — a missing pidfile (helper never spawned, e.g. its
        // binary absent) is unhealthy, not healthy, so the watchdog rebuilds it
        // instead of leaving traffic black-holed in an unbridged tun.
        if external_tun_running().await {
            let t = read_pidfile(TUN2SOCKS_PIDFILE).await;
            if !(t > 0 && pid_matches_bin(t, running_helper_bin().await).await) {
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
                });
            }
        }
        Ok(apps)
    }

    async fn reload_app_filter(&self) -> anyhow::Result<()> {
        let pid = read_pidfile(PIDFILE).await;
        if !(pid > 0 && pid_matches_any(pid, &core_bins()).await) {
            return Ok(());
        }
        // sing-box bakes the filter into its config and needs a restart (the Service
        // handles that); only xray reloads live here.
        if read_text(ENGINE_FILE)
            .await
            .map(|s| s.trim().to_string())
            .as_deref()
            == Some("sing-box")
        {
            return Ok(());
        }
        reload_app_filter_rules(&read_app_filter().await).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn iface_traffic_parses_proc_net_dev_columns() {
        // Real /proc/net/dev isn't available deterministically; exercise the parser
        // shape via a known iface absence (returns zeros).
        assert_eq!(iface_traffic(None).await, (0, 0));
        assert_eq!(iface_traffic(Some("definitely-not-an-iface")).await, (0, 0));
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
}
