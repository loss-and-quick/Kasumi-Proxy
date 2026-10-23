//! On-demand diagnostics (tcp-ping / real-ping / speed-test). Each builds a
//! SOCKS-only test config via the core builders, spawns a throwaway core on a free
//! port, probes through it with a SOCKS5 fetch, then tears it down. Proxying the
//! probe through fetch means no `curl` and no Start/Status polling: one async call
//! returns the result.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use kasumi_core::chain::chain_hops;
use kasumi_core::contract::{FetchMode, TEST_PORT_BASE, TEST_PORT_SPAN, TestKind};
use kasumi_core::core::resolve_core;
use kasumi_core::enums::CoreEngine;
use kasumi_core::profile::Profile;
use kasumi_core::singbox_config::{SingboxBuildOpts, build_singbox_config};
use kasumi_core::state::{AppState, DEFAULT_DELAY_TEST_URL, DEFAULT_SPEED_TEST_URL, RoutingMode};
use kasumi_core::xray_config::build_xray_probe_config;

use crate::net::{FetchUrlOptions, ProxyStatus, fetch_url, lease_ports, tcp_ping};
use crate::platform::{Engine, Platform};
use kasumi_log::{Area, ks_debug, ks_info, ks_warn};

struct Loaded {
    profile: Profile,
    state: AppState,
    profiles: Vec<Profile>,
}

/// The daemon — not the caller — owns how many probe cores run at once. A caller
/// just fires one `RealPing`/`SpeedTest` per profile (solo or batch) and can keep
/// adding more; these limiters serialise them so the cores never overrun the
/// device. The permit count tracks the user's setting: change it and the next
/// acquisition rebuilds the semaphore at the new size.
fn limiter(cell: &OnceLock<Mutex<(usize, Arc<Semaphore>)>>, limit: usize) -> Arc<Semaphore> {
    let limit = limit.max(1);
    let m = cell.get_or_init(|| Mutex::new((limit, Arc::new(Semaphore::new(limit)))));
    let mut g = m.lock().unwrap();
    if g.0 != limit {
        *g = (limit, Arc::new(Semaphore::new(limit)));
    }
    g.1.clone()
}

fn ping_limiter(limit: usize) -> Arc<Semaphore> {
    static C: OnceLock<Mutex<(usize, Arc<Semaphore>)>> = OnceLock::new();
    limiter(&C, limit)
}

fn speed_limiter(limit: usize) -> Arc<Semaphore> {
    static C: OnceLock<Mutex<(usize, Arc<Semaphore>)>> = OnceLock::new();
    limiter(&C, limit)
}

async fn load_profile(platform: &dyn Platform, profile_id: &str) -> Option<Loaded> {
    let state = crate::state::read_app_state(platform).await?;
    let profiles = state.profiles.clone();
    let profile = profiles.iter().find(|p| p.meta().id == profile_id)?.clone();
    Some(Loaded {
        profile,
        state,
        profiles,
    })
}

/// TCP-connect latency to the server the device dials for this profile (no core
/// needed): its own endpoint, or for a proxy chain the last hop, the only one
/// reached directly. `None` if that endpoint is unknown, unreachable, or the
/// chain is broken.
pub async fn run_ping(platform: &dyn Platform, profile_id: &str) -> Option<i64> {
    let loaded = load_profile(platform, profile_id).await?;
    let hops = chain_hops(&loaded.profile, &loaded.profiles).ok()?;
    let target = hops.last().copied().unwrap_or(&loaded.profile);
    let addr = target.address();
    let port = target.port()?;
    if addr.is_empty() {
        return None;
    }
    platform
        .tcp_ping(addr, port, Duration::from_secs(3))
        .await
        .map(|ms| ms as i64)
}

/// How long to wait for a freshly-spawned test core to start listening. Generous
/// because several cores can start at once (batch test): under CPU contention a
/// core that's perfectly healthy can take a few seconds to bind, and a too-tight
/// deadline would report it as failed even though the profile works (the exact
/// "single retest passes, batch fails" symptom).
const CORE_START_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait until a local port accepts connections, or give up after `timeout`. Poll
/// at a fixed interval — a not-yet-bound port refuses instantly, and a tight spin
/// would fire thousands of connects/s and storm the runtime under test concurrency.
async fn wait_port_up(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tcp_ping("127.0.0.1", port, Duration::from_millis(500))
            .await
            .is_some()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

pub use crate::platform::{safe_id, test_kind_slug};

/// The retained test-core log for a profile's last failed real-ping/speed-test, or
/// empty if none (it passed, was never run, or the `err` came from a coreless
/// tcp-ping which has no log).
pub async fn read_test_log(platform: &dyn Platform, profile_id: &str, kind: TestKind) -> String {
    platform.read_test_log(profile_id, kind).await
}

/// The lock that owns one retained-log slot. A test drops the previous log when it
/// starts and writes its own when it fails, so two overlapping attempts for the same
/// row would otherwise erase each other's reason; whoever holds this owns the slot from
/// the drop to the write. Entries are pruned once nobody holds or waits for them.
fn attempt_lock(retained: &Path) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks.retain(|_, slot| Arc::strong_count(slot) > 1);
    locks.entry(retained.to_path_buf()).or_default().clone()
}

/// Drop every retained test-core log for a profile — called when it's deleted so a
/// reused id can't surface a stale predecessor's log. (tcp-ping never writes one,
/// but sweep its slot too for completeness.)
pub async fn remove_test_logs(platform: &dyn Platform, profile_id: &str) {
    platform.remove_test_logs(profile_id).await;
}

/// Drop the retained test logs of every profile present in `prev` but gone from
/// `next`.
pub(crate) async fn remove_dropped_test_logs(
    platform: &dyn Platform,
    prev: &AppState,
    next: &AppState,
) {
    let kept: HashSet<&str> = next.profiles.iter().map(|p| p.meta().id.as_str()).collect();
    for p in &prev.profiles {
        if !kept.contains(p.meta().id.as_str()) {
            platform.remove_test_logs(&p.meta().id).await;
        }
    }
}

/// Delete every retained test log whose profile isn't in `state`. Providers
/// re-issue profile ids on each refresh, and logs written for ids dropped before
/// the cleanup existed (or by an unclean exit mid-test) would otherwise pile up.
pub async fn sweep_orphan_test_logs(platform: &dyn Platform, state: &AppState) {
    let live: HashSet<String> = state
        .profiles
        .iter()
        .map(|p| safe_id(&p.meta().id))
        .collect();
    platform.sweep_orphan_test_logs(&live).await;
}

/// Last `n` non-blank lines of a test core's log — the actual core error (bad
/// config, bind failure, …) to surface when it won't start.
async fn log_tail(platform: &dyn Platform, port: u16, n: usize) -> String {
    let text = platform.read_temp_test_log(port).await.unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].join(" | ")
}

/// Spawn a test core for `engine` on `cfg` (which binds SOCKS on `port`), wait for
/// it, run `measure` through `socks5://127.0.0.1:port`, then kill + clean up.
/// `Err` means the test core itself never came up (binary missing, config write
/// failed, spawn failed, or it never started listening) — a real failure the UI
/// should surface, distinct from `Ok(None)` which is "core ran but the probe got
/// no answer" (server unreachable). `measure` is bounded by `cap` so a hung probe
/// can't leak the core — killing it is what ultimately unblocks the probe.
async fn with_test_core<F, Fut>(
    platform: &dyn Platform,
    engine: Engine,
    cfg: &TestConfig,
    port: u16,
    measure: F,
    cap: Duration,
    retained: Option<(&str, TestKind)>,
) -> Result<Option<i64>, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Option<i64>>,
{
    if !platform.core_exists(engine).await {
        ks_warn!(
            Area::Jobs,
            "test core binary missing: {}",
            platform.core_path(engine).display()
        );
        return Err("test core binary missing".into());
    }
    let cfg_path = platform.paths().test_config(port);
    let log_path = platform.paths().test_log(port);
    if platform.write_test_config(port, &cfg.text).await.is_err() {
        return Err("failed to write test config".into());
    }

    // On desktop the core runs behind the privileged helper (so it can bind the
    // uplink and escape an active tun); it reads this config and writes this log as
    // root. Both live in the shared data_dir, which the GUI owns, so it can still
    // clean them up afterwards.
    ks_debug!(Area::Jobs, "test core {engine:?} starting on port {port}");
    let mut core = match platform.spawn_test_core(engine, &cfg_path, &log_path).await {
        Ok(c) => c,
        Err(e) => {
            ks_warn!(Area::Jobs, "test core spawn failed on port {port}: {e}");
            platform.cleanup_test_core(port).await;
            let reason = format!("failed to start test core: {e}");
            // Nothing ran, so there is no core log to keep — the reason itself is
            // what the row's log sheet has to show, behind what was being measured.
            if let Some((profile_id, kind)) = retained {
                let reason = format!("{}\n{reason}", cfg.measured);
                platform.note_test_failure(profile_id, kind, &reason).await;
            }
            return Err(reason);
        }
    };

    // Poll the SOCKS port for readiness. We no longer hold the core's `Child` to race
    // its exit (it may live behind the privileged helper), so a core that dies on a
    // bad config simply never binds the port and the wait times out — caught below.
    let listening = wait_port_up(port, CORE_START_TIMEOUT).await;
    let result = if listening {
        // The core's outbound already escapes the active tun (bound to the uplink at
        // build time), so just probe — bounded by `cap` so a hung request can't
        // wedge the test; killing the core is what unblocks it.
        let measured = tokio::time::timeout(cap, measure())
            .await
            .unwrap_or_default();
        // The core bound its SOCKS port but the probe got no answer: log the core's
        // own tail so a transport that connects-but-won't-pass-data (gRPC/XHTTP cold
        // start, TLS error, dead upstream) is diagnosable, not a silent None.
        if measured.is_none() {
            ks_info!(
                Area::Jobs,
                "test core on port {port}: no probe result; core log: {}",
                log_tail(platform, port, 6).await
            );
        }
        Ok(measured)
    } else {
        // The core exited or never bound its SOCKS port — surface its own log so the
        // user sees the real reason (bad config, port in use, TLS error, …).
        let tail = log_tail(platform, port, 5).await;
        ks_warn!(
            Area::Jobs,
            "test core on port {port} did not start; core log: {tail}"
        );
        Err(if tail.is_empty() {
            "test core did not start".into()
        } else {
            format!("test core did not start: {tail}")
        })
    };

    // Persist or clear the retained per-(profile,kind) log so the UI can open the
    // reason behind an `err`. Kept on failure, dropped on success — done before the
    // temp log is removed below.
    if let Some((profile_id, kind)) = retained {
        if matches!(result, Ok(Some(_))) {
            platform.remove_test_log(profile_id, kind).await;
        } else if let Some(text) = platform.read_temp_test_log(port).await {
            let body = match &result {
                Err(e) if text.trim().is_empty() => e.clone(),
                _ => text,
            };
            platform
                .write_test_log(profile_id, kind, &format!("{}\n{body}", cfg.measured))
                .await;
        }
    }

    core.kill().await;
    platform.cleanup_test_core(port).await;
    result
}

/// The config a test core runs, and the line naming what it measures.
#[derive(Debug)]
struct TestConfig {
    text: String,
    /// `measured path: …` — what `proxy` in the config stands for, so a `None` or a
    /// slow number on a provider row says which path it went through.
    measured: String,
}

/// The SOCKS-only config a test core runs, tuned for this platform like the main
/// core's (on Android, for one, a socket mark leaves the core unreachable).
fn build_test_config(
    platform: &dyn Platform,
    engine: Engine,
    loaded: &Loaded,
    port: u16,
    srs_dir: &str,
) -> Result<TestConfig, String> {
    let mut settings = loaded.state.settings.clone();
    settings.local_socks_port = Some(port);
    settings.local_http_port = Some(port + 1);
    // A probe answers "can this profile's default path carry traffic", where that
    // path is chosen by the profile itself and never by the user's routing or a
    // provider's conditional rules, so its core runs none of them: Global mode (with
    // the empty rule list below) leaves both builders nothing but "everything from the
    // local inbounds goes to `proxy`" — no rule blocks, no raw custom routing — while
    // keeping their own LAN bypass and the scope rules that only narrow a probe nobody
    // else matches. That also keeps the probe off the user's geo rule-sets: `rule_set`
    // entries are only ever emitted for route rules, and the `.srs` files behind them
    // exist only once a service start generated them, which is precisely what the device
    // that never started has not done. Without this, every test before the first start
    // dies on `parse rule-set[0]: open …/geosite-cn.srs: no such file or directory`.
    settings.routing_mode = RoutingMode::Global;
    let (mut value, measured) = match engine {
        CoreEngine::SingBox => {
            let value = build_singbox_config(
                &loaded.profile,
                &settings,
                &[],
                &loaded.profiles,
                SingboxBuildOpts {
                    no_tun: true,
                    force_tun: false,
                    srs_dir,
                },
            )?;
            (value, "outbound proxy".to_string())
        }
        CoreEngine::Xray => {
            let probe = build_xray_probe_config(&loaded.profile, &settings, &loaded.profiles)?;
            let measured = probe.target.describe();
            (probe.config, measured)
        }
    };
    platform.tune_config(engine, &mut value);
    let text = serde_json::to_string(&value).map_err(|e| e.to_string())?;
    // A config that still names geo data — xray's fake-DNS server pins
    // `geoip:!private` — would die the same silent way on a file that is not there.
    // Say what is absent while we can.
    let missing = crate::lifecycle::missing_geo_assets(platform, engine, &text);
    if !missing.is_empty() {
        return Err(format!(
            "the test core needs geo data that is not downloaded: {} (add it in Resource files)",
            missing.join(", ")
        ));
    }
    Ok(TestConfig {
        text,
        measured: format!("measured path: {measured}"),
    })
}

fn test_proxy(port: u16) -> ProxyStatus {
    ProxyStatus {
        running: true,
        socks_port: port,
        http_port: port + 1,
        force_port: kasumi_core::state::force_socks_port(port, port + 1),
    }
}

/// Real latency: time a `generate_204`-style fetch through the profile. `Err` if
/// the profile is unknown or its test core can't start; `Ok(None)` if the core ran
/// but the probe got no answer (server unreachable). The daemon leases its own
/// fresh port per test ([`lease_ports`]) and bounds concurrency itself
/// ([`ping_limiter`]), so the caller just names a profile.
pub async fn run_real_ping(
    platform: &dyn Platform,
    profile_id: &str,
) -> Result<Option<i64>, String> {
    let slot = attempt_lock(
        &platform
            .paths()
            .retained_test_log(profile_id, TestKind::RealPing),
    );
    let _slot = slot.lock().await;
    // A log left by an earlier failure describes that run, not this one: drop it up front
    // so whichever branch below fails writes the truth for this attempt —
    // [`Platform::note_test_failure`] then only fills in when the attempt produced no
    // core log of its own.
    platform
        .remove_test_log(profile_id, TestKind::RealPing)
        .await;
    let result = real_ping(platform, profile_id).await;
    if let Err(e) = &result {
        platform
            .note_test_failure(profile_id, TestKind::RealPing, e)
            .await;
    }
    result
}

async fn real_ping(platform: &dyn Platform, profile_id: &str) -> Result<Option<i64>, String> {
    let loaded = load_profile(platform, profile_id)
        .await
        .ok_or_else(|| "profile not found".to_string())?;
    let engine = resolve_core(&loaded.profile, &loaded.state.settings, &loaded.profiles)
        .map_err(|e| e.to_string())?;
    // Hold a concurrency permit for the whole test (released on drop).
    let _permit = ping_limiter(loaded.state.settings.ping_concurrency as usize)
        .acquire_owned()
        .await
        .ok();
    let lease = lease_ports(TEST_PORT_BASE, TEST_PORT_SPAN).await;
    let test_port = lease.base();
    let srs_dir = platform.paths().srs_dir.to_string_lossy().into_owned();
    let cfg = build_test_config(platform, engine, &loaded, test_port, &srs_dir)?;
    let url = loaded
        .state
        .settings
        .delay_test_url
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_DELAY_TEST_URL.to_owned());
    with_test_core(
        platform,
        engine,
        &cfg,
        test_port,
        || async move {
            let t0 = Instant::now();
            match fetch_url(
                &url,
                FetchUrlOptions {
                    mode: FetchMode::Proxy,
                    proxy: Some(test_proxy(test_port)),
                    // Generous: a freshly-spawned core's first request pays the full
                    // cold-start (asset load + the outbound handshake). gRPC/XHTTP in
                    // particular can take a few seconds to deliver the first byte, so a
                    // tight cap would false-None a perfectly working node.
                    timeout: Some(Duration::from_secs(8)),
                    ..Default::default()
                },
            )
            .await
            {
                Ok(_) => Some((t0.elapsed().as_millis() as i64).max(0)),
                Err(_) => None,
            }
        },
        Duration::from_secs(10),
        Some((profile_id, TestKind::RealPing)),
    )
    .await
    .inspect(|r| {
        ks_info!(
            Area::Jobs,
            "real-ping {} port {test_port}: {r:?} ({})",
            loaded.profile.meta().remarks,
            cfg.measured
        )
    })
}

/// Download throughput through the profile, in bytes/sec. `Err` if the profile is
/// unknown or its test core can't start; `Ok(None)` if the download produced no
/// bytes (server unreachable). The daemon owns the port and concurrency — see
/// [`run_real_ping`].
pub async fn run_speed_test(
    platform: &dyn Platform,
    profile_id: &str,
) -> Result<Option<i64>, String> {
    let slot = attempt_lock(
        &platform
            .paths()
            .retained_test_log(profile_id, TestKind::Speed),
    );
    let _slot = slot.lock().await;
    // See [`run_real_ping`]: a stale log from a previous failure must not outlive a
    // failure that raised before a core could write its own.
    platform.remove_test_log(profile_id, TestKind::Speed).await;
    let result = speed_test(platform, profile_id).await;
    if let Err(e) = &result {
        platform
            .note_test_failure(profile_id, TestKind::Speed, e)
            .await;
    }
    result
}

async fn speed_test(platform: &dyn Platform, profile_id: &str) -> Result<Option<i64>, String> {
    let loaded = load_profile(platform, profile_id)
        .await
        .ok_or_else(|| "profile not found".to_string())?;
    let engine = resolve_core(&loaded.profile, &loaded.state.settings, &loaded.profiles)
        .map_err(|e| e.to_string())?;
    let _permit = speed_limiter(loaded.state.settings.speed_concurrency as usize)
        .acquire_owned()
        .await
        .ok();
    let lease = lease_ports(TEST_PORT_BASE, TEST_PORT_SPAN).await;
    let test_port = lease.base();
    let srs_dir = platform.paths().srs_dir.to_string_lossy().into_owned();
    let cfg = build_test_config(platform, engine, &loaded, test_port, &srs_dir)?;
    let url = loaded
        .state
        .settings
        .speed_test_url
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_SPEED_TEST_URL.to_owned());
    with_test_core(
        platform,
        engine,
        &cfg,
        test_port,
        || async move {
            let t0 = Instant::now();
            match fetch_url(
                &url,
                FetchUrlOptions {
                    mode: FetchMode::Proxy,
                    proxy: Some(test_proxy(test_port)),
                    timeout: Some(Duration::from_secs(15)),
                    ..Default::default()
                },
            )
            .await
            {
                Ok(body) => {
                    let sec = t0.elapsed().as_secs_f64();
                    if body.is_empty() || sec <= 0.0 {
                        None
                    } else {
                        Some((body.len() as f64 / sec).round() as i64)
                    }
                }
                Err(_) => None,
            }
        },
        Duration::from_secs(18),
        Some((profile_id, TestKind::Speed)),
    )
    .await
    .inspect(|r| {
        ks_info!(
            Area::Jobs,
            "speed-test {} port {test_port}: {r:?} ({})",
            loaded.profile.meta().remarks,
            cfg.measured
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsjson::write_json_atomic;
    use crate::testutil::{TestPlatform, sample_vless, vless_at};
    use kasumi_core::route::{RouteBlockRef, RuleBlock};
    use kasumi_core::state::{RoutingMode, RoutingRule, default_app_state};

    #[tokio::test]
    async fn ping_none_when_profile_absent() {
        let (p, _d) = TestPlatform::new();
        assert_eq!(run_ping(&p, "missing").await, None);
    }

    #[tokio::test]
    async fn ping_reaches_live_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (p, _d) = TestPlatform::new();
        let prof = vless_at(port);
        let id = prof.meta().id.clone();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();
        assert!(run_ping(&p, &id).await.is_some_and(|ms| ms >= 0));
    }

    #[tokio::test]
    async fn ping_of_a_chain_measures_the_hop_dialed_directly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = listener.local_addr().unwrap().port();
        let at = |port: u16, id: &str, via: Option<&str>| {
            let mut p = vless_at(port);
            p.meta_mut().id = id.into();
            p.meta_mut().via = via.map(str::to_owned);
            p
        };
        // Only the entry hop listens; the exit and the middle hop refuse (port 1
        // on loopback), as servers reached only through the chain would.
        let profiles = vec![
            at(1, "exit", Some("mid")),
            at(1, "mid", Some("entry")),
            at(live, "entry", None),
            at(1, "broken", Some("broken")),
        ];
        let (p, _d) = TestPlatform::new();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &profiles)
            .await
            .unwrap();
        assert!(run_ping(&p, "exit").await.is_some());
        assert!(run_ping(&p, "mid").await.is_some());
        // A looped chain can't connect at all.
        assert_eq!(run_ping(&p, "broken").await, None);
    }

    #[tokio::test]
    async fn real_ping_and_speed_fail_without_core_binary() {
        let (p, _d) = TestPlatform::new();
        let prof = vless_at(443);
        let id = prof.meta().id.clone();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();
        // TestPlatform's core_path points at a nonexistent binary → core can't
        // start → a surfaced error, not a silent no-result.
        assert!(run_real_ping(&p, &id).await.is_err());
        assert!(run_speed_test(&p, &id).await.is_err());
        // Each test config got the platform's tuning, as the main core's does.
        assert_eq!(p.tuned(), [CoreEngine::Xray, CoreEngine::Xray]);
        // Unknown profile is also an error.
        assert!(run_real_ping(&p, "nope").await.is_err());
    }

    /// A state whose routing rules reference geosite/geoip, the way a fresh user
    /// sets it up in the rule editor before any service start.
    fn state_with_geo_rules() -> AppState {
        let mut state = default_app_state();
        state.settings.routing_mode = RoutingMode::Rules;
        state.rule_blocks = vec![RuleBlock {
            id: "b1".into(),
            name: "direct cn".into(),
            rules: vec![RoutingRule {
                id: "r1".into(),
                remarks: "cn sites".into(),
                enabled: true,
                outbound_tag: "direct".into(),
                domain: Some(vec!["geosite:cn".into()]),
                ip: Some(vec!["geoip:cn".into()]),
                port: None,
                network: None,
                protocol: None,
                process: None,
                package_name: None,
                source_ip: None,
            }],
            source_sub_id: None,
        }];
        state.routes[0].blocks = vec![RouteBlockRef {
            block_id: "b1".into(),
            enabled: true,
        }];
        state
    }

    fn loaded_with(profile: &Profile, state: AppState) -> Loaded {
        Loaded {
            profile: profile.clone(),
            state,
            profiles: vec![profile.clone()],
        }
    }

    /// A test core must never depend on the geo rule-sets only a service start
    /// generates: with a geo-heavy route configured and no `.dat` on disk at all,
    /// the probe config names no rule-set and still sends everything to the node.
    #[tokio::test]
    async fn test_config_ignores_route_rules_so_it_needs_no_rule_sets() {
        let (p, _d) = TestPlatform::new();
        let prof = sample_vless();
        let loaded = loaded_with(&prof, state_with_geo_rules());
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let cfg = build_test_config(&p, CoreEngine::SingBox, &loaded, TEST_PORT_BASE, &srs_dir)
            .expect("a probe needs no geo data");

        let value: serde_json::Value = serde_json::from_str(&cfg.text).unwrap();
        assert!(value.pointer("/route/rule_set").is_none(), "{}", cfg.text);
        assert_eq!(value["route"]["final"], "proxy");
        assert!(
            crate::lifecycle::referenced_srs(&cfg.text).is_empty(),
            "{}",
            cfg.text
        );
    }

    /// Whatever a probe config still names (xray's fake-DNS server pins
    /// `geoip:!private` regardless of rules) is reported up front instead of
    /// surfacing later as a core that "did not start".
    #[tokio::test]
    async fn test_config_reports_geo_data_it_still_needs() {
        let (p, _d) = TestPlatform::new();
        let prof = sample_vless();
        let mut state = default_app_state();
        state.settings.fake_dns = true;
        let loaded = loaded_with(&prof, state);
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let err =
            build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir).unwrap_err();
        assert!(err.contains("geoip.dat"), "{err}");

        tokio::fs::write(p.paths().dat_dir.join("geoip.dat"), b"geo")
            .await
            .unwrap();
        assert!(build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir).is_ok());
    }

    /// Custom mode's raw routing JSON is the user's own rules: a probe left them in and
    /// a `direct` rule could make it measure the LAN instead of the node.
    #[tokio::test]
    async fn test_config_ignores_custom_routing_too() {
        let (p, _d) = TestPlatform::new();
        let prof = sample_vless();
        let mut state = default_app_state();
        state.settings.routing_mode = RoutingMode::Custom;
        state.settings.custom_routing =
            Some(r#"[{"type":"field","domain":["geosite:cn"],"outboundTag":"direct"}]"#.into());
        let loaded = loaded_with(&prof, state);
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let cfg = build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir)
            .expect("custom routing needs no geo data in a probe");

        assert!(!cfg.text.contains("geosite"), "{}", cfg.text);
        // Everything the probe dials still leaves for the node.
        let value: serde_json::Value = serde_json::from_str(&cfg.text).unwrap();
        let rules = value["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap()["outboundTag"], "proxy");
    }

    fn custom_profile(origin: &str, raw: serde_json::Value) -> Profile {
        serde_json::from_value(serde_json::json!({
            "protocol": "custom",
            "meta": { "id": "c", "remarks": "C", "groupId": "g-main" },
            "raw": raw.to_string(),
            "origin": origin,
        }))
        .unwrap()
    }

    fn provider_server(tag: &str, host: &str) -> serde_json::Value {
        serde_json::json!({
            "tag": tag, "protocol": "vless",
            "settings": { "vnext": [{ "address": host, "port": 443,
                "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
            "streamSettings": { "network": "tcp", "security": "tls" },
        })
    }

    /// A provider config whose first outbound is a decoy nothing routes to: its
    /// routing sends every connection to a balancer. The rules it keeps also name
    /// geo data, which a probe must never need.
    fn provider_balancer_raw() -> serde_json::Value {
        serde_json::json!({
            "outbounds": [
                provider_server("proxy", "decoy.example"),
                provider_server("main", "main.example"),
                provider_server("main-2", "main2.example"),
                { "tag": "direct", "protocol": "freedom" },
            ],
            "routing": {
                "balancers": [{ "tag": "balancer-main", "selector": ["main"] }],
                "rules": [
                    { "type": "field", "domain": ["geosite:ru"], "outboundTag": "direct" },
                    { "type": "field", "inboundTag": ["in"], "network": "tcp,udp", "balancerTag": "balancer-main" },
                ],
            },
        })
    }

    /// A provider profile's rows measure the path its own routing takes, not its
    /// first outbound: a decoy there would report `None` forever.
    #[tokio::test]
    async fn test_config_of_a_provider_measures_its_routed_balancer() {
        let (p, _d) = TestPlatform::new();
        let prof = custom_profile("provider", provider_balancer_raw());
        let loaded = loaded_with(&prof, default_app_state());
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let cfg = build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir)
            .expect("a provider probe builds");
        assert_eq!(
            cfg.measured,
            "measured path: balancer balancer-main (main, main-2)"
        );
        let value: serde_json::Value = serde_json::from_str(&cfg.text).unwrap();
        // `proxy` is the alias into the balancer, and the decoy gave the tag up.
        assert_eq!(
            value["outbounds"][0],
            serde_json::json!({
                "tag": "proxy", "protocol": "loopback",
                "settings": { "inboundTag": "proxy-select" },
            })
        );
        assert!(cfg.text.contains("decoy.example"), "{}", cfg.text);
        let rules = value["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inboundTag"][0], "force-in");
        assert_eq!(rules[0]["outboundTag"], "proxy");
        assert!(
            !value["routing"].to_string().contains("proxy-provider"),
            "{}",
            value["routing"]
        );
    }

    /// A probe core must not need geo data a device has not downloaded, whatever
    /// rules a provider config carries: they never run in a probe.
    #[tokio::test]
    async fn test_config_of_a_provider_needs_no_geo_data() {
        let (p, _d) = TestPlatform::new();
        let prof = custom_profile("provider", provider_balancer_raw());
        let loaded = loaded_with(&prof, default_app_state());
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let cfg = build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir)
            .expect("a provider probe needs no geo data");
        assert!(!cfg.text.contains("geosite"), "{}", cfg.text);
    }

    /// A user's own config has no Kasumi inbounds to probe through, so a probe
    /// runs the sanitised view of it: its own listeners stay out, and the port it
    /// answers on is Kasumi's leased one.
    #[tokio::test]
    async fn test_config_of_a_user_custom_binds_the_leased_port() {
        let (p, _d) = TestPlatform::new();
        let raw = serde_json::json!({
            "inbounds": [{ "tag": "in", "protocol": "socks", "listen": "0.0.0.0", "port": 10808 }],
            "outbounds": [
                provider_server("proxy", "srv.example"),
                { "tag": "direct", "protocol": "freedom" },
            ],
        });
        let prof = custom_profile("user", raw);
        let loaded = loaded_with(&prof, default_app_state());
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let cfg = build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir)
            .expect("a user config is probed through its sanitised view");
        let value: serde_json::Value = serde_json::from_str(&cfg.text).unwrap();
        let inbound = |tag: &str| {
            value["inbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["tag"] == tag)
                .unwrap()
                .clone()
        };
        assert_eq!(inbound("socks-in")["port"], TEST_PORT_BASE);
        assert_eq!(inbound("http-in")["port"], TEST_PORT_BASE + 1);
        assert_eq!(
            inbound("force-in")["port"],
            kasumi_core::state::force_socks_port(TEST_PORT_BASE, TEST_PORT_BASE + 1)
        );
        assert!(!cfg.text.contains("10808"), "{}", cfg.text);
        assert_eq!(cfg.measured, "measured path: outbound proxy");
    }

    /// A config the sanitiser refuses cannot be probed, and says so instead of
    /// leaving the row on a silent `None`.
    #[tokio::test]
    async fn a_user_custom_that_cannot_be_sanitised_says_why() {
        let (p, _d) = TestPlatform::new();
        let prof = custom_profile(
            "user",
            serde_json::json!({ "outbounds": [{ "tag": "direct", "protocol": "freedom" }] }),
        );
        let loaded = loaded_with(&prof, default_app_state());
        let srs_dir = p.paths().srs_dir.to_string_lossy().into_owned();

        let err =
            build_test_config(&p, CoreEngine::Xray, &loaded, TEST_PORT_BASE, &srs_dir).unwrap_err();
        assert_eq!(err, "cannot be tested: no proxy outbound");
    }

    /// The row's `-1` opens the retained test log, so a failure raised before any
    /// core ran has to leave its reason there instead of an empty sheet.
    #[tokio::test]
    async fn a_test_that_fails_before_its_core_starts_records_why() {
        let (p, _d) = TestPlatform::new();
        let prof = vless_at(443);
        let id = prof.meta().id.clone();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();

        assert!(run_real_ping(&p, &id).await.is_err());
        let log = read_test_log(&p, &id, TestKind::RealPing).await;
        assert!(log.contains("test core binary missing"), "{log}");

        // A log from an earlier failure must not outlive this one's reason.
        p.write_test_log(&id, TestKind::RealPing, "boom: an older failure\n")
            .await;
        assert!(run_real_ping(&p, &id).await.is_err());
        let log = read_test_log(&p, &id, TestKind::RealPing).await;
        assert!(log.contains("test core binary missing"), "{log}");
        assert!(!log.contains("older failure"), "{log}");
    }

    /// One slot per row: overlapping attempts for the same profile and kind queue up
    /// instead of dropping the log the other one is about to write.
    #[tokio::test]
    async fn attempts_sharing_a_row_take_turns_in_its_log_slot() {
        let first = attempt_lock(Path::new("/data/test-last-realping-a.log"));
        let same = attempt_lock(Path::new("/data/test-last-realping-a.log"));
        let other = attempt_lock(Path::new("/data/test-last-speed-a.log"));
        assert!(Arc::ptr_eq(&first, &same));
        assert!(!Arc::ptr_eq(&first, &other));

        let held = first.lock().await;
        assert!(same.try_lock().is_err(), "the second attempt has to wait");
        drop(held);
        assert!(same.try_lock().is_ok());
        assert!(other.try_lock().is_ok(), "another row is a different slot");
    }

    #[test]
    fn safe_id_folds_unsafe_chars() {
        assert_eq!(safe_id("ab-12_3.x"), "ab-12_3.x");
        assert_eq!(safe_id("a/b c:d"), "a_b_c_d");
    }

    #[tokio::test]
    async fn orphan_sweep_removes_stale_logs_and_keeps_live_ones() {
        let (p, _d) = TestPlatform::new();
        let mut live = crate::testutil::sample_vless();
        live.meta_mut().id = "live/1".into();
        let mut state = kasumi_core::state::default_app_state();
        state.profiles = vec![live];
        let dir = p.paths().data_dir.clone();
        let kept = [
            "test-last-realping-live_1.log",
            "test-last-speed-live_1.log",
            "app.log",
            "test-last-notakind-gone.log",
        ];
        let gone = ["test-last-realping-gone.log", "test-last-speed-x-y.log"];
        for n in kept.iter().chain(&gone) {
            std::fs::write(dir.join(n), "x").unwrap();
        }
        sweep_orphan_test_logs(&p, &state).await;
        for n in kept {
            assert!(dir.join(n).exists(), "{n}");
        }
        for n in gone {
            assert!(!dir.join(n).exists(), "{n}");
        }
    }

    #[tokio::test]
    async fn read_test_log_roundtrips_and_is_per_kind() {
        let (p, _d) = TestPlatform::new();
        // Absent → empty.
        assert_eq!(read_test_log(&p, "p1", TestKind::RealPing).await, "");
        assert_eq!(p.read_test_log("p1", TestKind::RealPing).await, "");
        // A retained real-ping log reads back; the speed slot stays independent.
        p.write_test_log("p1", TestKind::RealPing, "boom: bad config\n")
            .await;
        assert_eq!(
            read_test_log(&p, "p1", TestKind::RealPing).await,
            "boom: bad config\n"
        );
        assert_eq!(
            p.read_test_log("p1", TestKind::RealPing).await,
            "boom: bad config\n"
        );
        assert_eq!(read_test_log(&p, "p1", TestKind::Speed).await, "");
    }

    #[tokio::test]
    async fn note_test_failure_fills_empty_log_but_preserves_content() {
        let (p, _d) = TestPlatform::new();
        p.write_test_log("silent", TestKind::RealPing, "  \n").await;
        p.note_test_failure("silent", TestKind::RealPing, "test core did not start")
            .await;
        assert_eq!(
            p.read_test_log("silent", TestKind::RealPing).await,
            "test core did not start\n"
        );

        p.write_test_log(
            "fatal",
            TestKind::RealPing,
            "FATAL create service: no such file\n",
        )
        .await;
        p.note_test_failure("fatal", TestKind::RealPing, "test core did not start")
            .await;
        assert_eq!(
            p.read_test_log("fatal", TestKind::RealPing).await,
            "FATAL create service: no such file\n"
        );
    }
}
