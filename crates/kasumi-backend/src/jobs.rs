//! On-demand diagnostics (tcp-ping / real-ping / speed-test). Each builds a
//! SOCKS-only test config via the core builders, spawns a throwaway core on a free
//! port, probes through it with a SOCKS5 fetch, then tears it down. Proxying the
//! probe through fetch means no `curl` and no Start/Status polling: one async call
//! returns the result.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use kasumi_core::contract::{FetchMode, TEST_PORT_BASE, TEST_PORT_SPAN, TestKind};
use kasumi_core::core::resolve_core;
use kasumi_core::enums::CoreEngine;
use kasumi_core::profile::Profile;
use kasumi_core::singbox_config::{SingboxBuildOpts, build_singbox_config};
use kasumi_core::state::{AppState, DEFAULT_DELAY_TEST_URL, DEFAULT_SPEED_TEST_URL};
use kasumi_core::xray_config::build_xray_config;

use crate::fs::{exists, read_text, remove_file};
use crate::fsjson::{read_json, write_text_atomic};
use crate::net::{FetchUrlOptions, ProxyStatus, fetch_url, lease_ports, tcp_ping};
use crate::platform::{Engine, Platform};

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
    let paths = platform.paths();
    let state: AppState = read_json(&paths.app_state).await?;
    let profiles: Vec<Profile> = read_json(&paths.profiles).await.unwrap_or_default();
    let profile = profiles.iter().find(|p| p.meta().id == profile_id)?.clone();
    Some(Loaded {
        profile,
        state,
        profiles,
    })
}

/// TCP-connect latency to the profile's server endpoint (no core needed). `None`
/// if the endpoint is unknown or unreachable.
pub async fn run_ping(platform: &dyn Platform, profile_id: &str) -> Option<i64> {
    let loaded = load_profile(platform, profile_id).await?;
    let addr = loaded.profile.address();
    let port = loaded.profile.port()?;
    if addr.is_empty() {
        return None;
    }
    // A plain TCP-connect from the daemon (unprivileged), so when a tun is up this
    // measures the path to the server *through* the active tunnel. That's a known
    // tcp-ping limitation while connected; real-ping/speed-test run their probe
    // through a helper-spawned core that binds the uplink and escapes the tun.
    tcp_ping(addr, port, Duration::from_secs(3))
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

/// Sanitise a profile id for use as a filename component. Ids are normally UUIDs,
/// but imported profiles can carry arbitrary strings, so keep only safe chars and
/// fold the rest to `_`.
fn safe_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn test_kind_slug(kind: TestKind) -> &'static str {
    match kind {
        TestKind::TcpPing => "tcpping",
        TestKind::RealPing => "realping",
        TestKind::Speed => "speed",
    }
}

/// Stable path of the retained test-core log for one (profile, kind). Overwritten
/// on each test of that kind: kept when the test failed (so the UI can show why),
/// removed when it passed — always in sync with the `err` the row shows.
fn retained_test_log_path(data_dir: &Path, profile_id: &str, kind: TestKind) -> PathBuf {
    data_dir.join(format!(
        "test-last-{}-{}.log",
        test_kind_slug(kind),
        safe_id(profile_id)
    ))
}

/// The retained test-core log for a profile's last failed real-ping/speed-test, or
/// empty if none (it passed, was never run, or the `err` came from a coreless
/// tcp-ping which has no log).
pub async fn read_test_log(platform: &dyn Platform, profile_id: &str, kind: TestKind) -> String {
    let path = retained_test_log_path(&platform.paths().data_dir, profile_id, kind);
    read_text(&path).await.unwrap_or_default()
}

/// Drop every retained test-core log for a profile — called when it's deleted so a
/// reused id can't surface a stale predecessor's log. (tcp-ping never writes one,
/// but sweep its slot too for completeness.)
pub async fn remove_test_logs(platform: &dyn Platform, profile_id: &str) {
    let data_dir = &platform.paths().data_dir;
    for kind in [TestKind::TcpPing, TestKind::RealPing, TestKind::Speed] {
        remove_file(retained_test_log_path(data_dir, profile_id, kind)).await;
    }
}

/// Last `n` non-blank lines of a test core's log — the actual core error (bad
/// config, bind failure, …) to surface when it won't start.
async fn log_tail(path: &std::path::Path, n: usize) -> String {
    let text = read_text(path).await.unwrap_or_default();
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
    cfg: &str,
    port: u16,
    measure: F,
    cap: Duration,
    retained: Option<&Path>,
) -> Result<Option<i64>, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Option<i64>>,
{
    let bin = platform.core_path(engine);
    if !exists(&bin).await {
        log::warn!("test core binary missing: {}", bin.display());
        return Err("test core binary missing".into());
    }
    let data_dir = platform.paths().data_dir.clone();
    let cfg_path = data_dir.join(format!("test-{port}.json"));
    let log_path = data_dir.join(format!("test-{port}.log"));
    if write_text_atomic(&cfg_path, cfg).await.is_err() {
        return Err("failed to write test config".into());
    }

    // On desktop the core runs behind the privileged helper (so it can bind the
    // uplink and escape an active tun); it reads this config and writes this log as
    // root. Both live in the shared data_dir, which the GUI owns, so it can still
    // clean them up afterwards.
    log::debug!("test core {engine:?} starting on port {port}");
    let mut core = match platform.spawn_test_core(engine, &cfg_path, &log_path).await {
        Ok(c) => c,
        Err(e) => {
            log::warn!("test core spawn failed on port {port}: {e}");
            remove_file(&cfg_path).await;
            remove_file(&log_path).await;
            return Err(format!("failed to start test core: {e}"));
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
            log::info!(
                "test core on port {port}: no probe result; core log: {}",
                log_tail(&log_path, 6).await
            );
        }
        Ok(measured)
    } else {
        // The core exited or never bound its SOCKS port — surface its own log so the
        // user sees the real reason (bad config, port in use, TLS error, …).
        let tail = log_tail(&log_path, 5).await;
        log::warn!("test core on port {port} did not start; core log: {tail}");
        Err(if tail.is_empty() {
            "test core did not start".into()
        } else {
            format!("test core did not start: {tail}")
        })
    };

    // Persist or clear the retained per-(profile,kind) log so the UI can open the
    // reason behind an `err`. Kept on failure, dropped on success — done before the
    // temp log is removed below.
    if let Some(dst) = retained {
        if matches!(result, Ok(Some(_))) {
            remove_file(dst).await;
        } else if let Some(text) = read_text(&log_path).await {
            let _ = write_text_atomic(dst, &text).await;
        }
    }

    core.kill().await;
    remove_file(&cfg_path).await;
    remove_file(&log_path).await;
    result
}

fn build_test_config(
    engine: Engine,
    loaded: &Loaded,
    port: u16,
    srs_dir: &str,
) -> Result<String, String> {
    let mut settings = loaded.state.settings.clone();
    settings.local_socks_port = Some(port);
    settings.local_http_port = Some(port + 1);
    let rules = &loaded.state.routing_rules;
    let value = match engine {
        CoreEngine::SingBox => build_singbox_config(
            &loaded.profile,
            &settings,
            rules,
            &loaded.profiles,
            SingboxBuildOpts {
                no_tun: true,
                srs_dir,
            },
        )?,
        CoreEngine::Xray => build_xray_config(&loaded.profile, &settings, rules, &loaded.profiles)?,
    };
    serde_json::to_string(&value).map_err(|e| e.to_string())
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
    let loaded = load_profile(platform, profile_id)
        .await
        .ok_or_else(|| "profile not found".to_string())?;
    let engine = resolve_core(&loaded.profile, &loaded.state.settings);
    // Hold a concurrency permit for the whole test (released on drop).
    let _permit = ping_limiter(loaded.state.settings.ping_concurrency as usize)
        .acquire_owned()
        .await
        .ok();
    let lease = lease_ports(TEST_PORT_BASE, TEST_PORT_SPAN).await;
    let test_port = lease.base();
    let srs_dir = platform.paths().srs_dir.to_string_lossy().into_owned();
    let retained =
        retained_test_log_path(&platform.paths().data_dir, profile_id, TestKind::RealPing);
    let cfg = build_test_config(engine, &loaded, test_port, &srs_dir)?;
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
        Some(&retained),
    )
    .await
    .inspect(|r| {
        log::info!(
            "real-ping {} port {test_port}: {r:?}",
            loaded.profile.meta().remarks
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
    let loaded = load_profile(platform, profile_id)
        .await
        .ok_or_else(|| "profile not found".to_string())?;
    let engine = resolve_core(&loaded.profile, &loaded.state.settings);
    let _permit = speed_limiter(loaded.state.settings.speed_concurrency as usize)
        .acquire_owned()
        .await
        .ok();
    let lease = lease_ports(TEST_PORT_BASE, TEST_PORT_SPAN).await;
    let test_port = lease.base();
    let srs_dir = platform.paths().srs_dir.to_string_lossy().into_owned();
    let retained = retained_test_log_path(&platform.paths().data_dir, profile_id, TestKind::Speed);
    let cfg = build_test_config(engine, &loaded, test_port, &srs_dir)?;
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
        Some(&retained),
    )
    .await
    .inspect(|r| {
        log::info!(
            "speed-test {} port {test_port}: {r:?}",
            loaded.profile.meta().remarks
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsjson::write_json_atomic;
    use crate::testutil::{TestPlatform, vless_at};
    use kasumi_core::state::default_app_state;

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
        // Unknown profile is also an error.
        assert!(run_real_ping(&p, "nope").await.is_err());
    }

    #[test]
    fn safe_id_folds_unsafe_chars() {
        assert_eq!(safe_id("ab-12_3.x"), "ab-12_3.x");
        assert_eq!(safe_id("a/b c:d"), "a_b_c_d");
    }

    #[tokio::test]
    async fn read_test_log_roundtrips_and_is_per_kind() {
        let (p, _d) = TestPlatform::new();
        // Absent → empty.
        assert_eq!(read_test_log(&p, "p1", TestKind::RealPing).await, "");
        // A retained real-ping log reads back; the speed slot stays independent.
        let path = retained_test_log_path(&p.paths().data_dir, "p1", TestKind::RealPing);
        write_text_atomic(&path, "boom: bad config\n")
            .await
            .unwrap();
        assert_eq!(
            read_test_log(&p, "p1", TestKind::RealPing).await,
            "boom: bad config\n"
        );
        assert_eq!(read_test_log(&p, "p1", TestKind::Speed).await, "");
    }
}
