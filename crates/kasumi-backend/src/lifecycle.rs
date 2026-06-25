//! Platform-neutral data-path lifecycle: build and write the active config, spawn
//! the core and tun2socks, keep sing-box's geo `.srs` rule-sets in step with their
//! `.dat` sources, inject random tun interface names, and verify the core stayed
//! up. A `Platform`'s `start_data_path` orchestrates these and wraps its own
//! OS-specific routing/tun/sysctl around them.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use regex::Regex;
use tokio::process::Child;

use kasumi_core::enums::CoreEngine;
use kasumi_core::state::{AppState, DEFAULT_LOCAL_SOCKS_PORT};

use crate::commands::{build_profile_config, CommandError};
use crate::fs::{exists, read_text, remove_file, write_text};
use crate::fsjson::{read_json, write_text_atomic};
use crate::platform::{Engine, Platform};
use crate::proc::{pid_matches_bin, run, spawn_logged, RunOpts};
// `spawn_logged_pre_exec` (and the `spawn_core_pre_exec` built on it) are unix-only:
// the pre_exec/fork seam has no Windows counterpart.
#[cfg(unix)]
use crate::proc::spawn_logged_pre_exec;

/// Map a hex digit to a consonant so the interface name starts with a letter
/// (kernel rejects names beginning with a digit).
fn lead_letter(c: char) -> char {
    match c {
        '0' => 'q',
        '1' => 'w',
        '2' => 'e',
        '3' => 'r',
        '4' => 't',
        '5' => 'y',
        '6' => 'u',
        '7' => 'i',
        '8' => 'o',
        '9' => 'p',
        'a' => 's',
        'b' => 'd',
        'c' => 'f',
        'd' => 'g',
        'e' => 'h',
        _ => 'j',
    }
}

/// A random tun interface name: a leading letter + 8 hex chars.
pub fn random_tun_iface() -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    let lead = lead_letter(hex.chars().next().unwrap_or('f'));
    format!("{lead}{}", &hex[1..9])
}

/// Build the config for `profile_id` (else the active profile), write it and the
/// engine marker, and return the engine + local SOCKS port to bind.
pub async fn resolve_and_write_config(
    platform: &dyn Platform,
    profile_id: Option<&str>,
) -> Result<(Engine, u16), CommandError> {
    let paths = platform.paths();
    let state = read_json::<AppState>(&paths.app_state).await;
    let id = profile_id
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| state.as_ref().and_then(|s| s.active_id.clone()))
        .unwrap_or_default();
    let built = build_profile_config(platform, &id).await?;
    let engine = built.engine;
    let cfg_path = match engine {
        CoreEngine::SingBox => &paths.singbox_config,
        CoreEngine::Xray => &paths.xray_config,
    };
    let cfg_text =
        serde_json::to_string_pretty(&built.config).map_err(|e| CommandError(e.to_string()))?;
    write_text_atomic(cfg_path, &cfg_text)
        .await
        .map_err(|e| CommandError(e.to_string()))?;
    write_text(&paths.engine_file, engine_label(engine))
        .await
        .map_err(|e| CommandError(e.to_string()))?;
    let socks_port = state
        .and_then(|s| s.settings.local_socks_port)
        .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
    Ok((engine, socks_port))
}

fn engine_label(engine: CoreEngine) -> &'static str {
    match engine {
        CoreEngine::Xray => "xray",
        CoreEngine::SingBox => "sing-box",
    }
}

// ---------- geo assets (geodat2srs) ----------

/// Matches a `"path": "…/foo.srs"` value in a config.
fn srs_path_re() -> Regex {
    Regex::new(r#""path":\s*"([^"]*\.srs)""#).unwrap()
}

/// The `.srs` basenames a sing-box config references (e.g. `geosite-ru.srs`).
pub fn referenced_srs(cfg_text: &str) -> HashSet<String> {
    let re = srs_path_re();
    re.captures_iter(cfg_text)
        .filter_map(|c| c.get(1))
        .filter_map(|m| m.as_str().rsplit('/').next())
        .map(str::to_owned)
        .collect()
}

async fn list_srs(dir: &Path, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(prefix) && name.ends_with(".srs") {
                out.push(name);
            }
        }
    }
    out
}

/// `size-mtime` of `path`, or empty when it can't be stat'd.
async fn dat_fingerprint(path: &Path) -> String {
    let Ok(m) = tokio::fs::metadata(path).await else {
        return String::new();
    };
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}-{}", m.len(), mtime)
}

/// Keep one geo kind's `.srs` in lock-step with its `.dat`, keeping only the
/// categories the active config references (geodat2srs emits 2000+; sing-box uses
/// a handful). Regenerate when the `.dat` changed or a needed `.srs` is missing;
/// purge when the `.dat` is gone. No-op without the bin.
pub async fn sync_geo_asset(
    kind: &str,
    dat_dir: &Path,
    srs_dir: &Path,
    geodat2srs_bin: &Path,
    needed: &HashSet<String>,
) {
    let dat = dat_dir.join(format!("{kind}.dat"));
    let prefix = format!("{kind}-");
    let stamp = srs_dir.join(format!(".{kind}.srs.stamp"));
    remove_file(srs_dir.join(format!(".{kind}.converted"))).await;

    let present = list_srs(srs_dir, &prefix).await;
    let mut want_with: Vec<&String> = needed.iter().filter(|n| n.starts_with(&prefix)).collect();
    want_with.sort();

    if !exists(&dat).await {
        if !present.is_empty() || exists(&stamp).await {
            for f in &present {
                remove_file(srs_dir.join(f)).await;
            }
            remove_file(&stamp).await;
        }
        return;
    }
    if !exists(geodat2srs_bin).await {
        return;
    }

    // Skip regen only when nothing changed AND every needed .srs is already here.
    let present_set: HashSet<&String> = present.iter().collect();
    let have_all = want_with.iter().all(|n| present_set.contains(*n));
    let fp = dat_fingerprint(&dat).await;
    let joined = want_with
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let stamp_want = format!("{fp}|{joined}");
    let have = read_text(&stamp)
        .await
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    if !fp.is_empty() && stamp_want == have && have_all {
        return;
    }

    let tmp = srs_dir.join(format!(".{kind}.srs.tmp"));
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    if tokio::fs::create_dir_all(&tmp).await.is_err() {
        return;
    }
    let argv = vec![
        geodat2srs_bin.to_string_lossy().into_owned(),
        kind.to_owned(),
        "-i".into(),
        dat.to_string_lossy().into_owned(),
        "-o".into(),
        tmp.to_string_lossy().into_owned(),
        "--prefix".into(),
        prefix.clone(),
    ];
    let ok = run(&argv, RunOpts::default())
        .await
        .map(|r| r.code == 0)
        .unwrap_or(false);
    if ok {
        // Replace this prefix's set with exactly the needed files.
        for f in &present {
            remove_file(srs_dir.join(f)).await;
        }
        if let Ok(mut rd) = tokio::fs::read_dir(&tmp).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".srs") && needed.contains(&name) {
                    let _ = tokio::fs::rename(tmp.join(&name), srs_dir.join(&name)).await;
                }
            }
        }
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        let _ = write_text(&stamp, &stamp_want).await;
    } else {
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        remove_file(&stamp).await;
    }
}

/// Local rule_set `.srs` files a sing-box config references but that are missing.
pub async fn missing_rule_sets(cfg_text: &str) -> Vec<String> {
    if !cfg_text.contains("\"rule_set\"") {
        return Vec::new();
    }
    let re = srs_path_re();
    let mut missing = Vec::new();
    for cap in re.captures_iter(cfg_text) {
        if let Some(p) = cap.get(1) {
            let path = p.as_str();
            if !exists(path).await {
                missing.push(path.to_owned());
            }
        }
    }
    missing
}

// ---------- sing-box tun iface injection ----------

/// Inject random `interface_name`s into the sing-box tun inbounds (stripping any a
/// prior start added, so re-runs don't stack duplicates) and persist them. The
/// second name is `None` when there is no force-proxy inbound.
pub async fn inject_singbox_ifaces(
    cfg_path: &Path,
    tun_iface_file: &Path,
    tun2_iface_file: &Path,
) -> std::io::Result<(String, Option<String>)> {
    let raw = read_text(cfg_path).await.unwrap_or_default();
    let strip = Regex::new(r#", "interface_name": "[^"]*""#).unwrap();
    let mut text = strip.replace_all(&raw, "").into_owned();

    let tun = read_text(tun_iface_file)
        .await
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(random_tun_iface);
    write_text(tun_iface_file, &tun).await?;
    text = text.replacen(
        r#""tag": "tun-in""#,
        &format!(r#""tag": "tun-in", "interface_name": "{tun}""#),
        1,
    );

    let tun2 = if text.contains(r#""tag": "tun-force""#) {
        let t2 = read_text(tun2_iface_file)
            .await
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(random_tun_iface);
        write_text(tun2_iface_file, &t2).await?;
        text = text.replacen(
            r#""tag": "tun-force""#,
            &format!(r#""tag": "tun-force", "interface_name": "{t2}""#),
            1,
        );
        Some(t2)
    } else {
        remove_file(tun2_iface_file).await;
        None
    };
    write_text(cfg_path, &text).await?;
    Ok((tun, tun2))
}

// ---------- core + tun2socks spawn ----------

/// Spawn the selected core (`<bin> run -c <cfg>`), logging to `log_path`. The
/// caller persists the returned pid to its pidfile.
pub async fn spawn_core(
    bin: &str,
    cfg: &str,
    log_path: &Path,
    dat_dir: &str,
    kill_on_drop: bool,
) -> std::io::Result<Child> {
    let env =
        std::collections::HashMap::from([("XRAY_LOCATION_ASSET".to_owned(), dat_dir.to_owned())]);
    spawn_logged(
        &[bin.to_owned(), "run".into(), "-c".into(), cfg.to_owned()],
        &env,
        log_path,
        kill_on_drop,
    )
    .await
}

/// Like [`spawn_core`], but runs `pre_exec` in the forked child before `exec`. Unix
/// only — see [`spawn_logged_pre_exec`]. The desktop least-privilege helper uses it
/// to grant a test core an ambient `CAP_NET_RAW`.
///
/// # Safety
///
/// `pre_exec` must be async-signal-safe (see [`spawn_logged_pre_exec`]).
#[cfg(unix)]
pub async unsafe fn spawn_core_pre_exec<F>(
    bin: &str,
    cfg: &str,
    log_path: &Path,
    dat_dir: &str,
    kill_on_drop: bool,
    pre_exec: F,
) -> std::io::Result<Child>
where
    F: FnMut() -> std::io::Result<()> + Send + Sync + 'static,
{
    let env =
        std::collections::HashMap::from([("XRAY_LOCATION_ASSET".to_owned(), dat_dir.to_owned())]);
    spawn_logged_pre_exec(
        &[bin.to_owned(), "run".into(), "-c".into(), cfg.to_owned()],
        &env,
        log_path,
        kill_on_drop,
        pre_exec,
    )
    .await
}

/// Spawn tun2socks bridging `iface` to the SOCKS port, logging to `log_path`.
/// `fwmark`, when set, marks tun2socks' own upstream socket so an `ip rule` can
/// keep it out of the tunnel — that's a Linux SO_MARK feature. Windows has no
/// fwmark (its server bypass is a host route), so it passes `None`.
pub async fn spawn_tun2socks(
    bin: &str,
    iface: &str,
    socks_port: u16,
    log_path: &Path,
    fwmark: Option<u32>,
) -> std::io::Result<Child> {
    let mut argv = vec![
        bin.to_owned(),
        "-device".into(),
        format!("tun://{iface}"),
        "-proxy".into(),
        format!("socks5://127.0.0.1:{socks_port}"),
    ];
    if let Some(mark) = fwmark {
        argv.push("-fwmark".into());
        argv.push(mark.to_string());
    }
    spawn_logged(&argv, &std::collections::HashMap::new(), log_path, false).await
}

/// Confirm the core stayed up: a bad config makes it exit within ~1s.
pub async fn verify_core_alive(pid: i32, bin: &str, attempts: u32, delay: Duration) -> bool {
    for _ in 0..attempts {
        if !pid_matches_bin(pid, bin).await {
            return false;
        }
        tokio::time::sleep(delay).await;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsjson::write_json_atomic;
    use crate::testutil::{sample_vless, TestPlatform};
    use kasumi_core::state::default_app_state;

    #[test]
    fn random_iface_is_letter_then_hex() {
        let name = random_tun_iface();
        assert_eq!(name.len(), 9);
        let mut chars = name.chars();
        assert!(chars.next().unwrap().is_ascii_alphabetic());
        assert!(chars.all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn referenced_srs_takes_basenames() {
        let cfg = r#"{"rule_set":[{"path":"/srs/geosite-ru.srs"},{"path":"geoip-ru.srs"}]}"#;
        let got = referenced_srs(cfg);
        assert!(got.contains("geosite-ru.srs"));
        assert!(got.contains("geoip-ru.srs"));
    }

    #[tokio::test]
    async fn missing_rule_sets_reports_absent_paths() {
        let dir = tempfile::tempdir().unwrap();
        let here = dir.path().join("present.srs");
        std::fs::write(&here, b"x").unwrap();
        let cfg = format!(
            r#"{{"rule_set":[{{"path":"{}"}},{{"path":"/no/where/gone.srs"}}]}}"#,
            here.display()
        );
        let missing = missing_rule_sets(&cfg).await;
        assert_eq!(missing, vec!["/no/where/gone.srs".to_string()]);
        // No rule_set key → nothing missing.
        assert!(missing_rule_sets("{}").await.is_empty());
    }

    #[tokio::test]
    async fn resolve_and_write_config_writes_engine_and_config() {
        let (p, _d) = TestPlatform::new();
        let prof = sample_vless();
        let id = prof.meta().id.clone();
        let mut state = default_app_state();
        state.active_id = Some(id.clone());
        state.settings.local_socks_port = Some(11080);
        write_json_atomic(&p.paths().app_state, &state)
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();

        // No explicit id → uses active_id.
        let (engine, socks) = resolve_and_write_config(&p, None).await.unwrap();
        assert_eq!(engine, CoreEngine::Xray);
        assert_eq!(socks, 11080);
        assert_eq!(
            read_text(&p.paths().engine_file).await.as_deref(),
            Some("xray")
        );
        let cfg = read_text(&p.paths().xray_config).await.unwrap();
        assert!(cfg.contains("outbounds"));
    }

    #[tokio::test]
    async fn inject_ifaces_adds_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sb.json");
        let f1 = dir.path().join("tun1");
        let f2 = dir.path().join("tun2");
        // The written config is pretty-printed, so tags carry a space after the colon.
        std::fs::write(
            &cfg,
            r#"{ "inbounds": [{ "type": "tun", "tag": "tun-in" }, { "type": "tun", "tag": "tun-force" }] }"#,
        )
        .unwrap();
        let (tun, tun2) = inject_singbox_ifaces(&cfg, &f1, &f2).await.unwrap();
        assert!(tun2.is_some());
        let text = read_text(&cfg).await.unwrap();
        assert!(text.contains(&format!(r#""interface_name": "{tun}""#)));
        assert!(text.contains(&format!(r#""interface_name": "{}""#, tun2.unwrap())));
        assert_eq!(read_text(&f1).await.as_deref(), Some(tun.as_str()));

        // Re-running reuses the persisted names and doesn't stack duplicates.
        let (tun_again, _) = inject_singbox_ifaces(&cfg, &f1, &f2).await.unwrap();
        assert_eq!(tun_again, tun);
        let text2 = read_text(&cfg).await.unwrap();
        assert_eq!(text2.matches(r#""interface_name""#).count(), 2);
    }

    #[tokio::test]
    async fn inject_ifaces_without_force_clears_tun2() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sb.json");
        let f1 = dir.path().join("tun1");
        let f2 = dir.path().join("tun2");
        // A stale tun2 name from a prior force-proxy run must be cleared when the
        // config no longer has a force-proxy inbound.
        std::fs::write(&f2, b"stale").unwrap();
        std::fs::write(
            &cfg,
            r#"{ "inbounds": [{ "type": "tun", "tag": "tun-in" }] }"#,
        )
        .unwrap();
        let (tun, tun2) = inject_singbox_ifaces(&cfg, &f1, &f2).await.unwrap();
        assert!(tun2.is_none());
        assert!(!exists(&f2).await);
        let text = read_text(&cfg).await.unwrap();
        assert_eq!(text.matches(r#""interface_name""#).count(), 1);
        assert!(text.contains(&format!(r#""interface_name": "{tun}""#)));
    }

    #[tokio::test]
    async fn verify_core_alive_against_self_and_wrong_bin() {
        let me = std::process::id() as i32;
        let exe = std::fs::read_link(format!("/proc/{me}/exe")).unwrap();
        let exe = exe.to_string_lossy().into_owned();
        assert!(verify_core_alive(me, &exe, 1, Duration::from_millis(1)).await);
        assert!(!verify_core_alive(me, "/bin/sh", 1, Duration::from_millis(1)).await);
    }
}
