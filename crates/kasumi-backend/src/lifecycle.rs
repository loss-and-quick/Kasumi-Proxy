//! Platform-neutral data-path lifecycle: build and write the active config, spawn
//! the core and tun2socks, keep sing-box's geo `.srs` rule-sets in step with their
//! `.dat` sources, inject random tun interface names, and verify the core stayed
//! up. A `Platform`'s `start_data_path` orchestrates these and wraps its own
//! OS-specific routing/tun/sysctl around them.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use regex::Regex;
use tokio::process::Child;

use kasumi_core::core::default_tun_for;
use kasumi_core::enums::{CoreEngine, TunEngine, tun_from_marker};
use kasumi_core::hev_config::build_hev_config;
use kasumi_core::state::{AppState, DEFAULT_LOCAL_SOCKS_PORT};
use kasumi_core::tun::TunOptions;

use crate::commands::{CommandError, build_profile_config};
use crate::fs::{exists, read_text, remove_file, write_text};
use crate::fsjson::{read_json, write_text_atomic};
use crate::platform::{Engine, Platform};
use crate::proc::{RunOpts, pid_matches_bin, run, spawn_logged};

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
/// engine marker, and return the engine + resolved TUN engine + external-engine
/// tuning + local SOCKS port.
pub async fn resolve_and_write_config(
    platform: &dyn Platform,
    profile_id: Option<&str>,
) -> Result<(Engine, TunEngine, TunOptions, u16), CommandError> {
    let paths = platform.paths();
    let state = read_json::<AppState>(&paths.app_state).await;
    let id = profile_id
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| state.as_ref().and_then(|s| s.active_id.clone()))
        .unwrap_or_default();
    let built = build_profile_config(platform, &id).await?;
    let engine = built.engine;
    let tun = built.tun;
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
    let settings = state.map(|s| s.settings).unwrap_or_default();
    let socks_port = settings
        .local_socks_port
        .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
    let tun_opts = settings.tun_options();
    Ok((engine, tun, tun_opts, socks_port))
}

/// The core engine's on-disk label (written to `paths.engine_file` at config
/// resolution). Also the fallback input to [`running_external_engine`].
pub fn engine_label(engine: CoreEngine) -> &'static str {
    match engine {
        CoreEngine::Xray => "xray",
        CoreEngine::SingBox => "sing-box",
    }
}

/// The external TUN engine a *running* data-path uses — so a shell can map it to the
/// helper binary and decide whether a live helper is required — or `None` when the
/// core owns its TUN natively (sing-box). This is the one place that reads that
/// state, shared by the desktop helper and the Android daemon (which previously each
/// reimplemented it and drifted).
///
/// The recorded tun-engine `marker` (its content, or `None` if absent) is
/// authoritative. On an absent/legacy marker — e.g. a data-path started by a build
/// from before the marker existed — it falls back to the running core's
/// `engine_label`: a native sing-box owns its own TUN, while xray (or any other /
/// unknown label) fronts an external one, so the fallback resolves to the universal
/// default external engine. The caller supplies the label however it knows the
/// running core (desktop from the live pid, the daemon from its engine file).
pub fn running_external_engine(
    marker: Option<&str>,
    engine_label: Option<&str>,
) -> Option<TunEngine> {
    if let Some(tun) = marker.map(str::trim).and_then(tun_from_marker) {
        return (tun != TunEngine::SingboxTun).then_some(tun);
    }
    (engine_label.map(str::trim) != Some(self::engine_label(CoreEngine::SingBox)))
        .then(|| default_tun_for(CoreEngine::Xray))
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

/// The core's argv (`<bin> run -c <cfg>`) and the env it needs (xray reads its geo
/// `.dat` assets from `XRAY_LOCATION_ASSET`). Split out so a caller that supervises
/// the spawn itself (e.g. the desktop helper's `PR_SET_PDEATHSIG` path) can reuse the
/// exact same command without duplicating it.
pub fn core_argv(bin: &str, cfg: &str) -> Vec<String> {
    vec![bin.to_owned(), "run".into(), "-c".into(), cfg.to_owned()]
}

pub fn core_env(dat_dir: &str) -> HashMap<String, String> {
    HashMap::from([("XRAY_LOCATION_ASSET".to_owned(), dat_dir.to_owned())])
}

/// Spawn the selected core (`<bin> run -c <cfg>`), logging to `log_path`. The
/// caller persists the returned pid to its pidfile. On Unix the child is tied to
/// its parent via `PR_SET_PDEATHSIG` (see [`proc::spawn_logged`]); capability
/// grants across exec live process-wide in the helper's ambient set, so no
/// per-spawn `pre_exec` is needed here.
pub async fn spawn_core(
    bin: &str,
    cfg: &str,
    log_path: &Path,
    dat_dir: &str,
    kill_on_drop: bool,
) -> std::io::Result<Child> {
    spawn_logged(
        &core_argv(bin, cfg),
        &core_env(dat_dir),
        log_path,
        kill_on_drop,
    )
    .await
}

/// Spawn tun2socks bridging the tun to the local SOCKS port. `fwmark`, when set,
/// marks tun2socks' own upstream socket so an `ip rule` can keep it out of the
/// tunnel — a Linux SO_MARK feature. Windows has no fwmark (its server bypass is a
/// host route), so it passes `None`.
async fn spawn_tun2socks(s: &TunSpawn<'_>) -> std::io::Result<Child> {
    let mut argv = vec![
        s.bin.to_owned(),
        "-device".into(),
        format!("tun://{}", s.iface),
        "-proxy".into(),
        format!("socks5://127.0.0.1:{}", s.socks_port),
        // The TUN MTU setting applies to every external engine; tun2socks creates
        // its own tun, so it must be told the MTU here (hev takes it in its YAML).
        "-mtu".into(),
        s.opts.mtu.to_string(),
    ];
    if let Some(mark) = s.fwmark {
        argv.push("-fwmark".into());
        argv.push(mark.to_string());
    }
    spawn_logged(&argv, &std::collections::HashMap::new(), s.log_path, false).await
}

/// Everything needed to bring up one external TUN engine, gathered so adding an
/// engine is a single match arm. `bin` is the engine binary (resolved per-platform);
/// `cfg_path` is where a config-file engine (hev) writes its YAML; `ipv4`/`ipv6` are
/// the addresses such an engine assigns to the tun it creates itself; `opts` carries
/// the resolved tuning.
pub struct TunSpawn<'a> {
    pub bin: &'a str,
    pub iface: &'a str,
    pub ipv4: &'a str,
    pub ipv6: Option<&'a str>,
    pub socks_port: u16,
    pub log_path: &'a Path,
    pub fwmark: Option<u32>,
    pub cfg_path: &'a Path,
    pub opts: &'a TunOptions,
}

/// The single place that knows how to launch an external TUN engine. Every shell
/// (desktop, root daemon) routes its bring-up through here, so adding a new engine
/// is one more arm — nothing else in the orchestration learns engine specifics.
/// `SingboxTun` has no external helper (the sing-box core owns the tun) and must
/// not reach this.
pub async fn spawn_tun_engine(tun: TunEngine, s: &TunSpawn<'_>) -> std::io::Result<Child> {
    match tun {
        TunEngine::Tun2socks => spawn_tun2socks(s).await,
        TunEngine::Hev => spawn_hev(s).await,
        // Callers gate this on the engine being external; a `SingboxTun` reaching
        // here means a corrupt/misresolved marker. Return an error rather than
        // panic — this runs in the privileged data-path owner, whose crash would
        // strand routing/tun state.
        TunEngine::SingboxTun => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SingboxTun has no external helper to spawn",
        )),
    }
}

/// hev creates and addresses its own tun from a YAML config: render it, write it
/// next to the runtime state, then run `<hev_bin> <cfg>`.
async fn spawn_hev(s: &TunSpawn<'_>) -> std::io::Result<Child> {
    let yaml = build_hev_config(s.iface, s.ipv4, s.ipv6, s.socks_port, s.fwmark, s.opts);
    write_text(s.cfg_path, &yaml).await?;
    let argv = [s.bin.to_owned(), s.cfg_path.to_string_lossy().into_owned()];
    spawn_logged(&argv, &std::collections::HashMap::new(), s.log_path, false).await
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
    use crate::testutil::{TestPlatform, sample_vless};
    use kasumi_core::state::default_app_state;

    #[test]
    fn external_engine_resolution() {
        use kasumi_core::enums::{TunEngine, tun_marker};
        // Marker is authoritative: native sing-box tun → no helper expected.
        let native = tun_marker(TunEngine::SingboxTun);
        assert_eq!(
            running_external_engine(Some(&native), Some("sing-box")),
            None
        );
        // Marker names an external engine → that engine (even behind sing-box).
        let hev = tun_marker(TunEngine::Hev);
        assert_eq!(
            running_external_engine(Some(&hev), Some("sing-box")),
            Some(TunEngine::Hev)
        );
        // Absent marker falls back to the core: xray → external default, sing-box →
        // native, unknown/absent → external (conservative).
        assert_eq!(
            running_external_engine(None, Some("xray")),
            Some(TunEngine::Tun2socks)
        );
        assert_eq!(running_external_engine(None, Some("sing-box")), None);
        assert_eq!(
            running_external_engine(None, None),
            Some(TunEngine::Tun2socks)
        );
        // Whitespace/garbage markers are treated as absent.
        assert_eq!(
            running_external_engine(Some("  \n"), Some("xray")),
            Some(TunEngine::Tun2socks)
        );
    }

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
        let (engine, tun, _tun_opts, socks) = resolve_and_write_config(&p, None).await.unwrap();
        assert_eq!(engine, CoreEngine::Xray);
        assert_eq!(tun, TunEngine::Tun2socks);
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
