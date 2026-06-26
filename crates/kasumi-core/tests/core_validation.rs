//! Validates that the configs our builders emit are actually accepted by the real
//! cores (`xray run -test` / `sing-box check`), catching schema drift — e.g. a field
//! our builder emits that a pinned core version rejects. This is the config-output
//! safety net: `core-compat.yml` runs it with staged cores on every PR touching
//! `crates/kasumi-core/**`.
//!
//! The case matrix is GENERATED from our own enums (`Protocol`, `Network`,
//! `Security`, `SsMethod` via `strum::IntoEnumIterator`), not hand-written, so a
//! new protocol/transport variant is swept automatically.
//!
//! The binaries are NOT committed; stage them with `scripts/fetch-binaries.sh desktop`
//! (pinned versions in `scripts/binary-versions.sh`). When they're absent — as in a
//! plain CI checkout — every case is skipped and the test passes, so this never
//! blocks the normal `cargo test --workspace` path. Point at custom binaries with
//! `KASUMI_XRAY_BIN` / `KASUMI_SINGBOX_BIN`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use strum::IntoEnumIterator;

use kasumi_core::core_config::build_core_config;
use kasumi_core::enums::{CoreEngine, Network, Security, SsMethod};
use kasumi_core::profile::{Profile, Protocol};
use kasumi_core::state::AdvancedSettings;

// ── valid credential / crypto material (cores validate these) ──
const UUID: &str = "11111111-1111-1111-1111-111111111111";
const PW: &str = "password123";
const WG_PRIV: &str = "sOs7Qk6VSmoowjvnQw37LUnV39bIG2rOjmmVItntGUw=";
const WG_PUB: &str = "xK8Tw4nv6TBWHl3WlVqoMLVrNsejQdC7/7jiTlR2rg8=";
const REALITY_PBK: &str = "c7twR4u_IvJsLGDqYsx2yb1nr2Kg74vsRlA_ou8c4QQ";
const SS_KEY_16: &str = "MTIzNDU2Nzg5MGFiY2RlZg==";
const SS_KEY_32: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";

/// The wire string of a serde enum (e.g. `Network::Ws` → `"ws"`).
fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn tls_carrying(p: Protocol) -> bool {
    matches!(
        p,
        Protocol::Vless
            | Protocol::Vmess
            | Protocol::Trojan
            | Protocol::Shadowsocks
            | Protocol::Http
            | Protocol::Hysteria2
            | Protocol::Tuic
            | Protocol::Anytls
            | Protocol::Naive
            | Protocol::Shadowtls
    )
}

/// Protocol-specific credentials a config needs to be buildable + core-valid.
fn creds(seed: &mut Value, proto: Protocol) {
    let put = |seed: &mut Value, k: &str, v: &str| seed[k] = json!(v);
    match proto {
        Protocol::Vless | Protocol::Vmess => put(seed, "uuid", UUID),
        Protocol::Tuic => {
            put(seed, "uuid", UUID);
            put(seed, "password", PW);
        }
        Protocol::Trojan | Protocol::Hysteria2 | Protocol::Anytls | Protocol::Shadowtls => {
            put(seed, "password", PW)
        }
        Protocol::Naive | Protocol::Socks | Protocol::Http => {
            put(seed, "username", "user");
            put(seed, "password", PW);
        }
        Protocol::Shadowsocks => {
            put(seed, "password", PW);
            put(seed, "method", "aes-256-gcm");
        }
        Protocol::Wireguard => {
            put(seed, "secretKey", WG_PRIV);
            put(seed, "peerPublicKey", WG_PUB);
        }
        Protocol::Custom => {}
    }
}

/// Build a profile seed for a protocol with an optional transport + TLS mode.
fn make(
    proto: Protocol,
    network: Option<Network>,
    security: Security,
    name: &str,
) -> Option<Profile> {
    if proto == Protocol::Custom {
        return None; // no buildable launch config
    }
    let mut seed = json!({
        "protocol": wire(&proto),
        "meta": { "id": "", "remarks": name, "groupId": "g-main" },
        "endpoint": { "address": "e.example", "port": 443 },
    });
    creds(&mut seed, proto);

    if let Some(net) = network {
        let mut t = json!({ "kind": wire(&net) });
        if net == Network::Grpc {
            t["serviceName"] = json!("GunService");
        }
        seed["transport"] = t;
    }

    if tls_carrying(proto) {
        let mut tls = json!({ "security": wire(&security), "sni": "s.example" });
        if security == Security::Reality {
            tls["publicKey"] = json!(REALITY_PBK);
            tls["shortId"] = json!("ab");
            tls["fingerprint"] = json!("chrome");
        }
        seed["tls"] = tls;
        if security == Security::Reality && proto == Protocol::Vless {
            seed["flow"] = json!("xtls-rprx-vision");
        }
    }

    serde_json::from_value(seed).ok()
}

/// The base64 key a shadowsocks method needs (2022 AEAD methods are length-checked).
fn ss_key(method: SsMethod) -> &'static str {
    match method {
        SsMethod::Blake3Aes128Gcm => SS_KEY_16,
        SsMethod::Blake3Aes256Gcm | SsMethod::Blake3Chacha20Poly1305 => SS_KEY_32,
        _ => PW,
    }
}

/// Every case to validate, generated by sweeping our enums.
fn generate() -> Vec<(String, Profile)> {
    let mut cases: Vec<(String, Profile)> = Vec::new();

    // 1. Every protocol once (default transport, TLS).
    for proto in Protocol::iter() {
        let name = format!("proto/{}", wire(&proto));
        if let Some(p) = make(proto, None, Security::Tls, &name) {
            cases.push((name, p));
        }
    }

    // 2. Transport-carrying protocols × every transport (TLS).
    for proto in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
        for net in Network::iter() {
            let name = format!("xport/{}-{}", wire(&proto), wire(&net));
            if let Some(p) = make(proto, Some(net), Security::Tls, &name) {
                cases.push((name, p));
            }
        }
    }

    // 3. Shadowsocks × every cipher (TCP).
    for method in SsMethod::iter() {
        let name = format!("ss/{}", wire(&method));
        if let Some(Profile::Shadowsocks(mut s)) =
            make(Protocol::Shadowsocks, None, Security::Tls, &name)
        {
            s.method = method;
            s.password = ss_key(method).to_string();
            cases.push((name, Profile::Shadowsocks(s)));
        }
    }

    // 4. VLESS × every TLS security mode (TCP).
    for sec in Security::iter() {
        let name = format!("sec/vless-{}", wire(&sec));
        if let Some(p) = make(Protocol::Vless, Some(Network::Tcp), sec, &name) {
            cases.push((name, p));
        }
    }

    cases
}

// ── core invocation ──

fn binaries_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../src-tauri/binaries")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src-tauri/binaries"))
}

fn find_core(env_var: &str, prefix: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_var) {
        let path = PathBuf::from(p);
        return path.is_file().then_some(path);
    }
    let dir = binaries_dir();
    for e in std::fs::read_dir(&dir).ok()?.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && !name.ends_with(".dll") {
            return Some(e.path());
        }
    }
    None
}

fn write_config(
    profile: &Profile,
    srs_dir: &Path,
) -> Option<(tempfile::TempDir, PathBuf, CoreEngine)> {
    let settings = AdvancedSettings::default();
    let built = build_core_config(
        profile,
        &settings,
        &[],
        std::slice::from_ref(profile),
        &srs_dir.to_string_lossy(),
    )
    .ok()?;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_string_pretty(&built.config).unwrap()).unwrap();
    Some((dir, path, built.engine))
}

fn validate(engine: CoreEngine, bin: &Path, cfg: &Path, asset_dir: &Path) -> (bool, String) {
    let mut cmd = Command::new(bin);
    match engine {
        CoreEngine::Xray => {
            cmd.args(["run", "-test", "-c"]).arg(cfg);
            cmd.env("XRAY_LOCATION_ASSET", asset_dir);
        }
        CoreEngine::SingBox => {
            cmd.args(["check", "-c"]).arg(cfg);
        }
    }
    let out = cmd.output().expect("spawn core");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

#[test]
fn generated_configs_validate_against_real_cores() {
    let xray = find_core("KASUMI_XRAY_BIN", "xray");
    let singbox = find_core("KASUMI_SINGBOX_BIN", "sing-box");
    if xray.is_none() && singbox.is_none() {
        eprintln!(
            "skipping core validation: no staged binaries in {} (run scripts/fetch-binaries.sh desktop)",
            binaries_dir().display()
        );
        return;
    }

    let asset_dir = binaries_dir();
    let srs_dir = tempfile::tempdir().unwrap();

    let mut failures = Vec::new();
    let mut checked = 0;
    for (name, profile) in generate() {
        let Some((_keep, cfg, engine)) = write_config(&profile, srs_dir.path()) else {
            continue; // our builder declined this combo — not a core problem.
        };
        let bin = match engine {
            CoreEngine::Xray => xray.as_deref(),
            CoreEngine::SingBox => singbox.as_deref(),
        };
        let Some(bin) = bin else { continue };
        let (ok, output) = validate(engine, bin, &cfg, asset_dir.as_path());
        checked += 1;
        if !ok {
            failures.push(format!("[{name}] {engine:?} rejected:\n{}", output.trim()));
        }
    }

    eprintln!(
        "core validation: {}/{checked} configs accepted",
        checked - failures.len()
    );
    assert!(
        failures.is_empty(),
        "{}/{} configs rejected by their core:\n\n{}",
        failures.len(),
        checked,
        failures.join("\n---\n")
    );
    assert!(
        checked > 0,
        "no cases validated — staged binaries unreadable?"
    );
}
