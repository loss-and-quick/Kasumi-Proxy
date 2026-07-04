//! Versioned upgrade of the persisted [`AppState`] document.
//!
//! Persistence stays JSON, but the schema evolves: the document carries a
//! `schemaVersion`, and [`MIGRATIONS`] is an ordered list of steps, each lifting
//! the value from version `i` to `i + 1`. On read, every step from the stored
//! version up to [`SCHEMA_VERSION`] runs in sequence (the Room-style ladder), then
//! the version stamp is refreshed. A document already at the current version
//! passes through untouched, so the upgrade is idempotent. Adding a field is
//! usually just a serde default; a step is only needed when the change can't be
//! expressed as a default (renames, regrouping, value reshaping).
//!
//! The very first step (v0 → v1) lifts the original flat profile layout — every
//! meta/endpoint/transport/tls field at the top level, transport keyed by a plain
//! `network` string, compound values stored as CSV/JSON strings — into the nested
//! model with the transport tagged on `kind`.

use serde_json::{Map, Value, json};

/// A single upgrade step, mutating the whole `AppState` value from one version to
/// the next.
type MigrationStep = fn(&mut Value);

/// The ordered migration ladder. Index `i` lifts version `i` to `i + 1`; append a
/// new step (never reorder or delete) whenever the on-disk schema changes.
const MIGRATIONS: &[MigrationStep] = &[migrate_v0_to_v1];

/// The schema version the current code writes (the length of the ladder).
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// Run every migration step from the document's stored `schemaVersion` up to
/// [`SCHEMA_VERSION`], then stamp the current version. No-op once current.
pub fn migrate_app_state(v: &mut Value) {
    let mut version = v
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(MIGRATIONS.len() as u64) as usize;
    while version < MIGRATIONS.len() {
        MIGRATIONS[version](v);
        version += 1;
    }
    if let Some(obj) = v.as_object_mut() {
        obj.insert("schemaVersion".into(), Value::from(SCHEMA_VERSION));
    }
}

/// v0 → v1: nest each profile's field groups and tag its transport on `kind`.
fn migrate_v0_to_v1(v: &mut Value) {
    if let Some(arr) = v.get_mut("profiles").and_then(Value::as_array_mut) {
        for p in arr {
            migrate_profile(p);
        }
    }
}

const META_KEYS: &[&str] = &["id", "remarks", "groupId", "subId", "coreType"];
const ENDPOINT_KEYS: &[&str] = &["address", "port"];
const TRANSPORT_KEYS: &[&str] = &[
    "network",
    "headerType",
    "host",
    "path",
    "wsEarlyData",
    "wsEarlyDataHeader",
    "wsHeartbeatPeriod",
    "wsHeaders",
    "acceptProxyProtocol",
    "serviceName",
    "authority",
    "grpcMode",
    "grpcIdleTimeout",
    "grpcHealthCheckTimeout",
    "grpcPingTimeout",
    "grpcPermitWithoutStream",
    "grpcInitialWindowsSize",
    "userAgent",
    "xhttpMode",
    "xhttpExtra",
    "kcpSeed",
    "kcpMtu",
    "kcpTti",
    "kcpUplink",
    "kcpDownlink",
    "kcpCwndMultiplier",
    "kcpMaxSendingWindow",
];
const TLS_KEYS: &[&str] = &[
    "security",
    "sni",
    "disableSni",
    "fingerprint",
    "alpn",
    "allowInsecure",
    "tlsMinVersion",
    "tlsMaxVersion",
    "tlsCipherSuites",
    "tlsCurvePreferences",
    "cert",
    "disableSystemRoot",
    "rejectUnknownSni",
    "enableSessionResumption",
    "publicKey",
    "shortId",
    "spiderX",
    "ech",
    "vcn",
    "pcs",
    "pqv",
];

fn has_transport(protocol: &str) -> bool {
    matches!(protocol, "vless" | "vmess" | "trojan" | "shadowsocks")
}

fn has_tls(protocol: &str) -> bool {
    matches!(
        protocol,
        "vless"
            | "vmess"
            | "trojan"
            | "shadowsocks"
            | "http"
            | "hysteria2"
            | "tuic"
            | "anytls"
            | "naive"
            | "shadowtls"
    )
}

/// Upgrade a single persisted profile in place (the v0 → v1 per-profile worker).
pub fn migrate_profile(v: &mut Value) {
    let Some(protocol) = v
        .get("protocol")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    let is_flat = v.get("meta").is_none() && v.get("id").is_some();
    if is_flat {
        flatten_to_nested(v, &protocol);
        return;
    }
    // Already nested, but an intermediate build may have left the transport keyed
    // on `network` rather than tagged on `kind`; tag it if so.
    if let Some(t) = v.get("transport")
        && t.is_object()
        && t.get("kind").is_none()
        && t.get("network").is_some()
        && let Some(Value::Object(map)) = v.get_mut("transport").map(Value::take)
    {
        v["transport"] = nest_transport(&map);
    }
}

fn flatten_to_nested(v: &mut Value, protocol: &str) {
    let Some(obj) = v.as_object_mut() else { return };

    let mut meta = take_group(obj, META_KEYS);
    fix_meta(&mut meta);
    obj.insert("meta".into(), Value::Object(meta));

    if protocol != "custom" {
        let endpoint = take_group(obj, ENDPOINT_KEYS);
        obj.insert("endpoint".into(), Value::Object(endpoint));
    }

    if has_transport(protocol) {
        // `muxEnabled` is now a protocol field, so it stays on the profile.
        let flat_t = take_group(obj, TRANSPORT_KEYS);
        obj.insert("transport".into(), nest_transport(&flat_t));
        obj.entry("muxEnabled").or_insert(Value::Bool(false));
    }

    if has_tls(protocol) {
        let mut tls = take_group(obj, TLS_KEYS);
        fix_tls(&mut tls);
        obj.insert("tls".into(), Value::Object(tls));
    }

    if protocol == "wireguard"
        && let Some(r) = obj.get_mut("reserved")
    {
        *r = reserved_to_bytes(r);
    }
}

/// Pull the listed keys out of `obj` into a fresh map (absent keys are skipped,
/// leaving the deserializer to fill their defaults).
fn take_group(obj: &mut Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    let mut out = Map::new();
    for k in keys {
        if let Some(val) = obj.remove(*k) {
            out.insert((*k).to_string(), val);
        }
    }
    out
}

fn fix_meta(meta: &mut Map<String, Value>) {
    // `coreType` was a string with a `"global"` sentinel; it is now nullable.
    match meta.get("coreType").and_then(Value::as_str) {
        Some("xray") | Some("sing-box") => {}
        _ => {
            meta.insert("coreType".into(), Value::Null);
        }
    }
}

fn fix_tls(tls: &mut Map<String, Value>) {
    for k in ["alpn", "tlsCipherSuites", "tlsCurvePreferences"] {
        if let Some(v) = tls.get(k) {
            let arr = csv_to_array(v);
            tls.insert(k.into(), arr);
        }
    }
}

/// CSV string → array of trimmed non-empty parts. An existing array is kept.
fn csv_to_array(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::Array(
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(|x| Value::String(x.to_string()))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `"0,0,0"` → `[0, 0, 0]`. An existing array is kept.
fn reserved_to_bytes(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::Array(
            s.split(',')
                .filter_map(|x| x.trim().parse::<u8>().ok())
                .map(Value::from)
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Build a header map from the old `wsHeaders` JSON-string (string values only).
fn ws_headers(flat: &Map<String, Value>) -> Value {
    let raw = flat.get("wsHeaders").and_then(Value::as_str).unwrap_or("");
    if raw.trim().is_empty() {
        return json!({});
    }
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(o)) => {
            Value::Object(o.into_iter().filter(|(_, v)| v.is_string()).collect())
        }
        _ => json!({}),
    }
}

/// The first key whose value is a non-empty string, as an owned `Value`.
fn first_nonempty(flat: &Map<String, Value>, keys: &[&str]) -> Option<Value> {
    keys.iter()
        .filter_map(|k| flat.get(*k))
        .find(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        .cloned()
}

/// Turn a flat transport map (keyed on `network`) into the tagged-union shape.
fn nest_transport(flat: &Map<String, Value>) -> Value {
    let net = flat.get("network").and_then(Value::as_str).unwrap_or("tcp");
    let mut o = Map::new();
    let put = |o: &mut Map<String, Value>, k: &str, src: &str| {
        if let Some(v) = flat.get(src) {
            o.insert(k.to_string(), v.clone());
        }
    };
    match net {
        "ws" => {
            o.insert("kind".into(), "ws".into());
            put(&mut o, "host", "host");
            put(&mut o, "path", "path");
            put(&mut o, "earlyData", "wsEarlyData");
            put(&mut o, "earlyDataHeader", "wsEarlyDataHeader");
            put(&mut o, "heartbeatPeriod", "wsHeartbeatPeriod");
            o.insert("headers".into(), ws_headers(flat));
            put(&mut o, "acceptProxyProtocol", "acceptProxyProtocol");
        }
        "grpc" => {
            o.insert("kind".into(), "grpc".into());
            // The host/path fallbacks become the canonical serviceName/authority.
            if let Some(v) = first_nonempty(flat, &["serviceName", "path"]) {
                o.insert("serviceName".into(), v);
            }
            if let Some(v) = first_nonempty(flat, &["authority", "host"]) {
                o.insert("authority".into(), v);
            }
            put(&mut o, "mode", "grpcMode");
            put(&mut o, "idleTimeout", "grpcIdleTimeout");
            put(&mut o, "healthCheckTimeout", "grpcHealthCheckTimeout");
            put(&mut o, "pingTimeout", "grpcPingTimeout");
            put(&mut o, "permitWithoutStream", "grpcPermitWithoutStream");
            put(&mut o, "initialWindowSize", "grpcInitialWindowsSize");
            put(&mut o, "userAgent", "userAgent");
        }
        "h2" => {
            o.insert("kind".into(), "h2".into());
            put(&mut o, "host", "host");
            put(&mut o, "path", "path");
            put(&mut o, "idleTimeout", "grpcIdleTimeout");
            put(&mut o, "pingTimeout", "grpcPingTimeout");
        }
        "httpupgrade" => {
            o.insert("kind".into(), "httpupgrade".into());
            put(&mut o, "host", "host");
            put(&mut o, "path", "path");
            put(&mut o, "earlyData", "wsEarlyData");
            o.insert("headers".into(), ws_headers(flat));
            put(&mut o, "acceptProxyProtocol", "acceptProxyProtocol");
        }
        "xhttp" => {
            o.insert("kind".into(), "xhttp".into());
            put(&mut o, "host", "host");
            put(&mut o, "path", "path");
            put(&mut o, "mode", "xhttpMode");
            put(&mut o, "extra", "xhttpExtra");
        }
        "kcp" => {
            o.insert("kind".into(), "kcp".into());
            put(&mut o, "headerType", "headerType");
            put(&mut o, "seed", "kcpSeed");
            put(&mut o, "mtu", "kcpMtu");
            put(&mut o, "tti", "kcpTti");
            put(&mut o, "uplink", "kcpUplink");
            put(&mut o, "downlink", "kcpDownlink");
            put(&mut o, "cwndMultiplier", "kcpCwndMultiplier");
            put(&mut o, "maxSendingWindow", "kcpMaxSendingWindow");
        }
        "quic" => {
            o.insert("kind".into(), "quic".into());
            put(&mut o, "headerType", "headerType");
        }
        _ => {
            o.insert("kind".into(), "tcp".into());
            put(&mut o, "headerType", "headerType");
            put(&mut o, "host", "host");
            put(&mut o, "path", "path");
        }
    }
    Value::Object(o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use crate::share::parse_share_link;

    /// A migrated profile must equal the same profile parsed straight from its
    /// share link (ids normalised) — proving the upgrade lands on the live shape.
    fn assert_migrates_like(flat: Value, uri: &str) {
        let mut v = flat;
        migrate_profile(&mut v);
        let migrated: Profile =
            serde_json::from_value(v).unwrap_or_else(|e| panic!("deserialize after migrate: {e}"));
        let parsed = parse_share_link(uri, None).unwrap();
        let mut a = serde_json::to_value(&migrated).unwrap();
        let mut b = serde_json::to_value(&parsed).unwrap();
        a["meta"]["id"] = Value::String(String::new());
        b["meta"]["id"] = Value::String(String::new());
        assert_eq!(a, b);
    }

    #[test]
    fn flat_vless_ws_upgrades_to_nested_tagged_transport() {
        let flat = json!({
            "protocol": "vless",
            "id": "x", "remarks": "Home", "groupId": "g-main", "subId": null,
            "coreType": "global",
            "address": "ex.com", "port": 443,
            "network": "ws", "headerType": "none", "host": "cdn.ex.com", "path": "/ws",
            "wsEarlyData": 2048, "wsEarlyDataHeader": "Sec-WebSocket-Protocol",
            "wsHeartbeatPeriod": 0, "wsHeaders": "", "acceptProxyProtocol": false,
            "serviceName": "", "authority": "", "grpcMode": "", "grpcIdleTimeout": 0,
            "grpcHealthCheckTimeout": 0, "grpcPingTimeout": 0, "grpcPermitWithoutStream": false,
            "grpcInitialWindowsSize": 0, "userAgent": "", "xhttpMode": "", "xhttpExtra": "",
            "kcpSeed": "", "kcpMtu": 0, "kcpTti": 0, "kcpUplink": 0, "kcpDownlink": 0,
            "kcpCwndMultiplier": 0, "kcpMaxSendingWindow": 0, "muxEnabled": false,
            "security": "reality", "sni": "ex.com", "fingerprint": "chrome",
            "alpn": "h2,http/1.1", "publicKey": "PK", "shortId": "ab",
            "uuid": "11111111-1111-1111-1111-111111111111", "flow": "", "encryption": "none",
            "packetEncoding": ""
        });
        let mut v = flat;
        migrate_profile(&mut v);
        // Coarse structural checks.
        assert!(v["meta"].is_object());
        assert!(v["meta"]["coreType"].is_null(), "global → null");
        assert!(v["meta"].get("ping").is_none(), "ping dropped");
        assert_eq!(v["transport"]["kind"], "ws");
        assert_eq!(v["transport"]["earlyData"], 2048);
        assert!(v["transport"].get("network").is_none());
        assert_eq!(v["tls"]["alpn"], json!(["h2", "http/1.1"]));
        assert!(v.get("network").is_none(), "flat keys consumed");
        // And it deserializes into a Profile.
        let p: Profile = serde_json::from_value(v).unwrap();
        assert_eq!(p.protocol(), crate::profile::Protocol::Vless);
        assert!(!p.mux_enabled());
    }

    #[test]
    fn flat_grpc_folds_fallbacks() {
        // serviceName/authority empty but path/host set → folded canonical fields.
        let flat = json!({
            "protocol": "trojan",
            "id": "x", "remarks": "G", "groupId": "g-main",
            "address": "ex.com", "port": 443,
            "network": "grpc", "host": "auth.ex", "path": "svc",
            "serviceName": "", "authority": "", "grpcMode": "multi",
            "security": "tls", "password": "pw"
        });
        let mut v = flat;
        migrate_profile(&mut v);
        assert_eq!(v["transport"]["kind"], "grpc");
        assert_eq!(v["transport"]["serviceName"], "svc");
        assert_eq!(v["transport"]["authority"], "auth.ex");
        assert_eq!(v["transport"]["mode"], "multi");
        let _: Profile = serde_json::from_value(v).unwrap();
    }

    #[test]
    fn flat_wireguard_reserved_csv_to_bytes() {
        let flat = json!({
            "protocol": "wireguard",
            "id": "w", "remarks": "W", "groupId": "g-main",
            "address": "ex.com", "port": 51820,
            "secretKey": "sk", "peerPublicKey": "pk", "reserved": "1,2,3",
            "localAddress": "172.16.0.2/32", "mtu": 1420
        });
        let mut v = flat;
        migrate_profile(&mut v);
        assert_eq!(v["reserved"], json!([1, 2, 3]));
        assert!(v["meta"].is_object());
        let p: Profile = serde_json::from_value(v).unwrap();
        let Profile::Wireguard(w) = p else { panic!() };
        assert_eq!(w.reserved, vec![1, 2, 3]);
    }

    #[test]
    fn migrating_current_shape_is_a_noop() {
        // A profile already in the live shape survives migration unchanged.
        let parsed =
            parse_share_link("vless://u@ex.com:443?type=ws&host=h&path=%2Fw", None).unwrap();
        let nested = serde_json::to_value(&parsed).unwrap();
        let mut v = nested.clone();
        migrate_profile(&mut v);
        assert_eq!(v, nested);
    }

    #[test]
    fn app_state_ladder_runs_and_stamps_version() {
        // A versionless (v0) document gets its profiles nested and is stamped.
        let mut doc = json!({
            "activeId": null,
            "profiles": [{
                "protocol": "vless",
                "id": "x", "remarks": "H", "groupId": "g-main",
                "address": "ex.com", "port": 443,
                "network": "ws", "host": "h", "path": "/w",
                "security": "tls", "uuid": "u"
            }]
        });
        migrate_app_state(&mut doc);
        assert_eq!(doc["schemaVersion"], json!(SCHEMA_VERSION));
        assert_eq!(doc["profiles"][0]["transport"]["kind"], "ws");
        assert!(doc["profiles"][0]["meta"].is_object());

        // Re-running is a no-op (already current).
        let again = doc.clone();
        migrate_app_state(&mut doc);
        assert_eq!(doc, again);
    }

    #[test]
    fn nested_but_network_keyed_transport_gets_tagged() {
        // An intermediate build can leave a profile nested (has `meta`) yet with
        // its transport keyed on `network` instead of tagged on `kind`. The
        // per-profile worker must re-tag it without touching the rest.
        let mut v = json!({
            "protocol": "vless",
            "meta": { "id": "x", "remarks": "H", "groupId": "g-main" },
            "endpoint": { "address": "ex.com", "port": 443 },
            "transport": { "network": "ws", "host": "h", "path": "/w" },
            "tls": { "security": "tls" },
            "uuid": "u"
        });
        migrate_profile(&mut v);
        assert_eq!(v["transport"]["kind"], "ws");
        assert_eq!(v["transport"]["host"], "h");
        assert!(v["transport"].get("network").is_none(), "network re-tagged");
        let p: Profile = serde_json::from_value(v).unwrap();
        assert_eq!(p.transport().unwrap().network(), crate::enums::Network::Ws);
    }

    #[test]
    fn future_schema_version_clamps_and_skips_steps() {
        // A document claiming a version beyond the ladder is clamped: no step runs
        // (so a flat profile stays flat), but the stamp is normalised back down.
        let mut doc = json!({
            "schemaVersion": 99,
            "profiles": [{
                "protocol": "vless",
                "id": "x", "remarks": "H", "groupId": "g-main",
                "address": "ex.com", "port": 443,
                "network": "ws", "host": "h", "path": "/w",
                "security": "tls", "uuid": "u"
            }]
        });
        migrate_app_state(&mut doc);
        assert_eq!(doc["schemaVersion"], json!(SCHEMA_VERSION));
        assert!(
            doc["profiles"][0].get("meta").is_none(),
            "no migration step should have run"
        );
        assert_eq!(doc["profiles"][0]["network"], "ws");
    }

    #[test]
    fn flat_matches_share_parsed_equivalent() {
        // Trojan over tcp with http obfs header.
        assert_migrates_like(
            json!({
                "protocol": "trojan",
                "id": "x", "remarks": "ex.com", "groupId": "g-main",
                "address": "ex.com", "port": 8443,
                "network": "tcp", "headerType": "none",
                "security": "tls", "sni": "ex.com", "password": "secret",
                "flow": "xtls-rprx-vision"
            }),
            "trojan://secret@ex.com:8443?type=tcp&security=tls&sni=ex.com&flow=xtls-rprx-vision#ex.com",
        );
    }
}
