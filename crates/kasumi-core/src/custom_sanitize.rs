//! Reduce a subscription provider's Xray JSON to the part Kasumi lets a provider
//! decide: its outbounds and the routing between them. The core runs as root on
//! Android, so whatever reaches the host is dropped, not trusted: log file paths
//! (root file writes), inbounds (listeners), `api`/`stats`/`policy` (a gRPC
//! control plane), `reverse` (tunnels in), TLS key-log and certificate paths, and
//! socket marks or interface binds that escape Kasumi's fwmark/uid routing.

use std::collections::HashSet;
use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::sub_ingest::limits;

/// Outbound protocols a provider config may use.
const PROTOCOLS: [&str; 11] = [
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "wireguard",
    "hysteria",
    "freedom",
    "blackhole",
    "dns",
];
/// Protocols that never reach a proxy server.
pub(crate) const SERVICE_PROTOCOLS: [&str; 3] = ["freedom", "blackhole", "dns"];
const OUTBOUND_KEYS: [&str; 6] = [
    "tag",
    "protocol",
    "settings",
    "streamSettings",
    "mux",
    "proxySettings",
];
const SOCKOPT_KEYS: [&str; 8] = [
    "tcpFastOpen",
    "tcpKeepAliveInterval",
    "tcpKeepAliveIdle",
    "tcpNoDelay",
    "tcpcongestion",
    "domainStrategy",
    "happyEyeballs",
    "dialerProxy",
];
/// `streamSettings` keys that name host files.
const FILE_KEYS: [&str; 3] = ["masterKeyLog", "certificateFile", "keyFile"];
/// `redirect` is left out: it could point the user's traffic at local services.
const FREEDOM_SETTINGS_KEYS: [&str; 3] = ["domainStrategy", "fragment", "noises"];
const RULE_KEYS: [&str; 9] = [
    "type",
    "domain",
    "ip",
    "port",
    "sourcePort",
    "network",
    "protocol",
    "outboundTag",
    "balancerTag",
];
/// The other strategies need the observatory, which is dropped.
const BALANCER_STRATEGIES: [&str; 2] = ["random", "roundRobin"];

/// The parts of a provider's Xray config that survive sanitising.
#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedXray {
    pub outbounds: Vec<Value>,
    pub routing: Option<Value>,
    pub remarks: Option<String>,
    /// Paths of what was removed, for logs and tests.
    pub dropped: Vec<String>,
}

/// Why a provider config can't be used at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeError {
    NotObject,
    NoOutbounds,
    NoProxyOutbound,
    TooLarge,
}

impl fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SanitizeError::NotObject => "not a JSON object",
            SanitizeError::NoOutbounds => "no outbounds",
            SanitizeError::NoProxyOutbound => "no proxy outbound",
            SanitizeError::TooLarge => "too large",
        })
    }
}

impl std::error::Error for SanitizeError {}

/// Keep only the allowlisted parts of a provider's Xray config.
pub fn sanitize_provider_xray(v: &Value) -> Result<SanitizedXray, SanitizeError> {
    if exceeds(v, limits().max_body_bytes) {
        return Err(SanitizeError::TooLarge);
    }
    let top = v.as_object().ok_or(SanitizeError::NotObject)?;
    let mut dropped: Vec<String> = top
        .keys()
        .filter(|k| !["outbounds", "routing", "remarks"].contains(&k.as_str()))
        .cloned()
        .collect();

    let raw = top
        .get("outbounds")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(SanitizeError::NoOutbounds)?;
    let mut outbounds = Vec::new();
    let mut tags = HashSet::new();
    for (i, ob) in raw.iter().enumerate() {
        if let Some(ob) = sanitize_outbound(ob, i, &mut tags, &mut dropped) {
            outbounds.push(ob);
        }
    }
    // Chain references resolve only once every kept tag is known.
    for (i, ob) in outbounds.iter_mut().enumerate() {
        restrict_references(ob, &format!("outbounds[{i}]"), &tags, &mut dropped);
    }
    if outbounds.is_empty() {
        return Err(SanitizeError::NoOutbounds);
    }
    if outbounds.iter().all(is_service_outbound) {
        return Err(SanitizeError::NoProxyOutbound);
    }

    let routing = top
        .get("routing")
        .and_then(|r| sanitize_routing(r, &outbounds, &tags, &mut dropped));
    let remarks = top
        .get("remarks")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(SanitizedXray {
        outbounds,
        routing,
        remarks,
        dropped,
    })
}

/// True for an outbound that carries no traffic to a proxy server.
pub(crate) fn is_service_outbound(ob: &Value) -> bool {
    ob.get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|p| SERVICE_PROTOCOLS.contains(&p))
}

/// SHA-256 of a stored provider config's outbounds with their tags removed: a
/// refresh that only renames tags is still the same server.
pub fn provider_outbounds_identity(raw: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let mut outbounds = v.get("outbounds")?.as_array()?.clone();
    for ob in &mut outbounds {
        if let Some(o) = ob.as_object_mut() {
            o.remove("tag");
        }
    }
    let digest = Sha256::digest(Value::Array(outbounds).to_string().as_bytes());
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// Serialised size above `max`, counted without building the string.
fn exceeds(v: &Value, max: usize) -> bool {
    struct Budget(usize);
    impl std::io::Write for Budget {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(buf.len())
                .ok_or_else(|| std::io::Error::other("over budget"))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Budget(max), v).is_err()
}

fn sanitize_outbound(
    ob: &Value,
    i: usize,
    tags: &mut HashSet<String>,
    dropped: &mut Vec<String>,
) -> Option<Value> {
    let path = format!("outbounds[{i}]");
    let Some(obj) = ob.as_object() else {
        dropped.push(format!("{path}: not an object"));
        return None;
    };
    let protocol = obj.get("protocol").and_then(Value::as_str).unwrap_or("");
    if !PROTOCOLS.contains(&protocol) {
        dropped.push(format!("{path}: protocol \"{protocol}\""));
        return None;
    }
    let mut out = Map::new();
    for (k, val) in obj {
        if OUTBOUND_KEYS.contains(&k.as_str()) {
            out.insert(k.clone(), val.clone());
        } else {
            dropped.push(format!("{path}.{k}"));
        }
    }
    match out.get("tag").map(|t| t.as_str().map(str::to_string)) {
        Some(Some(tag)) if !tag.is_empty() => {
            if tags.contains(&tag) {
                dropped.push(format!("{path}: duplicate tag \"{tag}\""));
                return None;
            }
            tags.insert(tag);
        }
        Some(_) => {
            out.remove("tag");
            dropped.push(format!("{path}.tag"));
        }
        None => {}
    }
    if protocol == "freedom"
        && let Some(settings) = out.get_mut("settings").and_then(Value::as_object_mut)
    {
        settings.retain(|k, _| {
            let keep = FREEDOM_SETTINGS_KEYS.contains(&k.as_str());
            if !keep {
                dropped.push(format!("{path}.settings.{k}"));
            }
            keep
        });
    }
    if let Some(stream) = out.get_mut("streamSettings") {
        strip_host_files(stream, &format!("{path}.streamSettings"), dropped);
    }
    Some(Value::Object(out))
}

/// Drop file keys and reduce every sockopt (including nested ones such as an
/// xhttp download leg's or ECH's) to the allowlist, at any depth.
fn strip_host_files(v: &mut Value, path: &str, dropped: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            m.retain(|k, _| {
                let keep = !FILE_KEYS.contains(&k.as_str());
                if !keep {
                    dropped.push(format!("{path}.{k}"));
                }
                keep
            });
            for (k, child) in m.iter_mut() {
                let child_path = format!("{path}.{k}");
                if is_sockopt_key(k) {
                    match child.as_object_mut() {
                        Some(so) => so.retain(|sk, _| {
                            let keep = SOCKOPT_KEYS.contains(&sk.as_str());
                            if !keep {
                                dropped.push(format!("{child_path}.{sk}"));
                            }
                            keep
                        }),
                        None => {
                            *child = Value::Object(Map::new());
                            dropped.push(child_path);
                        }
                    }
                } else {
                    strip_host_files(child, &child_path, dropped);
                }
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                strip_host_files(child, &format!("{path}[{i}]"), dropped);
            }
        }
        _ => {}
    }
}

fn is_sockopt_key(k: &str) -> bool {
    k == "sockopt" || k.ends_with("Sockopt")
}

/// Drop `dialerProxy` / `proxySettings` that name an outbound outside this config.
fn restrict_references(
    ob: &mut Value,
    path: &str,
    tags: &HashSet<String>,
    dropped: &mut Vec<String>,
) {
    if let Some(stream) = ob.get_mut("streamSettings") {
        restrict_dialer_proxy(stream, &format!("{path}.streamSettings"), tags, dropped);
    }
    let Some(obj) = ob.as_object_mut() else {
        return;
    };
    if let Some(ps) = obj.get("proxySettings") {
        let tag = ps.get("tag").and_then(Value::as_str);
        match tag.filter(|t| tags.contains(*t)) {
            Some(t) => {
                let mut kept = Map::new();
                kept.insert("tag".into(), t.into());
                if let Some(tl) = ps.get("transportLayer").and_then(Value::as_bool) {
                    kept.insert("transportLayer".into(), tl.into());
                }
                obj.insert("proxySettings".into(), Value::Object(kept));
            }
            None => {
                obj.remove("proxySettings");
                dropped.push(format!("{path}.proxySettings"));
            }
        }
    }
}

fn restrict_dialer_proxy(
    v: &mut Value,
    path: &str,
    tags: &HashSet<String>,
    dropped: &mut Vec<String>,
) {
    match v {
        Value::Object(m) => {
            if let Some(d) = m.get("dialerProxy")
                && !d.as_str().is_some_and(|t| tags.contains(t))
            {
                m.remove("dialerProxy");
                dropped.push(format!("{path}.dialerProxy"));
            }
            for (k, child) in m.iter_mut() {
                restrict_dialer_proxy(child, &format!("{path}.{k}"), tags, dropped);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                restrict_dialer_proxy(child, &format!("{path}[{i}]"), tags, dropped);
            }
        }
        _ => {}
    }
}

fn sanitize_routing(
    routing: &Value,
    outbounds: &[Value],
    tags: &HashSet<String>,
    dropped: &mut Vec<String>,
) -> Option<Value> {
    let Some(obj) = routing.as_object() else {
        dropped.push("routing".into());
        return None;
    };
    let mut out = Map::new();
    for k in obj.keys() {
        if !["domainStrategy", "rules", "balancers"].contains(&k.as_str()) {
            dropped.push(format!("routing.{k}"));
        }
    }
    if let Some(ds) = obj.get("domainStrategy").and_then(Value::as_str) {
        out.insert("domainStrategy".into(), ds.into());
    }

    let order: Vec<&str> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
    let mut balancer_tags = HashSet::new();
    let balancers: Vec<Value> = array_of(obj, "balancers")
        .enumerate()
        .filter_map(|(i, b)| sanitize_balancer(b, i, &order, tags, &mut balancer_tags, dropped))
        .collect();
    let rules: Vec<Value> = array_of(obj, "rules")
        .enumerate()
        .filter_map(|(i, r)| sanitize_rule(r, i, tags, &balancer_tags, dropped))
        .collect();
    if !balancers.is_empty() {
        out.insert("balancers".into(), balancers.into());
    }
    if !rules.is_empty() {
        out.insert("rules".into(), rules.into());
    }
    (!out.is_empty()).then_some(Value::Object(out))
}

fn array_of<'a>(obj: &'a Map<String, Value>, key: &str) -> impl Iterator<Item = &'a Value> {
    obj.get(key).and_then(Value::as_array).into_iter().flatten()
}

/// The selector's tag prefixes are expanded to the outbound tags they match
/// here, so the members stay the same once the config sits beside Kasumi's own
/// outbounds, whose tags the prefixes could otherwise also match.
fn sanitize_balancer(
    b: &Value,
    i: usize,
    order: &[&str],
    tags: &HashSet<String>,
    balancer_tags: &mut HashSet<String>,
    dropped: &mut Vec<String>,
) -> Option<Value> {
    let path = format!("routing.balancers[{i}]");
    let tag = b
        .get("tag")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty());
    let prefixes: Vec<&str> = b
        .get("selector")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let members: Vec<Value> = order
        .iter()
        .filter(|t| prefixes.iter().any(|p| t.starts_with(p)))
        .map(|t| Value::from(*t))
        .collect();
    let Some(tag) = tag.filter(|_| !members.is_empty()) else {
        dropped.push(path);
        return None;
    };
    if !balancer_tags.insert(tag.to_string()) {
        dropped.push(format!("{path}: duplicate tag \"{tag}\""));
        return None;
    }
    let mut out = Map::new();
    out.insert("tag".into(), tag.into());
    out.insert("selector".into(), members.into());
    if let Some(strategy) = b.get("strategy") {
        match strategy.get("type").and_then(Value::as_str) {
            Some(t) if BALANCER_STRATEGIES.contains(&t) => {
                out.insert("strategy".into(), serde_json::json!({ "type": t }));
            }
            _ => dropped.push(format!("{path}.strategy")),
        }
    }
    if let Some(fallback) = b.get("fallbackTag") {
        match fallback.as_str().filter(|t| tags.contains(*t)) {
            Some(t) => {
                out.insert("fallbackTag".into(), t.into());
            }
            None => dropped.push(format!("{path}.fallbackTag")),
        }
    }
    Some(Value::Object(out))
}

fn sanitize_rule(
    r: &Value,
    i: usize,
    tags: &HashSet<String>,
    balancer_tags: &HashSet<String>,
    dropped: &mut Vec<String>,
) -> Option<Value> {
    let path = format!("routing.rules[{i}]");
    let Some(obj) = r.as_object() else {
        dropped.push(path);
        return None;
    };
    // None when the rule has no such target, else whether it names a kept one.
    let target_ok = |key: &str, known: &HashSet<String>| {
        obj.get(key)
            .map(|t| t.as_str().is_some_and(|t| known.contains(t)))
    };
    let outbound = target_ok("outboundTag", tags);
    let balancer = target_ok("balancerTag", balancer_tags);
    let has_target = outbound == Some(true) || balancer == Some(true);
    if !has_target || outbound == Some(false) || balancer == Some(false) {
        dropped.push(format!("{path}: unknown or missing target"));
        return None;
    }
    let mut out = Map::new();
    for (k, val) in obj {
        if RULE_KEYS.contains(&k.as_str()) {
            out.insert(k.clone(), val.clone());
        } else {
            dropped.push(format!("{path}.{k}"));
        }
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vless(tag: &str) -> Value {
        json!({
            "tag": tag, "protocol": "vless",
            "settings": { "vnext": [{ "address": "srv.example", "port": 443,
                "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
            "streamSettings": { "network": "tcp", "security": "tls" },
        })
    }

    fn sanitize(v: Value) -> SanitizedXray {
        sanitize_provider_xray(&v).unwrap()
    }

    #[test]
    fn drops_log_paths_inbounds_api_stats_policy_reverse() {
        let out = sanitize(json!({
            "log": { "loglevel": "debug", "error": "/data/adb/kasumi-proxy/x", "access": "/data/adb/x" },
            "inbounds": [{ "protocol": "socks", "listen": "0.0.0.0", "port": 1080 }],
            "api": { "tag": "api", "services": ["HandlerService"] },
            "stats": {},
            "policy": { "system": { "statsOutboundUplink": true } },
            "reverse": { "bridges": [{ "tag": "bridge", "domain": "r.example" }] },
            "remarks": "Server",
            "outbounds": [vless("proxy")],
        }));
        for key in ["log", "inbounds", "api", "stats", "policy", "reverse"] {
            assert!(out.dropped.iter().any(|d| d == key), "{key} not listed");
        }
        assert_eq!(out.outbounds.len(), 1);
        assert_eq!(out.remarks.as_deref(), Some("Server"));
        let text = serde_json::to_string(&out.outbounds).unwrap();
        assert!(!text.contains("/data/adb"));
    }

    #[test]
    fn drops_sockopt_mark_and_interface() {
        let mut ob = vless("proxy");
        ob["sendThrough"] = "10.0.0.1".into();
        ob["streamSettings"]["sockopt"] = json!({
            "mark": 255, "interface": "wlan0", "tproxy": "tproxy",
            "customSockopt": [{ "level": "1", "opt": "36", "value": "255" }],
            "tcpFastOpen": true,
        });
        ob["streamSettings"]["xhttpSettings"] = json!({ "extra": { "downloadSettings": {
            "address": "d.example", "port": 443,
            "sockopt": { "mark": 1, "tcpNoDelay": true },
        }}});
        ob["streamSettings"]["tlsSettings"] = json!({
            "serverName": "srv.example",
            "masterKeyLog": "/data/adb/keys.log",
            "certificates": [{ "certificateFile": "/data/adb/kasumi-proxy/state.json", "usage": "verify" }],
        });
        let out = sanitize(json!({ "outbounds": [ob] }));
        let ob = &out.outbounds[0];
        assert!(ob.get("sendThrough").is_none());
        assert_eq!(
            ob["streamSettings"]["sockopt"],
            json!({ "tcpFastOpen": true })
        );
        assert_eq!(
            ob["streamSettings"]["xhttpSettings"]["extra"]["downloadSettings"]["sockopt"],
            json!({ "tcpNoDelay": true })
        );
        let text = serde_json::to_string(ob).unwrap();
        assert!(!text.contains("/data/adb"), "{text}");
        assert!(
            out.dropped
                .contains(&"outbounds[0].streamSettings.sockopt.mark".to_string())
        );
    }

    #[test]
    fn keeps_dialer_proxy_only_for_internal_tag() {
        let mut exit = vless("exit");
        exit["streamSettings"]["sockopt"] = json!({ "dialerProxy": "entry" });
        let mut stray = vless("stray");
        stray["streamSettings"]["sockopt"] = json!({ "dialerProxy": "elsewhere" });
        stray["proxySettings"] = json!({ "tag": "elsewhere" });
        let out = sanitize(json!({ "outbounds": [exit, vless("entry"), stray] }));
        assert_eq!(
            out.outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
            "entry"
        );
        assert!(
            out.outbounds[2]["streamSettings"]["sockopt"]
                .get("dialerProxy")
                .is_none()
        );
        assert!(out.outbounds[2].get("proxySettings").is_none());
    }

    #[test]
    fn rejects_without_outbounds() {
        for v in [
            json!({}),
            json!({ "outbounds": [] }),
            json!({ "outbounds": "x" }),
        ] {
            assert_eq!(sanitize_provider_xray(&v), Err(SanitizeError::NoOutbounds));
        }
        assert_eq!(
            sanitize_provider_xray(&json!({ "outbounds": [{ "protocol": "loopback" }] })),
            Err(SanitizeError::NoOutbounds)
        );
        assert_eq!(
            sanitize_provider_xray(&json!([1])),
            Err(SanitizeError::NotObject)
        );
    }

    #[test]
    fn rejects_only_freedom() {
        let v = json!({ "outbounds": [
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "dns", "protocol": "dns" },
        ]});
        assert_eq!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::NoProxyOutbound)
        );
    }

    #[test]
    fn rejects_oversized_input() {
        let pad = "x".repeat(limits().max_body_bytes);
        let v = json!({ "outbounds": [vless("proxy")], "remarks": pad });
        assert_eq!(sanitize_provider_xray(&v), Err(SanitizeError::TooLarge));
    }

    #[test]
    fn freedom_redirect_is_dropped() {
        let out = sanitize(json!({ "outbounds": [
            vless("proxy"),
            { "tag": "direct", "protocol": "freedom",
              "settings": { "domainStrategy": "UseIPv4", "redirect": "127.0.0.1:9090" } },
        ]}));
        assert_eq!(
            out.outbounds[1]["settings"],
            json!({ "domainStrategy": "UseIPv4" })
        );
    }

    #[test]
    fn routing_rules_to_unknown_tags_dropped() {
        let out = sanitize(json!({
            "outbounds": [vless("proxy"), { "tag": "direct", "protocol": "freedom" }],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "balancers": [
                    { "tag": "lb", "selector": ["prox"], "strategy": { "type": "leastPing" } },
                    { "tag": "nosel" },
                ],
                "rules": [
                    { "type": "field", "domain": ["geosite:ru"], "outboundTag": "direct" },
                    { "type": "field", "domain": ["a.example"], "outboundTag": "api" },
                    { "type": "field", "ip": ["1.1.1.1"], "balancerTag": "lb" },
                    { "type": "field", "ip": ["8.8.8.8"], "balancerTag": "nosel" },
                    { "type": "field", "ip": ["9.9.9.9"] },
                ],
                "settings": {},
            },
        }));
        let routing = out.routing.unwrap();
        let rules = routing["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["outboundTag"], "direct");
        assert_eq!(rules[1]["balancerTag"], "lb");
        // leastPing needs the observatory, which a provider can't configure.
        assert_eq!(
            routing["balancers"],
            json!([{ "tag": "lb", "selector": ["proxy"] }])
        );
        assert!(out.dropped.contains(&"routing.settings".to_string()));
    }

    #[test]
    fn inbound_tag_field_dropped() {
        let out = sanitize(json!({
            "outbounds": [vless("proxy")],
            "routing": { "rules": [
                { "type": "field", "inboundTag": ["api"], "user": ["x"], "outboundTag": "proxy" },
            ]},
        }));
        let rule = &out.routing.unwrap()["rules"][0];
        assert_eq!(rule, &json!({ "type": "field", "outboundTag": "proxy" }));
        assert!(
            out.dropped
                .contains(&"routing.rules[0].inboundTag".to_string())
        );
    }

    #[test]
    fn duplicate_outbound_tags_keep_the_first() {
        let out = sanitize(json!({ "outbounds": [vless("a"), vless("a")] }));
        assert_eq!(out.outbounds.len(), 1);
    }
}
