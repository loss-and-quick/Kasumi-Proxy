//! Reduce a subscription provider's Xray JSON to the part Kasumi lets a provider
//! decide: its outbounds and the routing between them. The core runs as root on
//! Android, so whatever reaches the host is dropped, not trusted: log file paths
//! (root file writes), inbounds (listeners), `api`/`stats`/`policy` (a gRPC
//! control plane), `reverse` (tunnels in), TLS key-log and certificate paths, and
//! socket marks or interface binds that escape Kasumi's fwmark/uid routing.

use std::collections::HashSet;
use std::fmt;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::provider_graph::{
    BALANCER_STRATEGIES, MAX_SELECTOR_MEMBERS, validate_balancer_observatory_coverage,
    validate_dialer_proxies, validate_observatory_config, validate_routing_graph_acyclic,
    validate_stream_security,
};
use crate::sub_ingest::limits;
use crate::xray_config::xray_rule_has_condition;

/// Outbound protocols a provider config may use.
const PROTOCOLS: [&str; 12] = [
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
    "loopback",
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

const RULE_KEYS: [&str; 11] = [
    "type",
    "domain",
    "domains",
    "ip",
    "port",
    "sourcePort",
    "network",
    "protocol",
    "inboundTag",
    "outboundTag",
    "balancerTag",
];

/// The parts of a provider's Xray config that survive sanitising.
#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedXray {
    pub outbounds: Vec<Value>,
    pub routing: Option<Value>,
    pub remarks: Option<String>,
    pub observatory: Option<Value>,
    pub burst_observatory: Option<Value>,
    pub ingress_tags: Vec<String>,
    pub virtual_inbound_tags: Vec<String>,
    /// Paths of what was removed, for logs and tests.
    pub dropped: Vec<String>,
}

impl SanitizedXray {
    /// Emit the safe provider JSON representation for storage or wire encoding.
    /// Emits outbounds, routing, remarks, observatory / burstObservatory,
    /// and tag-only placeholder objects for inbounds (`[{"tag": ...}]`).
    pub fn into_provider_json(self) -> Value {
        let mut map = Map::new();
        map.insert("outbounds".into(), Value::Array(self.outbounds));
        if let Some(routing) = self.routing {
            map.insert("routing".into(), routing);
        }
        if let Some(remarks) = self.remarks {
            map.insert("remarks".into(), Value::String(remarks));
        }
        if let Some(obs) = self.observatory {
            map.insert("observatory".into(), obs);
        }
        if let Some(bobs) = self.burst_observatory {
            map.insert("burstObservatory".into(), bobs);
        }
        if !self.ingress_tags.is_empty() {
            let inbounds: Vec<Value> = self
                .ingress_tags
                .into_iter()
                .map(|tag| json!({ "tag": tag }))
                .collect();
            map.insert("inbounds".into(), Value::Array(inbounds));
        }
        Value::Object(map)
    }
}

/// Why a provider config can't be used at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizeError {
    NotObject,
    NoOutbounds,
    NoProxyOutbound,
    TooLarge,
    Incompatible { path: String, reason: &'static str },
}

impl fmt::Display for SanitizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SanitizeError::NotObject => f.write_str("not a JSON object"),
            SanitizeError::NoOutbounds => f.write_str("no outbounds"),
            SanitizeError::NoProxyOutbound => f.write_str("no proxy outbound"),
            SanitizeError::TooLarge => f.write_str("too large"),
            SanitizeError::Incompatible { path, reason } => {
                write!(f, "incompatible config at {path}: {reason}")
            }
        }
    }
}

impl std::error::Error for SanitizeError {}

/// Keep only the allowlisted parts of a provider's Xray config.
pub fn sanitize_provider_xray(v: &Value) -> Result<SanitizedXray, SanitizeError> {
    if exceeds(v, limits().max_body_bytes) {
        return Err(SanitizeError::TooLarge);
    }
    let top = v.as_object().ok_or(SanitizeError::NotObject)?;

    // Only record safe allowlisted categories in dropped; never echo unknown input keys
    let mut dropped: Vec<String> = Vec::new();
    for k in top.keys() {
        match k.as_str() {
            "log" | "api" | "stats" | "policy" | "reverse" | "dns" | "meta" => {
                dropped.push(k.clone());
            }
            "outbounds" | "routing" | "remarks" | "observatory" | "burstObservatory"
            | "inbounds" => {}
            _ => {
                if !dropped.contains(&"config".to_string()) {
                    dropped.push("config".into());
                }
            }
        }
    }

    // Ingress metadata
    let mut ingress_tags = Vec::new();
    let mut inbounds_had_listeners = false;
    if let Some(inbounds) = top.get("inbounds") {
        match inbounds.as_array() {
            Some(arr) => {
                for (i, inb) in arr.iter().enumerate() {
                    let Some(obj) = inb.as_object() else {
                        inbounds_had_listeners = true;
                        continue;
                    };
                    if obj.keys().any(|k| k != "tag") {
                        inbounds_had_listeners = true;
                    }
                    if let Some(tag) = obj.get("tag").and_then(Value::as_str) {
                        let tag = tag.trim();
                        if !tag.is_empty() {
                            if ingress_tags.contains(&tag.to_string()) {
                                return Err(SanitizeError::Incompatible {
                                    path: format!("inbounds[{i}].tag"),
                                    reason: "duplicate inbound tag",
                                });
                            }
                            ingress_tags.push(tag.to_string());
                        }
                    }
                }
            }
            None => {
                inbounds_had_listeners = true;
            }
        }
    }
    if inbounds_had_listeners && !dropped.contains(&"inbounds".to_string()) {
        dropped.push("inbounds".into());
    }

    // Outbounds
    let raw = top
        .get("outbounds")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(SanitizeError::NoOutbounds)?;

    let mut outbounds = Vec::new();
    let mut tags = HashSet::new();
    let mut virtual_inbound_tags = Vec::new();

    for (i, ob) in raw.iter().enumerate() {
        if let Some(ob) = sanitize_outbound(
            ob,
            i,
            &mut tags,
            &ingress_tags,
            &mut virtual_inbound_tags,
            &mut dropped,
        )? {
            outbounds.push(ob);
        }
    }

    // Cross-namespace collision check: real ingress vs virtual inbound
    for vtag in &virtual_inbound_tags {
        if ingress_tags.contains(vtag) {
            return Err(SanitizeError::Incompatible {
                path: "outbounds.settings.inboundTag".into(),
                reason: "virtual inbound tag collides with inbound tag",
            });
        }
    }

    // Validate outbound chaining references
    for (i, ob) in outbounds.iter_mut().enumerate() {
        validate_and_restrict_references(ob, i, &tags)?;
    }

    if outbounds.is_empty() {
        return Err(SanitizeError::NoOutbounds);
    }
    if outbounds.iter().all(|o| {
        is_service_outbound(o) || o.get("protocol").and_then(Value::as_str) == Some("loopback")
    }) {
        return Err(SanitizeError::NoProxyOutbound);
    }

    // Observatories: exactly one allowed for bounded implementation
    let has_obs = top.get("observatory").is_some();
    let has_burst = top.get("burstObservatory").is_some();
    if has_obs && has_burst {
        return Err(SanitizeError::Incompatible {
            path: "observatory".into(),
            reason: "cannot specify both observatory and burstObservatory",
        });
    }

    let observatory = if let Some(obs) = top.get("observatory") {
        Some(sanitize_observatory(obs, false, &outbounds, &tags)?)
    } else {
        None
    };

    let burst_observatory = if let Some(bobs) = top.get("burstObservatory") {
        Some(sanitize_observatory(bobs, true, &outbounds, &tags)?)
    } else {
        None
    };

    let has_any_observatory = observatory.is_some() || burst_observatory.is_some();

    // Routing
    let routing = top
        .get("routing")
        .map(|r| {
            sanitize_routing(
                r,
                &outbounds,
                &tags,
                &ingress_tags,
                &virtual_inbound_tags,
                has_any_observatory,
                &mut dropped,
            )
        })
        .transpose()?;

    let final_routing = routing.flatten();

    // Cycle & termination validation on the complete graph (unconditional, even if routing is None)
    let balancers = final_routing
        .as_ref()
        .and_then(|r| r.get("balancers"))
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let rules = final_routing
        .as_ref()
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    let vtags: HashSet<String> = virtual_inbound_tags.iter().cloned().collect();

    validate_routing_graph_acyclic(&outbounds, balancers, rules, &vtags)?;
    validate_balancer_observatory_coverage(
        balancers,
        &outbounds,
        observatory.as_ref(),
        burst_observatory.as_ref(),
    )?;

    let remarks = top
        .get("remarks")
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(SanitizedXray {
        outbounds,
        routing: final_routing,
        remarks,
        observatory,
        burst_observatory,
        ingress_tags,
        virtual_inbound_tags,
        dropped,
    })
}

/// True for an outbound that carries no traffic to a proxy server.
pub(crate) fn is_service_outbound(ob: &Value) -> bool {
    ob.get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|p| SERVICE_PROTOCOLS.contains(&p))
}

/// SHA-256 of a stored provider config's outbounds with their tags and REALITY
/// picks removed: a refresh that only renames tags, or draws another
/// `serverName`/`shortId` from the provider's pool, is still the same server.
pub fn provider_outbounds_identity(raw: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let mut outbounds = v.get("outbounds")?.as_array()?.clone();
    for ob in &mut outbounds {
        if let Some(o) = ob.as_object_mut() {
            o.remove("tag");
        }
        forget_reality_pick(ob);
    }
    let digest = Sha256::digest(Value::Array(outbounds).to_string().as_bytes());
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// True when two stored provider configs differ at most in their outbounds'
/// REALITY `serverName`/`shortId`.
pub fn differs_only_in_reality_pick(a: &str, b: &str) -> bool {
    let without_pick = |raw: &str| -> Option<Value> {
        let mut v: Value = serde_json::from_str(raw).ok()?;
        forget_reality_pick(v.get_mut("outbounds")?);
        Some(v)
    };
    matches!((without_pick(a), without_pick(b)), (Some(x), Some(y)) if x == y)
}

/// Every `realitySettings` counts, an xhttp download leg's included.
fn forget_reality_pick(v: &mut Value) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Object(r)) = m.get_mut("realitySettings") {
                r.remove("serverName");
                r.remove("shortId");
            }
            m.values_mut().for_each(forget_reality_pick);
        }
        Value::Array(a) => a.iter_mut().for_each(forget_reality_pick),
        _ => {}
    }
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

fn sanitize_observatory(
    obs: &Value,
    is_burst: bool,
    outbounds: &[Value],
    outbound_tags: &HashSet<String>,
) -> Result<Value, SanitizeError> {
    validate_observatory_config(obs, is_burst, outbounds, outbound_tags)?;
    let mut obj = obs.as_object().unwrap().clone();

    let prefixes: Vec<&str> = obj
        .get("subjectSelector")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();

    let mut members = Vec::new();
    for ob in outbounds {
        let tag = ob.get("tag").and_then(Value::as_str).unwrap_or("");
        if prefixes.iter().any(|p| tag.starts_with(p)) {
            members.push(Value::from(tag));
        }
    }
    obj.insert("subjectSelector".into(), Value::Array(members));
    Ok(Value::Object(obj))
}

fn sanitize_outbound(
    ob: &Value,
    i: usize,
    tags: &mut HashSet<String>,
    ingress_tags: &[String],
    virtual_inbound_tags: &mut Vec<String>,
    dropped: &mut Vec<String>,
) -> Result<Option<Value>, SanitizeError> {
    let path = format!("outbounds[{i}]");
    let Some(obj) = ob.as_object() else {
        dropped.push(path);
        return Ok(None);
    };
    let protocol = obj.get("protocol").and_then(Value::as_str).unwrap_or("");
    if !PROTOCOLS.contains(&protocol) {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.protocol"),
            reason: "unsupported outbound protocol",
        });
    }

    // Security: check local file paths in streamSettings
    if let Some(stream) = obj.get("streamSettings") {
        validate_stream_security(stream, &format!("{path}.streamSettings"))?;
    }

    let mut out = Map::new();
    for (k, val) in obj {
        let canonical = OUTBOUND_KEYS.iter().find(|c| c.eq_ignore_ascii_case(k));
        if let Some(&canon) = canonical {
            if k != canon {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.{canon}"),
                    reason: "non-canonical schema field alias",
                });
            }
            out.insert(k.clone(), val.clone());
        } else if !dropped.contains(&path) {
            dropped.push(path.clone());
        }
    }

    // Validate tag uniqueness
    match out.get("tag").map(|t| t.as_str().map(str::to_string)) {
        Some(Some(tag)) if !tag.is_empty() => {
            if tags.contains(&tag) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.tag"),
                    reason: "duplicate outbound tag",
                });
            }
            tags.insert(tag);
        }
        Some(_) => {
            out.remove("tag");
            let p = format!("{path}.tag");
            if !dropped.contains(&p) {
                dropped.push(p);
            }
        }
        None => {}
    }

    // Virtual loopback handling
    if protocol == "loopback" {
        let vtag_raw = out
            .get("settings")
            .and_then(|s| s.get("inboundTag"))
            .and_then(Value::as_str);

        let Some(vtag_raw) = vtag_raw else {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.settings.inboundTag"),
                reason: "loopback requires non-empty inboundTag",
            });
        };

        if vtag_raw.trim().is_empty() {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.settings.inboundTag"),
                reason: "loopback requires non-empty inboundTag",
            });
        }

        if vtag_raw != vtag_raw.trim() {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.settings.inboundTag"),
                reason: "inboundTag cannot contain leading or trailing whitespace",
            });
        }

        let vtag = vtag_raw;

        if ingress_tags.contains(&vtag.to_string()) {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.settings.inboundTag"),
                reason: "virtual inbound tag collides with inbound tag",
            });
        }

        if !virtual_inbound_tags.contains(&vtag.to_string()) {
            virtual_inbound_tags.push(vtag.to_string());
        }
    }

    if protocol == "freedom"
        && let Some(settings) = out.get_mut("settings").and_then(Value::as_object_mut)
    {
        settings.retain(|k, _| {
            let keep = FREEDOM_SETTINGS_KEYS.contains(&k.as_str());
            if !keep {
                let p = format!("{path}.settings.freedom");
                if !dropped.contains(&p) {
                    dropped.push(p);
                }
            }
            keep
        });
    }

    if let Some(stream) = out.get_mut("streamSettings") {
        strip_host_files(stream, &format!("{path}.streamSettings"), dropped);
        drop_pinned_allow_insecure(stream, &format!("{path}.streamSettings"), dropped);
    }

    Ok(Some(Value::Object(out)))
}

/// Whether some `tlsSettings` in `v` sets `allowInsecure` without a
/// `pinnedPeerCertSha256`. Xray refuses the key, and dropping it would turn the
/// certificate check back on, so no core can run such a config as written.
pub(crate) fn has_unpinned_allow_insecure(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.iter().any(|(k, child)| {
            (k == "tlsSettings" && allows_insecure(child) && !is_pinned(child))
                || has_unpinned_allow_insecure(child)
        }),
        Value::Array(a) => a.iter().any(has_unpinned_allow_insecure),
        _ => false,
    }
}

/// Drop `allowInsecure` from every `tlsSettings` in `v` that pins the peer
/// certificate. Xray refuses the key, and with a pin it already skips the CA
/// chain and accepts only the pinned certificate, so the key adds nothing.
pub(crate) fn drop_pinned_allow_insecure(v: &mut Value, path: &str, dropped: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                let child_path = if k == "tlsSettings" {
                    format!("{path}.tlsSettings")
                } else {
                    path.to_owned()
                };
                if k == "tlsSettings"
                    && allows_insecure(child)
                    && is_pinned(child)
                    && let Some(tls) = child.as_object_mut()
                {
                    tls.remove("allowInsecure");
                    dropped.push(format!("{child_path}.allowInsecure"));
                }
                drop_pinned_allow_insecure(child, &child_path, dropped);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter_mut().enumerate() {
                drop_pinned_allow_insecure(child, &format!("{path}[{i}]"), dropped);
            }
        }
        _ => {}
    }
}

fn allows_insecure(tls: &Value) -> bool {
    tls.get("allowInsecure") == Some(&Value::Bool(true))
}

fn is_pinned(tls: &Value) -> bool {
    tls.get("pinnedPeerCertSha256")
        .and_then(Value::as_str)
        .is_some_and(|pcs| !pcs.trim().is_empty())
}

/// Drop file keys (such as masterKeyLog) and reduce every sockopt to the allowlist.
fn strip_host_files(v: &mut Value, path: &str, dropped: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            m.retain(|k, _| {
                let keep = !FILE_KEYS.contains(&k.as_str());
                if !keep {
                    let p = format!("{path}.masterKeyLog");
                    if !dropped.contains(&p) {
                        dropped.push(p);
                    }
                }
                keep
            });
            for (k, child) in m.iter_mut() {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                let child_path = if is_sockopt_key(k) {
                    format!("{path}.sockopt")
                } else if k == "tlsSettings" {
                    format!("{path}.tlsSettings")
                } else {
                    path.to_owned()
                };
                if is_sockopt_key(k) {
                    match child.as_object_mut() {
                        Some(so) => so.retain(|sk, _| {
                            let keep = SOCKOPT_KEYS.contains(&sk.as_str());
                            if !keep {
                                let p = child_path.clone();
                                if !dropped.contains(&p) {
                                    dropped.push(p);
                                }
                            }
                            keep
                        }),
                        None => {
                            *child = Value::Object(Map::new());
                            if !dropped.contains(&child_path) {
                                dropped.push(child_path);
                            }
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
    k.to_ascii_lowercase().ends_with("sockopt")
}

/// Fail closed on dangling `proxySettings` or `dialerProxy` references.
fn validate_and_restrict_references(
    ob: &mut Value,
    i: usize,
    tags: &HashSet<String>,
) -> Result<(), SanitizeError> {
    let path = format!("outbounds[{i}]");
    if let Some(stream) = ob.get_mut("streamSettings") {
        validate_dialer_proxies(stream, &format!("{path}.streamSettings"), tags)?;
    }
    let Some(obj) = ob.as_object_mut() else {
        return Ok(());
    };
    if let Some(ps) = obj.get("proxySettings") {
        let tag = ps.get("tag").and_then(Value::as_str);
        match tag {
            Some(t) if tags.contains(t) => {
                let mut kept = Map::new();
                kept.insert("tag".into(), t.into());
                if let Some(tl) = ps.get("transportLayer").and_then(Value::as_bool) {
                    kept.insert("transportLayer".into(), tl.into());
                }
                obj.insert("proxySettings".into(), Value::Object(kept));
            }
            _ => {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.proxySettings.tag"),
                    reason: "references unknown outbound tag",
                });
            }
        }
    }
    Ok(())
}

fn sanitize_routing(
    routing: &Value,
    outbounds: &[Value],
    tags: &HashSet<String>,
    ingress_tags: &[String],
    virtual_inbound_tags: &[String],
    has_observatory: bool,
    dropped: &mut Vec<String>,
) -> Result<Option<Value>, SanitizeError> {
    let Some(obj) = routing.as_object() else {
        dropped.push("routing".into());
        return Ok(None);
    };
    let mut out = Map::new();
    for k in obj.keys() {
        if !["domainStrategy", "rules", "balancers"].contains(&k.as_str())
            && !dropped.contains(&"routing".to_string())
        {
            dropped.push("routing".into());
        }
    }
    if let Some(ds) = obj.get("domainStrategy").and_then(Value::as_str) {
        out.insert("domainStrategy".into(), ds.into());
    }

    let order: Vec<&str> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
    let mut balancer_tags = HashSet::new();

    let ingress_set: HashSet<String> = ingress_tags.iter().cloned().collect();
    let virtual_set: HashSet<String> = virtual_inbound_tags.iter().cloned().collect();

    let raw_balancers: Vec<&Value> = array_of(obj, "balancers").collect();
    let mut balancers = Vec::new();
    let mut cx = BalancerContext {
        order: &order,
        outbounds,
        outbound_tags: tags,
        balancer_tags: &mut balancer_tags,
        has_observatory,
    };
    for (i, b) in raw_balancers.into_iter().enumerate() {
        balancers.push(sanitize_balancer(b, i, &mut cx)?);
    }

    // Check multiple ingress tags referenced differently
    let raw_rules: Vec<&Value> = array_of(obj, "rules").collect();
    validate_ingress_references_across_rules(&raw_rules, ingress_tags)?;

    let mut rules = Vec::new();
    for (i, r) in raw_rules.into_iter().enumerate() {
        rules.push(sanitize_rule(
            r,
            i,
            tags,
            &balancer_tags,
            &ingress_set,
            &virtual_set,
        )?);
    }

    if !balancers.is_empty() {
        out.insert("balancers".into(), balancers.into());
    }
    if !rules.is_empty() {
        out.insert("rules".into(), rules.into());
    }
    Ok((!out.is_empty()).then_some(Value::Object(out)))
}

fn array_of<'a>(obj: &'a Map<String, Value>, key: &str) -> impl Iterator<Item = &'a Value> {
    obj.get(key).and_then(Value::as_array).into_iter().flatten()
}

struct BalancerContext<'a> {
    order: &'a [&'a str],
    outbounds: &'a [Value],
    outbound_tags: &'a HashSet<String>,
    balancer_tags: &'a mut HashSet<String>,
    has_observatory: bool,
}

fn sanitize_balancer(
    b: &Value,
    i: usize,
    cx: &mut BalancerContext<'_>,
) -> Result<Value, SanitizeError> {
    let path = format!("routing.balancers[{i}]");
    let tag = b
        .get("tag")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| SanitizeError::Incompatible {
            path: format!("{path}.tag"),
            reason: "balancer tag is missing",
        })?;

    if !cx.balancer_tags.insert(tag.to_string()) {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.tag"),
            reason: "duplicate balancer tag",
        });
    }

    let prefixes: Vec<&str> = b
        .get("selector")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();

    if prefixes.is_empty() || prefixes.iter().any(|p| p.trim().is_empty()) {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.selector"),
            reason: "empty selector prefix is unsupported",
        });
    }

    let members: Vec<Value> = cx
        .order
        .iter()
        .filter(|t| prefixes.iter().any(|p| t.starts_with(p)))
        .map(|t| Value::from(*t))
        .collect();

    if members.is_empty() {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.selector"),
            reason: "balancer selector matches no outbounds",
        });
    }
    if members.len() > MAX_SELECTOR_MEMBERS {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.selector"),
            reason: "balancer selector exceeds maximum members",
        });
    }

    // Candidate members must not match service or loopback outbounds
    for m in &members {
        let m_tag = m.as_str().unwrap_or("");
        if let Some(ob) = cx
            .outbounds
            .iter()
            .find(|o| o.get("tag").and_then(Value::as_str) == Some(m_tag))
        {
            let proto = ob.get("protocol").and_then(Value::as_str).unwrap_or("");
            if is_service_outbound(ob) || proto == "loopback" {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.selector"),
                    reason: "balancer selector matches service or loopback outbound",
                });
            }
        }
    }

    let mut out = Map::new();
    out.insert("tag".into(), tag.into());
    out.insert("selector".into(), members.into());

    if let Some(strategy) = b.get("strategy") {
        let strat_type = match strategy {
            Value::String(s) => Some(s.as_str()),
            Value::Object(o) => o.get("type").and_then(Value::as_str),
            _ => None,
        };
        let Some(t) = strat_type.filter(|t| BALANCER_STRATEGIES.contains(t)) else {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.strategy"),
                reason: "unsupported balancer strategy",
            });
        };
        if (t == "leastPing" || t == "leastLoad") && !cx.has_observatory {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.strategy"),
                reason: "leastPing and leastLoad strategies require an observatory",
            });
        }
        if t == "leastLoad" {
            let costs = strategy.get("settings").and_then(|s| s.get("costs"));
            if let Some(costs) = costs {
                let non_empty = match costs {
                    Value::Array(a) => !a.is_empty(),
                    Value::Object(o) => !o.is_empty(),
                    Value::Null => false,
                    _ => true,
                };
                if non_empty {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.strategy.settings.costs"),
                        reason: "unsupported tag-based balancing costs",
                    });
                }
            }
        }
        if let Some(obj) = strategy.as_object() {
            out.insert("strategy".into(), Value::Object(obj.clone()));
        } else {
            out.insert("strategy".into(), json!({ "type": t }));
        }
    }

    if let Some(fb) = b.get("fallbackTag") {
        if !cx.has_observatory {
            return Err(SanitizeError::Incompatible {
                path: format!("{path}.fallbackTag"),
                reason: "fallbackTag requires an observatory",
            });
        }
        let fb_tag = fb
            .as_str()
            .filter(|t| cx.outbound_tags.contains(*t))
            .ok_or(SanitizeError::Incompatible {
                path: format!("{path}.fallbackTag"),
                reason: "references unknown outbound tag",
            })?;
        out.insert("fallbackTag".into(), fb_tag.into());
    }

    Ok(Value::Object(out))
}

fn validate_ingress_references_across_rules(
    rules: &[&Value],
    ingress_tags: &[String],
) -> Result<(), SanitizeError> {
    let mut referenced_ingress = HashSet::new();
    for r in rules {
        if let Some(obj) = r.as_object()
            && let Some(inb) = obj.get("inboundTag")
        {
            let tags: Vec<&str> = match inb {
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                Value::String(s) => vec![s.as_str()],
                _ => Vec::new(),
            };
            for t in tags {
                if ingress_tags.iter().any(|it| it == t) {
                    referenced_ingress.insert(t.to_string());
                }
            }
        }
    }
    if referenced_ingress.len() > 1 {
        return Err(SanitizeError::Incompatible {
            path: "routing.rules".into(),
            reason: "multiple ingress tags referenced with different routing",
        });
    }
    Ok(())
}

fn sanitize_rule(
    r: &Value,
    i: usize,
    outbound_tags: &HashSet<String>,
    balancer_tags: &HashSet<String>,
    ingress_tags: &HashSet<String>,
    virtual_inbound_tags: &HashSet<String>,
) -> Result<Value, SanitizeError> {
    let path = format!("routing.rules[{i}]");
    let Some(obj) = r.as_object() else {
        return Err(SanitizeError::Incompatible {
            path,
            reason: "rule must be a JSON object",
        });
    };

    // Fail closed on unsupported condition keys to prevent broadening rule match
    for k in obj.keys() {
        if !RULE_KEYS.contains(&k.as_str()) {
            return Err(SanitizeError::Incompatible {
                path,
                reason: "unsupported rule condition",
            });
        }
    }

    // Validate value types of conditions
    for (k, val) in obj {
        match k.as_str() {
            "type" if val.as_str() != Some("field") => {
                return Err(SanitizeError::Incompatible {
                    path: path.clone(),
                    reason: "invalid rule condition value",
                });
            }
            "network" => {
                let ok = match val {
                    Value::String(s) => {
                        !s.is_empty()
                            && s.split(',').all(|network| matches!(network, "tcp" | "udp"))
                    }
                    Value::Array(a) => a.iter().all(|item| {
                        if let Some(s) = item.as_str() {
                            matches!(s, "tcp" | "udp")
                        } else {
                            false
                        }
                    }),
                    _ => false,
                };
                if !ok {
                    return Err(SanitizeError::Incompatible {
                        path: path.clone(),
                        reason: "invalid rule condition value",
                    });
                }
            }
            "port" | "sourcePort" => {
                let ok = match val {
                    Value::String(s) => !s.trim().is_empty(),
                    Value::Number(_) => true,
                    Value::Array(a) => a.iter().all(|item| item.is_string() || item.is_number()),
                    _ => false,
                };
                if !ok {
                    return Err(SanitizeError::Incompatible {
                        path: path.clone(),
                        reason: "invalid rule condition value",
                    });
                }
            }
            "inboundTag" => {
                let ok = match val {
                    Value::String(s) => !s.trim().is_empty(),
                    Value::Array(a) => {
                        !a.is_empty()
                            && a.iter()
                                .all(|item| item.as_str().is_some_and(|s| !s.trim().is_empty()))
                    }
                    _ => false,
                };
                if !ok {
                    return Err(SanitizeError::Incompatible {
                        path: path.clone(),
                        reason: "invalid rule condition value",
                    });
                }
            }
            "domain" | "domains" | "ip" | "protocol" => {
                let ok = match val {
                    Value::Array(a) => a.iter().all(|item| item.is_string()),
                    _ => false,
                };
                if !ok {
                    return Err(SanitizeError::Incompatible {
                        path: path.clone(),
                        reason: "invalid rule condition value",
                    });
                }
            }
            _ => {}
        }
    }

    let ob_target = obj.get("outboundTag").and_then(Value::as_str);
    let bal_target = obj.get("balancerTag").and_then(Value::as_str);

    if ob_target.is_some() && bal_target.is_some() {
        return Err(SanitizeError::Incompatible {
            path,
            reason: "rule cannot specify both outboundTag and balancerTag",
        });
    }
    if ob_target.is_none() && bal_target.is_none() {
        return Err(SanitizeError::Incompatible {
            path,
            reason: "rule target is missing",
        });
    }

    if let Some(ot) = ob_target
        && !outbound_tags.contains(ot)
    {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.outboundTag"),
            reason: "references unknown outbound tag",
        });
    }
    if let Some(bt) = bal_target
        && !balancer_tags.contains(bt)
    {
        return Err(SanitizeError::Incompatible {
            path: format!("{path}.balancerTag"),
            reason: "references unknown balancer tag",
        });
    }

    let mut out = Map::new();
    for (k, val) in obj {
        if RULE_KEYS.contains(&k.as_str()) {
            out.insert(k.clone(), val.clone());
        }
    }

    // Validate inboundTag internal references
    if let Some(inb) = out.get("inboundTag") {
        let inb_tags: Vec<&str> = match inb {
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            Value::String(s) => vec![s.as_str()],
            _ => Vec::new(),
        };
        for t in inb_tags {
            if !virtual_inbound_tags.contains(t) && !ingress_tags.contains(t) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.inboundTag"),
                    reason: "references unknown inbound tag",
                });
            }
        }
    }

    if !xray_rule_has_condition(&out) {
        return Err(SanitizeError::Incompatible {
            path,
            reason: "rule has no valid condition",
        });
    }

    Ok(Value::Object(out))
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

    fn loopback(tag: &str, inbound_tag: &str) -> Value {
        json!({
            "tag": tag, "protocol": "loopback",
            "settings": { "inboundTag": inbound_tag },
        })
    }

    fn obs() -> Value {
        json!({
            "subjectSelector": ["prox"],
            "probeUrl": "https://www.example.com/generate_204",
            "probeInterval": "10s",
        })
    }

    fn burst_obs() -> Value {
        json!({
            "subjectSelector": ["prox"],
            "pingConfig": {
                "destination": "https://www.example.com/generate_204",
                "interval": "10s",
                "timeout": "5s",
                "sampling": 10,
            }
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
                .contains(&"outbounds[0].streamSettings.sockopt".to_string())
        );
        assert!(
            out.dropped
                .contains(&"outbounds[0].streamSettings.tlsSettings.masterKeyLog".to_string())
        );
    }

    #[test]
    fn certificate_file_fails_closed() {
        let mut ob = vless("proxy");
        ob["streamSettings"]["tlsSettings"] = json!({
            "serverName": "srv.example",
            "certificates": [{ "certificateFile": "/data/adb/kasumi-proxy/state.json", "usage": "verify" }],
        });
        let res = sanitize_provider_xray(&json!({ "outbounds": [ob] }));
        assert!(matches!(
            res,
            Err(SanitizeError::Incompatible { path, reason })
            if path.contains("certificateFile") && reason == "local certificate files are unsupported"
        ));
    }

    #[test]
    fn dialer_proxy_resolves_and_dangling_fails_closed() {
        let mut exit = vless("exit");
        exit["streamSettings"]["sockopt"] = json!({ "dialerProxy": "entry" });
        let out = sanitize(json!({ "outbounds": [exit, vless("entry")] }));
        assert_eq!(
            out.outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
            "entry"
        );

        let mut stray = vless("stray");
        stray["streamSettings"]["sockopt"] = json!({ "dialerProxy": "elsewhere" });
        let res = sanitize_provider_xray(&json!({ "outbounds": [stray, vless("entry")] }));
        assert!(matches!(
            res,
            Err(SanitizeError::Incompatible { path, reason })
            if path.contains("dialerProxy") && reason == "references unknown outbound tag"
        ));
    }

    #[test]
    fn dialer_proxy_cycle_without_routing_fails_closed() {
        // Cycle check must run even if routing key is omitted
        let mut a = vless("a");
        a["streamSettings"]["sockopt"] = json!({ "dialerProxy": "b" });
        let mut b = vless("b");
        b["streamSettings"]["sockopt"] = json!({ "dialerProxy": "a" });
        let res = sanitize_provider_xray(&json!({ "outbounds": [a, b] }));
        assert!(matches!(
            res,
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing" && reason == "unsupported routing cycle/structure"
        ));
    }

    #[test]
    fn canonical_probe_url_spelling_and_safety() {
        // Canonical probeURL with private IP must be rejected
        let v = json!({
            "observatory": {
                "subjectSelector": ["prox"],
                "probeURL": "http://127.0.0.1:8080/x",
            },
            "outbounds": [vless("proxy")],
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "observatory.probeURL" && reason == "invalid probe URL"
        ));

        // Ambiguous conflicting probeURL and probeUrl must be rejected
        let v_conflict = json!({
            "observatory": {
                "subjectSelector": ["prox"],
                "probeURL": "https://example.com/a",
                "probeUrl": "https://example.com/b",
            },
            "outbounds": [vless("proxy")],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_conflict),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "observatory.probeURL" && reason == "ambiguous probe URL fields"
        ));
    }

    #[test]
    fn tag_collisions_order_independent() {
        // Cross-domain spelling (outbound tag equals virtual inbound tag) is ALLOWED
        let v_cross = json!({
            "outbounds": [
                loopback("l", "v"),
                vless("v"),
            ],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["v"], "outboundTag": "v" }
                ]
            }
        });
        assert!(sanitize_provider_xray(&v_cross).is_ok());

        // Real ingress vs virtual inbound collision is REJECTED
        let v_inbound_collision = json!({
            "inbounds": [{ "tag": "shared-in", "listen": "127.0.0.1", "port": 1080 }],
            "outbounds": [
                loopback("l", "shared-in"),
                vless("proxy"),
            ],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_inbound_collision),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "outbounds[0].settings.inboundTag" && reason == "virtual inbound tag collides with inbound tag"
        ));
    }

    #[test]
    fn random_balancer_with_fallback_requires_observed_candidates() {
        let v = json!({
            "observatory": {
                "subjectSelector": ["prox"],
                "probeUrl": "https://www.example.com/generate_204",
            },
            "outbounds": [vless("proxy"), vless("unobserved"), { "tag": "direct", "protocol": "freedom" }],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["unobs"], "strategy": { "type": "random" }, "fallbackTag": "direct" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.balancers[0].strategy" && reason == "balancer members not covered by observatory"
        ));
    }

    #[test]
    fn least_load_costs_rejected() {
        let v_costs = json!({
            "observatory": obs(),
            "outbounds": [vless("proxy")],
            "routing": {
                "balancers": [
                    {
                        "tag": "lb",
                        "selector": ["prox"],
                        "strategy": {
                            "type": "leastLoad",
                            "settings": {
                                "costs": [{ "regexp": ".*", "value": 1 }]
                            }
                        }
                    }
                ]
            }
        });
        assert!(matches!(
            sanitize_provider_xray(&v_costs),
            Err(SanitizeError::Incompatible { path, reason })
            if path.contains("costs") && reason == "unsupported tag-based balancing costs"
        ));
    }

    #[test]
    fn non_canonical_outbound_key_alias_rejected() {
        let mut ob = vless("proxy");
        ob["ProxySettings"] = json!({ "tag": "proxy" });
        let v = json!({ "outbounds": [ob] });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { reason, .. })
            if reason == "non-canonical schema field alias"
        ));
    }

    #[test]
    fn whitespace_in_loopback_inbound_tag_rejected() {
        let v = json!({
            "outbounds": [
                { "tag": "l", "protocol": "loopback", "settings": { "inboundTag": "  v-in  " } },
                vless("proxy"),
            ]
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "outbounds[0].settings.inboundTag" && reason == "inboundTag cannot contain leading or trailing whitespace"
        ));
    }

    #[test]
    fn least_ping_rejects_unobserved_candidates() {
        // Balancer members not covered by observatory's subjectSelector
        let v = json!({
            "observatory": {
                "subjectSelector": ["prox"],
                "probeUrl": "https://www.example.com/generate_204",
            },
            "outbounds": [vless("proxy"), vless("unobserved")],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["unobs"], "strategy": { "type": "leastPing" } },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.balancers[0].strategy" && reason == "balancer members not covered by observatory"
        ));
    }

    #[test]
    fn secret_keys_and_protocols_never_interpolated() {
        let v_key = json!({
            "secret_token_key": "private_secret_value",
            "outbounds": [vless("proxy")],
            "routing": {
                "rules": [
                    { "type": "field", "secret_condition_key": "some_val", "outboundTag": "proxy" }
                ]
            }
        });
        let err = sanitize_provider_xray(&v_key).unwrap_err();
        let formatted = err.to_string();
        assert!(!formatted.contains("secret_token_key"), "{formatted}");
        assert!(!formatted.contains("secret_condition_key"), "{formatted}");
        assert!(!formatted.contains("private_secret_value"), "{formatted}");

        let v_proto = json!({
            "outbounds": [{
                "tag": "bad",
                "protocol": "secret_protocol_name",
            }, vless("proxy")],
        });
        let err_proto = sanitize_provider_xray(&v_proto).unwrap_err();
        let formatted_proto = err_proto.to_string();
        assert!(
            !formatted_proto.contains("secret_protocol_name"),
            "{formatted_proto}"
        );
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
            sanitize_provider_xray(&json!([1])),
            Err(SanitizeError::NotObject)
        );
    }

    #[test]
    fn rejects_only_freedom_or_loopback() {
        let v = json!({ "outbounds": [
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "dns", "protocol": "dns" },
        ]});
        assert_eq!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::NoProxyOutbound)
        );

        let v_loop = json!({ "outbounds": [
            loopback("lb", "v-in"),
            { "tag": "direct", "protocol": "freedom" },
        ]});
        assert_eq!(
            sanitize_provider_xray(&v_loop),
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
    fn preserves_least_ping_and_fallback_with_observatory() {
        let out = sanitize(json!({
            "observatory": {
                "subjectSelector": ["prox", "back"],
                "probeUrl": "https://www.example.com/generate_204",
                "probeInterval": "10s",
            },
            "outbounds": [vless("proxy"), vless("backup"), { "tag": "direct", "protocol": "freedom" }],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["prox"], "strategy": { "type": "leastPing" }, "fallbackTag": "direct" },
                ],
                "rules": [
                    { "type": "field", "domain": ["geosite:ru"], "outboundTag": "direct" },
                    { "type": "field", "ip": ["1.1.1.1"], "balancerTag": "lb" },
                ],
            },
        }));
        assert!(out.observatory.is_some());
        let routing = out.routing.unwrap();
        assert_eq!(
            routing["balancers"],
            json!([{
                "tag": "lb",
                "selector": ["proxy"],
                "strategy": { "type": "leastPing" },
                "fallbackTag": "direct",
            }])
        );
        let rules = routing["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn rejects_least_load_or_fallback_without_observatory() {
        let v = json!({
            "outbounds": [vless("proxy"), vless("backup")],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["prox"], "strategy": { "type": "leastLoad" } },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path.contains("strategy") && reason.contains("require an observatory")
        ));

        let v_fb = json!({
            "outbounds": [vless("proxy"), vless("backup")],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["prox"], "fallbackTag": "backup" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v_fb),
            Err(SanitizeError::Incompatible { path, reason })
            if path.contains("fallbackTag") && reason.contains("requires an observatory")
        ));
    }

    #[test]
    fn loopback_and_inbound_tag_reentry() {
        let out = sanitize(json!({
            "observatory": obs(),
            "outbounds": [
                vless("proxy"),
                vless("backup"),
                loopback("loop-entry", "virtual-in"),
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["prox"], "fallbackTag": "loop-entry" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["virtual-in"], "outboundTag": "backup" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "lb" },
                ],
            },
        }));
        assert_eq!(out.virtual_inbound_tags, vec!["virtual-in"]);
        let rules = out.routing.unwrap()["rules"].as_array().unwrap().clone();
        assert_eq!(rules[0]["inboundTag"], json!(["virtual-in"]));
        assert_eq!(rules[0]["outboundTag"], "backup");
    }

    #[test]
    fn rejects_cycle_in_loopback_routing() {
        let v = json!({
            "outbounds": [
                vless("proxy"),
                loopback("loop-a", "virtual-a"),
                loopback("loop-b", "virtual-b"),
            ],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["virtual-a"], "outboundTag": "loop-b" },
                    { "type": "field", "inboundTag": ["virtual-b"], "outboundTag": "loop-a" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing" && reason == "unsupported routing cycle/structure"
        ));
    }

    #[test]
    fn accepts_acyclic_fallback_chain() {
        let mut observer = obs();
        observer["subjectSelector"] = json!(["main", "secondary"]);
        let out = sanitize(json!({
            "observatory": observer,
            "outbounds": [
                vless("main-proxy"),
                vless("secondary-proxy"),
                loopback("loop-to-sec", "in-sec"),
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb-main", "selector": ["main"], "fallbackTag": "loop-to-sec" },
                    { "tag": "lb-sec", "selector": ["secondary"] },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["in-sec"], "network": "tcp,udp", "balancerTag": "lb-sec" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "lb-main" },
                ],
            },
        }));
        assert_eq!(out.virtual_inbound_tags, vec!["in-sec"]);
    }

    #[test]
    fn rejects_duplicate_outbound_tags() {
        let v = json!({ "outbounds": [vless("a"), vless("a")] });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "outbounds[1].tag" && reason == "duplicate outbound tag"
        ));
    }

    #[test]
    fn rejects_both_observatories() {
        let v = json!({
            "observatory": obs(),
            "burstObservatory": burst_obs(),
            "outbounds": [vless("proxy")],
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "observatory" && reason == "cannot specify both observatory and burstObservatory"
        ));
    }

    #[test]
    fn rejects_burst_connectivity() {
        let mut bobs = burst_obs();
        bobs["pingConfig"]["connectivity"] =
            "https://connectivitycheck.gstatic.com/generate_204".into();
        let v = json!({
            "burstObservatory": bobs,
            "outbounds": [vless("proxy")],
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path.contains("connectivity") && reason == "unsupported burst connectivity check"
        ));
    }

    #[test]
    fn roundtrip_into_provider_json() {
        let original = json!({
            "burstObservatory": burst_obs(),
            "inbounds": [{ "tag": "socks-in", "listen": "127.0.0.1", "port": 1080 }],
            "outbounds": [
                vless("proxy"),
                loopback("loop", "virtual-in"),
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["prox"], "fallbackTag": "loop" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["virtual-in"], "outboundTag": "proxy" },
                    { "type": "field", "inboundTag": ["socks-in"], "balancerTag": "lb" },
                ],
            },
            "remarks": "Test Remarks",
        });

        let sanitized = sanitize_provider_xray(&original).unwrap();
        assert_eq!(sanitized.ingress_tags, vec!["socks-in"]);
        assert_eq!(sanitized.virtual_inbound_tags, vec!["virtual-in"]);

        let encoded = sanitized.clone().into_provider_json();
        let roundtrip = sanitize_provider_xray(&encoded).unwrap();

        assert_eq!(roundtrip.outbounds, sanitized.outbounds);
        assert_eq!(roundtrip.routing, sanitized.routing);
        assert_eq!(roundtrip.remarks, sanitized.remarks);
        assert_eq!(roundtrip.observatory, sanitized.observatory);
        assert_eq!(roundtrip.burst_observatory, sanitized.burst_observatory);
        assert_eq!(roundtrip.ingress_tags, sanitized.ingress_tags);
        assert_eq!(
            roundtrip.virtual_inbound_tags,
            sanitized.virtual_inbound_tags
        );
        assert!(roundtrip.dropped.is_empty());
    }

    #[test]
    fn identity_ignores_only_the_reality_pick() {
        let a = reality_config("a.sni.example", "aa", "PK");
        let b = reality_config("b.sni.example", "bb", "PK");
        let other_key = reality_config("a.sni.example", "aa", "PK2");
        assert_eq!(
            provider_outbounds_identity(&a),
            provider_outbounds_identity(&b)
        );
        assert_ne!(
            provider_outbounds_identity(&a),
            provider_outbounds_identity(&other_key)
        );
        assert!(differs_only_in_reality_pick(&a, &b));
        assert!(!differs_only_in_reality_pick(&a, &other_key));
        assert!(!differs_only_in_reality_pick(&a, "not json"));
    }

    fn reality_config(sni: &str, sid: &str, public_key: &str) -> String {
        let reality = json!({ "serverName": sni, "shortId": sid, "publicKey": public_key });
        let mut ob = vless("proxy");
        ob["streamSettings"] = json!({
            "network": "xhttp", "security": "reality", "realitySettings": reality,
            "xhttpSettings": { "extra": { "downloadSettings": {
                "security": "reality", "realitySettings": reality,
            }}},
        });
        json!({ "outbounds": [ob, { "tag": "direct", "protocol": "freedom" }] }).to_string()
    }

    fn insecure_tls(pin: Option<&str>) -> Value {
        let mut tls = json!({ "serverName": "srv.example", "allowInsecure": true });
        if let Some(pin) = pin {
            tls["pinnedPeerCertSha256"] = pin.into();
        }
        tls
    }

    #[test]
    fn pinned_allow_insecure_is_dropped() {
        let mut ob = vless("proxy");
        ob["streamSettings"]["tlsSettings"] = insecure_tls(Some("aabb"));
        ob["streamSettings"]["xhttpSettings"] = json!({ "extra": { "downloadSettings": {
            "security": "tls", "tlsSettings": insecure_tls(Some("ccdd")),
        }}});
        let out = sanitize(json!({ "outbounds": [ob] }));
        assert!(!has_unpinned_allow_insecure(&Value::from(
            out.outbounds.clone()
        )));
        let stream = &out.outbounds[0]["streamSettings"];
        assert_eq!(
            stream["tlsSettings"],
            json!({ "serverName": "srv.example", "pinnedPeerCertSha256": "aabb" })
        );
        let leg = &stream["xhttpSettings"]["extra"]["downloadSettings"]["tlsSettings"];
        assert!(leg.get("allowInsecure").is_none(), "{leg}");
        assert!(
            out.dropped
                .contains(&"outbounds[0].streamSettings.tlsSettings.allowInsecure".to_string())
        );
    }

    #[test]
    fn unpinned_allow_insecure_is_kept_and_reported() {
        let mut ob = vless("proxy");
        ob["streamSettings"]["tlsSettings"] = insecure_tls(Some(" "));
        let out = sanitize(json!({ "outbounds": [vless("other"), ob] }));
        assert_eq!(
            out.outbounds[1]["streamSettings"]["tlsSettings"]["allowInsecure"],
            true
        );
        assert!(has_unpinned_allow_insecure(&Value::from(out.outbounds)));

        let mut checked = vless("proxy");
        checked["streamSettings"]["tlsSettings"] = json!({ "allowInsecure": false });
        assert!(!has_unpinned_allow_insecure(&checked));
    }

    #[test]
    fn rejects_multiple_different_ingress_tags_in_rules() {
        let v = json!({
            "inbounds": [
                { "tag": "in-socks", "listen": "127.0.0.1", "port": 1080 },
                { "tag": "in-http", "listen": "127.0.0.1", "port": 8080 },
            ],
            "outbounds": [vless("p1"), vless("p2")],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["in-socks"], "outboundTag": "p1" },
                    { "type": "field", "inboundTag": ["in-http"], "outboundTag": "p2" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.rules" && reason == "multiple ingress tags referenced with different routing"
        ));
    }

    #[test]
    fn accepts_single_ingress_tag_referenced_in_rules() {
        let v = json!({
            "inbounds": [
                { "tag": "in-socks", "listen": "127.0.0.1", "port": 1080 },
                { "tag": "in-unused", "listen": "127.0.0.1", "port": 8080 },
            ],
            "outbounds": [vless("p1")],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["in-socks"], "outboundTag": "p1" },
                ],
            },
        });
        let out = sanitize(v);
        assert_eq!(out.ingress_tags, vec!["in-socks", "in-unused"]);
        let rules = out.routing.unwrap()["rules"].as_array().unwrap().clone();
        assert_eq!(rules[0]["inboundTag"], json!(["in-socks"]));
    }

    #[test]
    fn rejects_unsupported_rule_conditions() {
        let v = json!({
            "outbounds": [vless("proxy")],
            "routing": {
                "rules": [
                    { "type": "field", "user": ["admin@example.com"], "outboundTag": "proxy" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.rules[0]" && reason == "unsupported rule condition"
        ));
    }

    #[test]
    fn rejects_unknown_rule_targets() {
        let v = json!({
            "outbounds": [vless("proxy")],
            "routing": {
                "rules": [
                    { "type": "field", "network": "tcp", "outboundTag": "nonexistent" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.rules[0].outboundTag" && reason == "references unknown outbound tag"
        ));
    }

    #[test]
    fn rejects_unknown_inbound_tag_in_rule() {
        let v = json!({
            "outbounds": [vless("proxy")],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["unknown-inbound"], "outboundTag": "proxy" },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.rules[0].inboundTag" && reason == "references unknown inbound tag"
        ));
    }

    #[test]
    fn rejects_balancer_empty_selector_matches() {
        let v = json!({
            "outbounds": [vless("proxy")],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["nomatch"] },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.balancers[0].selector" && reason == "balancer selector matches no outbounds"
        ));
    }

    #[test]
    fn rejects_duplicate_balancer_tag() {
        let v = json!({
            "outbounds": [vless("proxy")],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["proxy"] },
                    { "tag": "lb", "selector": ["proxy"] },
                ],
            },
        });
        assert!(matches!(
            sanitize_provider_xray(&v),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing.balancers[1].tag" && reason == "duplicate balancer tag"
        ));
    }

    #[test]
    fn rejects_loopback_invalid_inbound_tag() {
        let v_empty = json!({
            "outbounds": [
                vless("proxy"),
                { "tag": "l1", "protocol": "loopback", "settings": { "inboundTag": "  " } },
            ],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_empty),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "outbounds[1].settings.inboundTag" && reason == "loopback requires non-empty inboundTag"
        ));

        let v_collides = json!({
            "inbounds": [{ "tag": "in-1", "listen": "127.0.0.1", "port": 1080 }],
            "outbounds": [
                vless("proxy"),
                loopback("l1", "in-1"),
            ],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_collides),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "outbounds[1].settings.inboundTag" && reason == "virtual inbound tag collides with inbound tag"
        ));
    }

    #[test]
    fn rejects_observatory_invalid_selectors_or_resources() {
        // Selector matching freedom outbound
        let v_freedom = json!({
            "observatory": {
                "subjectSelector": ["dir"],
                "probeUrl": "https://www.example.com/generate_204",
            },
            "outbounds": [vless("proxy"), { "tag": "direct", "protocol": "freedom" }],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_freedom),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "observatory.subjectSelector" && reason == "observatory selector matches service or loopback outbound"
        ));

        // Sub 10s interval
        let v_interval = json!({
            "observatory": {
                "subjectSelector": ["prox"],
                "probeUrl": "https://www.example.com/generate_204",
                "probeInterval": "5s",
            },
            "outbounds": [vless("proxy")],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_interval),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "observatory.probeInterval" && reason == "probe interval below minimum"
        ));

        // Burst sampling > 20
        let v_sampling = json!({
            "burstObservatory": {
                "subjectSelector": ["prox"],
                "pingConfig": {
                    "destination": "https://www.example.com/generate_204",
                    "sampling": 25,
                },
            },
            "outbounds": [vless("proxy")],
        });
        assert!(matches!(
            sanitize_provider_xray(&v_sampling),
            Err(SanitizeError::Incompatible { path, reason })
            if path == "burstObservatory.pingConfig.sampling" && reason == "burst sampling exceeds maximum"
        ));
    }

    #[test]
    fn accepts_real_cascade_fixture_structure() {
        let obs = json!({
            "subjectSelector": ["node-de", "node-lte"],
            "pingConfig": {
                "destination": "https://www.example.com/generate_204",
                "interval": "1m",
                "timeout": "5s",
                "sampling": 5,
            }
        });
        let fixture = json!({
            "burstObservatory": obs,
            "inbounds": [
                { "tag": "socks-in", "listen": "127.0.0.1", "port": 1080 },
                { "tag": "http-in", "listen": "127.0.0.1", "port": 8080 }
            ],
            "outbounds": [
                vless("node-de"),
                vless("node-lte"),
                loopback("loop-sticky", "v-sticky"),
                loopback("loop-main", "v-main"),
                loopback("loop-lte", "v-lte"),
                { "tag": "direct", "protocol": "freedom" }
            ],
            "routing": {
                "balancers": [
                    { "tag": "bal-all", "selector": ["node"], "fallbackTag": "direct" },
                    { "tag": "bal-lte", "selector": ["node-lte"], "fallbackTag": "direct" },
                    { "tag": "bal-main", "selector": ["node-de"], "fallbackTag": "loop-lte" },
                    { "tag": "bal-sticky", "selector": ["node-de"], "strategy": { "type": "leastLoad" }, "fallbackTag": "loop-main" }
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["v-lte"], "balancerTag": "bal-all" },
                    { "type": "field", "inboundTag": ["v-main"], "balancerTag": "bal-lte" },
                    { "type": "field", "inboundTag": ["v-sticky"], "balancerTag": "bal-main" },
                    { "type": "field", "inboundTag": ["socks-in"], "balancerTag": "bal-sticky" }
                ]
            }
        });
        let sanitized = sanitize_provider_xray(&fixture).unwrap();
        assert_eq!(sanitized.virtual_inbound_tags.len(), 3);
        let roundtrip = sanitize_provider_xray(&sanitized.into_provider_json()).unwrap();
        assert_eq!(roundtrip.virtual_inbound_tags.len(), 3);
    }
}
