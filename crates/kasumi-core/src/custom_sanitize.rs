//! Reduce a subscription provider's Xray JSON to the part Kasumi lets a provider
//! decide: its outbounds and the routing between them. The core runs as root on
//! Android, so whatever reaches the host is dropped, not trusted: log file paths
//! (root file writes), inbounds (listeners), `api`/`stats`/`policy` (a gRPC
//! control plane), `reverse` (tunnels in), TLS key-log and certificate paths, and
//! socket marks or interface binds that escape Kasumi's fwmark/uid routing.

use std::fmt;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::provider_graph::{ProviderFragment, validate_stream_security};
use crate::sub_ingest::limits;

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
const FILE_KEYS: [&str; 1] = ["masterKeyLog"];
/// `redirect` is left out: it could point the user's traffic at local services.
const FREEDOM_SETTINGS_KEYS: [&str; 3] = ["domainStrategy", "fragment", "noises"];

/// The parts of a provider's Xray config that survive sanitising.
#[derive(Debug, Clone, PartialEq)]
pub struct SanitizedXray {
    pub outbounds: Vec<Value>,
    pub routing: Option<Value>,
    pub remarks: Option<String>,
    pub observatory: Option<Value>,
    pub burst_observatory: Option<Value>,
    pub ingress_tags: Vec<String>,
    /// Paths of what was removed, for logs and tests.
    pub dropped: Vec<String>,
    pub fragment: ProviderFragment,
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
            SanitizeError::Incompatible { path, reason } => write!(f, "{path}: {reason}"),
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
    let mut dropped: Vec<String> = top
        .keys()
        .filter(|k| {
            ![
                "outbounds",
                "routing",
                "remarks",
                "observatory",
                "burstObservatory",
                "inbounds",
            ]
            .contains(&k.as_str())
        })
        .cloned()
        .collect();

    let mut ingress_tags = Vec::new();
    if let Some(inbounds) = top.get("inbounds").and_then(Value::as_array) {
        if !dropped.contains(&"inbounds".to_string()) {
            dropped.push("inbounds".to_string());
        }
        for inbound in inbounds {
            if let Some(tag) = inbound.get("tag").and_then(Value::as_str)
                && !tag.trim().is_empty()
                && !ingress_tags.contains(&tag.to_string())
            {
                ingress_tags.push(tag.to_string());
            }
        }
    }

    let raw = top
        .get("outbounds")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or(SanitizeError::NoOutbounds)?;

    let mut outbounds = Vec::new();
    for (i, ob) in raw.iter().enumerate() {
        if let Some(ob) = sanitize_outbound(ob, i, &mut dropped)? {
            outbounds.push(ob);
        }
    }

    if outbounds.is_empty() {
        return Err(SanitizeError::NoOutbounds);
    }
    if outbounds.iter().all(is_service_outbound) {
        return Err(SanitizeError::NoProxyOutbound);
    }

    let routing = top.get("routing");
    let remarks = top
        .get("remarks")
        .and_then(Value::as_str)
        .map(str::to_string);
    let observatory = top.get("observatory");
    let burst_observatory = top.get("burstObservatory");

    let fragment = ProviderFragment::build(
        outbounds,
        routing,
        observatory,
        burst_observatory,
        &ingress_tags,
    )?;

    for warning in &fragment.dropped_warnings {
        if !dropped.contains(warning) {
            dropped.push(warning.clone());
        }
    }

    let sanitized_outbounds: Vec<Value> =
        fragment.outbounds.iter().map(|o| o.raw.clone()).collect();

    Ok(SanitizedXray {
        outbounds: sanitized_outbounds,
        routing: routing.cloned(),
        remarks,
        observatory: observatory.cloned(),
        burst_observatory: burst_observatory.cloned(),
        ingress_tags,
        dropped,
        fragment,
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

fn sanitize_outbound(
    ob: &Value,
    i: usize,
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

fn strip_host_files(v: &mut Value, path: &str, dropped: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            m.retain(|k, _| {
                if k.eq_ignore_ascii_case("headers") {
                    return true;
                }
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
