//! Safe, dependency-aware validation of provider Xray configuration graphs.
//!
//! Preserves provider internal routing (virtual loopback / `inboundTag` re-entry,
//! balancers with `leastLoad`/`leastPing` and observatories, strategy settings,
//! and fallback chains) while enforcing strict boundaries:
//! - No host filesystem file access (`certificateFile`, `keyFile`).
//! - No platform-level socket controls or listening sockets.
//! - Closed failure on dangling chain hops, unknown tags, or ambiguous ingress.
//! - Bounded observation resource limits and routed probe URL safety.
//! - Iterative DFS cycle detection with explicit node and depth limits.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;
use url::Url;

use crate::custom_sanitize::{SanitizeError, is_service_outbound};

/// Supported balancer routing strategies.
pub const BALANCER_STRATEGIES: [&str; 4] = ["random", "roundRobin", "leastPing", "leastLoad"];

/// Maximum number of members allowed in a balancer or observatory selector.
pub const MAX_SELECTOR_MEMBERS: usize = 64;

/// Maximum number of nodes in the provider graph (counting both sources and sinks).
pub const MAX_GRAPH_NODES: usize = 1024;

/// Maximum recursion/depth budget for the graph.
pub const MAX_GRAPH_DEPTH: usize = 256;

/// Minimum probe interval for observatories (10 seconds).
pub const MIN_PROBE_INTERVAL_SECONDS: u64 = 10;

/// Maximum probe timeout for burst observatories (60 seconds).
pub const MAX_BURST_TIMEOUT_SECONDS: u64 = 60;

/// Maximum burst sampling count.
pub const MAX_BURST_SAMPLING: u64 = 20;

/// Default burst sampling count when omitted in Xray.
pub const DEFAULT_BURST_SAMPLING: u64 = 10;

/// Default burst interval when omitted in Xray (1 minute).
pub const DEFAULT_BURST_INTERVAL_SECONDS: u64 = 60;

/// Default burst timeout when omitted in Xray (5 seconds).
pub const DEFAULT_BURST_TIMEOUT_SECONDS: u64 = 5;

/// Keys permitted in routing rules.
pub const ALLOWED_RULE_KEYS: [&str; 11] = [
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

/// Permitted keys in standard observatory.
pub const ALLOWED_OBSERVATORY_KEYS: [&str; 5] = [
    "subjectSelector",
    "probeURL",
    "probeUrl",
    "probeInterval",
    "enableConcurrency",
];

/// Permitted keys in burst observatory.
pub const ALLOWED_BURST_OBSERVATORY_KEYS: [&str; 2] = ["subjectSelector", "pingConfig"];

/// Permitted keys in burst pingConfig.
pub const ALLOWED_PING_CONFIG_KEYS: [&str; 6] = [
    "destination",
    "connectivity",
    "interval",
    "timeout",
    "sampling",
    "httpMethod",
];

/// Validate that a streamSettings object contains no local file access paths.
/// Uses fixed structural field paths to prevent leaking arbitrary nested keys into diagnostics.
pub fn validate_stream_security(v: &Value, base_path: &str) -> Result<(), SanitizeError> {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                for canonical in ["dialerProxy", "tlsSettings"] {
                    if k.eq_ignore_ascii_case(canonical) && k != canonical {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{base_path}.{canonical}"),
                            reason: "non-canonical schema field alias",
                        });
                    }
                }
                if k.eq_ignore_ascii_case("certificateFile") {
                    if k != "certificateFile" {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{base_path}.certificateFile"),
                            reason: "non-canonical schema field alias",
                        });
                    }
                    return Err(SanitizeError::Incompatible {
                        path: format!("{base_path}.certificateFile"),
                        reason: "local certificate files are unsupported",
                    });
                }
                if k.eq_ignore_ascii_case("keyFile") {
                    if k != "keyFile" {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{base_path}.keyFile"),
                            reason: "non-canonical schema field alias",
                        });
                    }
                    return Err(SanitizeError::Incompatible {
                        path: format!("{base_path}.keyFile"),
                        reason: "local certificate files are unsupported",
                    });
                }
                if k.eq_ignore_ascii_case("masterKeyLog") && k != "masterKeyLog" {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{base_path}.masterKeyLog"),
                        reason: "non-canonical schema field alias",
                    });
                }
                if k.eq_ignore_ascii_case("allowInsecure") && k != "allowInsecure" {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{base_path}.allowInsecure"),
                        reason: "non-canonical schema field alias",
                    });
                }
                if k.eq_ignore_ascii_case("pinnedPeerCertSha256") && k != "pinnedPeerCertSha256" {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{base_path}.pinnedPeerCertSha256"),
                        reason: "non-canonical schema field alias",
                    });
                }
                validate_stream_security(child, base_path)?;
            }
        }
        Value::Array(a) => {
            for child in a {
                validate_stream_security(child, base_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate that dialerProxy references within streamSettings resolve to known outbounds.
/// Uses fixed structural field paths to prevent leaking arbitrary nested keys into diagnostics.
pub fn validate_dialer_proxies(
    v: &Value,
    base_path: &str,
    outbound_tags: &HashSet<String>,
) -> Result<(), SanitizeError> {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                if k.eq_ignore_ascii_case("dialerProxy") {
                    if k != "dialerProxy" {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{base_path}.dialerProxy"),
                            reason: "non-canonical schema field alias",
                        });
                    }
                    let target = child.as_str().filter(|s| !s.trim().is_empty());
                    match target {
                        Some(t) if outbound_tags.contains(t) => {}
                        _ => {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{base_path}.dialerProxy"),
                                reason: "references unknown outbound tag",
                            });
                        }
                    }
                } else {
                    validate_dialer_proxies(child, base_path, outbound_tags)?;
                }
            }
        }
        Value::Array(a) => {
            for child in a {
                validate_dialer_proxies(child, base_path, outbound_tags)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Parse duration string with explicit unit suffix (e.g. "10s", "1m", "300ms", "2h") into seconds.
/// Bare numbers are rejected per Go duration string requirements.
pub fn parse_duration_string(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_suffix("ms") {
        let ms: u64 = rest.parse().ok()?;
        Some(ms / 1000)
    } else if let Some(rest) = s.strip_suffix('s') {
        rest.parse().ok()
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<u64>().ok()?.checked_mul(60)
    } else if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<u64>().ok()?.checked_mul(3600)
    } else {
        None
    }
}

fn validate_ipv4_host(ip: Ipv4Addr) -> bool {
    if ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_unspecified() {
        return false;
    }
    let octets = ip.octets();
    // 10.0.0.0/8
    if octets[0] == 10 {
        return false;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return false;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }
    true
}

/// Validate safety of a probe destination URL.
///
/// Ensures the URL is absolute HTTP/HTTPS, contains no userinfo or fragments,
/// and does not target loopback, link-local, or private RFC1918/RFC4193 addresses
/// (including IPv4-mapped IPv6 representations like `::ffff:127.0.0.1`).
pub fn validate_probe_url(raw: &str) -> bool {
    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return false;
    }
    let Some(host) = parsed.host() else {
        return false;
    };
    match host {
        url::Host::Ipv4(ip) => {
            if !validate_ipv4_host(ip) {
                return false;
            }
        }
        url::Host::Ipv6(ip) => {
            // Check IPv4-mapped IPv6 (::ffff:a.b.c.d)
            if let Some(v4) = ip.to_ipv4_mapped()
                && !validate_ipv4_host(v4)
            {
                return false;
            }
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                return false;
            }
            let segs = ip.segments();
            // fc00::/7 (unique local)
            if (segs[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            // fe80::/10 (link-local)
            if (segs[0] & 0xffc0) == 0xfe80 {
                return false;
            }
        }
        url::Host::Domain(d) => {
            let d_lower = d.to_ascii_lowercase();
            if d_lower.is_empty()
                || d_lower == "localhost"
                || d_lower.ends_with(".localhost")
                || d_lower.ends_with(".local")
            {
                return false;
            }
            if let Ok(ip) = d.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(v4) => {
                        if !validate_ipv4_host(v4) {
                            return false;
                        }
                    }
                    IpAddr::V6(v6) => {
                        if let Some(v4) = v6.to_ipv4_mapped()
                            && !validate_ipv4_host(v4)
                        {
                            return false;
                        }
                        if v6.is_loopback() || v6.is_unspecified() {
                            return false;
                        }
                    }
                }
            }
        }
    }
    true
}

/// Validate observatory or burstObservatory configuration and its dependency on outbounds.
pub fn validate_observatory_config(
    obs: &Value,
    is_burst: bool,
    outbounds: &[Value],
    _outbound_tags: &HashSet<String>,
) -> Result<(), SanitizeError> {
    let base_path = if is_burst {
        "burstObservatory"
    } else {
        "observatory"
    };
    let Some(obj) = obs.as_object() else {
        return Err(SanitizeError::Incompatible {
            path: base_path.into(),
            reason: "observatory must be a JSON object",
        });
    };

    // Check unknown fields
    let allowed_keys = if is_burst {
        &ALLOWED_BURST_OBSERVATORY_KEYS[..]
    } else {
        &ALLOWED_OBSERVATORY_KEYS[..]
    };
    for k in obj.keys() {
        if !allowed_keys.contains(&k.as_str()) {
            return Err(SanitizeError::Incompatible {
                path: base_path.into(),
                reason: "unsupported observatory field",
            });
        }
    }

    // subjectSelector must be array of strings
    let sel_val = obj
        .get("subjectSelector")
        .ok_or_else(|| SanitizeError::Incompatible {
            path: format!("{base_path}.subjectSelector"),
            reason: "subjectSelector is required",
        })?;
    let sel_arr = sel_val
        .as_array()
        .ok_or_else(|| SanitizeError::Incompatible {
            path: format!("{base_path}.subjectSelector"),
            reason: "subjectSelector must be an array of strings",
        })?;
    if sel_arr.is_empty() {
        return Err(SanitizeError::Incompatible {
            path: format!("{base_path}.subjectSelector"),
            reason: "observatory selector matches no outbounds",
        });
    }

    let mut prefixes = Vec::new();
    for elem in sel_arr {
        let s = elem.as_str().ok_or_else(|| SanitizeError::Incompatible {
            path: format!("{base_path}.subjectSelector"),
            reason: "subjectSelector elements must be strings",
        })?;
        let s = s.trim();
        if s.is_empty() {
            return Err(SanitizeError::Incompatible {
                path: format!("{base_path}.subjectSelector"),
                reason: "empty selector prefix is unsupported",
            });
        }
        prefixes.push(s);
    }

    let mut matched_members = HashSet::new();
    for ob in outbounds {
        let tag = ob.get("tag").and_then(Value::as_str).unwrap_or("");
        if prefixes.iter().any(|p| tag.starts_with(p)) {
            let protocol = ob.get("protocol").and_then(Value::as_str).unwrap_or("");
            if protocol == "loopback" || is_service_outbound(ob) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{base_path}.subjectSelector"),
                    reason: "observatory selector matches service or loopback outbound",
                });
            }
            matched_members.insert(tag.to_string());
        }
    }

    if matched_members.is_empty() {
        return Err(SanitizeError::Incompatible {
            path: format!("{base_path}.subjectSelector"),
            reason: "observatory selector matches no outbounds",
        });
    }

    if matched_members.len() > MAX_SELECTOR_MEMBERS {
        return Err(SanitizeError::Incompatible {
            path: format!("{base_path}.subjectSelector"),
            reason: "observatory selector exceeds maximum members",
        });
    }

    if !is_burst {
        if let Some(ec) = obj.get("enableConcurrency")
            && !ec.is_boolean()
        {
            return Err(SanitizeError::Incompatible {
                path: "observatory.enableConcurrency".into(),
                reason: "enableConcurrency must be a boolean",
            });
        }

        // Standard observatory probeUrl / probeURL (support both Xray spellings)
        let probe_url = match (obj.get("probeURL"), obj.get("probeUrl")) {
            (Some(Value::String(u1)), Some(Value::String(u2))) if u1 != u2 => {
                return Err(SanitizeError::Incompatible {
                    path: "observatory.probeURL".into(),
                    reason: "ambiguous probe URL fields",
                });
            }
            (Some(Value::String(u)), _) | (_, Some(Value::String(u))) => Some(u.as_str()),
            (Some(_), _) | (_, Some(_)) => {
                return Err(SanitizeError::Incompatible {
                    path: "observatory.probeURL".into(),
                    reason: "probe URL must be a string",
                });
            }
            (None, None) => None,
        };

        if let Some(url) = probe_url
            && !validate_probe_url(url)
        {
            return Err(SanitizeError::Incompatible {
                path: "observatory.probeURL".into(),
                reason: "invalid probe URL",
            });
        }

        if let Some(interval_val) = obj.get("probeInterval") {
            let interval_str =
                interval_val
                    .as_str()
                    .ok_or_else(|| SanitizeError::Incompatible {
                        path: "observatory.probeInterval".into(),
                        reason: "probe interval must be a string duration",
                    })?;
            let interval =
                parse_duration_string(interval_str).ok_or_else(|| SanitizeError::Incompatible {
                    path: "observatory.probeInterval".into(),
                    reason: "invalid probe interval",
                })?;
            if interval < MIN_PROBE_INTERVAL_SECONDS {
                return Err(SanitizeError::Incompatible {
                    path: "observatory.probeInterval".into(),
                    reason: "probe interval below minimum",
                });
            }
        }
    } else {
        let ping_cfg = obj
            .get("pingConfig")
            .and_then(Value::as_object)
            .ok_or_else(|| SanitizeError::Incompatible {
                path: "burstObservatory.pingConfig".into(),
                reason: "burstObservatory requires pingConfig",
            })?;

        for k in ping_cfg.keys() {
            if !ALLOWED_PING_CONFIG_KEYS.contains(&k.as_str()) {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig".into(),
                    reason: "unsupported burst observatory field",
                });
            }
        }

        // Plain direct HTTP connectivity check is prohibited
        if let Some(conn) = ping_cfg.get("connectivity")
            && !conn.is_null()
        {
            let s = conn.as_str().unwrap_or("non-string");
            if !s.trim().is_empty() {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.connectivity".into(),
                    reason: "unsupported burst connectivity check",
                });
            }
        }

        if let Some(dest_val) = ping_cfg.get("destination") {
            let dest = dest_val
                .as_str()
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.destination".into(),
                    reason: "destination must be a string URL",
                })?;
            if !validate_probe_url(dest) {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.destination".into(),
                    reason: "invalid probe URL",
                });
            }
        }

        let interval = if let Some(int_val) = ping_cfg.get("interval") {
            let int_str = int_val
                .as_str()
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.interval".into(),
                    reason: "interval must be a string duration",
                })?;
            let int_sec =
                parse_duration_string(int_str).ok_or_else(|| SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.interval".into(),
                    reason: "invalid probe interval",
                })?;
            if int_sec < MIN_PROBE_INTERVAL_SECONDS {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.interval".into(),
                    reason: "probe interval below minimum",
                });
            }
            int_sec
        } else {
            DEFAULT_BURST_INTERVAL_SECONDS
        };

        let _timeout = if let Some(to_val) = ping_cfg.get("timeout") {
            let to_str = to_val.as_str().ok_or_else(|| SanitizeError::Incompatible {
                path: "burstObservatory.pingConfig.timeout".into(),
                reason: "timeout must be a string duration",
            })?;
            let to_sec =
                parse_duration_string(to_str).ok_or_else(|| SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.timeout".into(),
                    reason: "invalid burst timeout",
                })?;
            if to_sec == 0 || to_sec > MAX_BURST_TIMEOUT_SECONDS {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.timeout".into(),
                    reason: "burst timeout exceeds maximum",
                });
            }
            to_sec
        } else {
            DEFAULT_BURST_TIMEOUT_SECONDS
        };

        let sampling = if let Some(samp_val) = ping_cfg.get("sampling") {
            let samp = samp_val
                .as_u64()
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.sampling".into(),
                    reason: "sampling must be a positive integer",
                })?;
            if samp == 0 {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.sampling".into(),
                    reason: "sampling must be a positive integer",
                });
            }
            if samp > MAX_BURST_SAMPLING {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.sampling".into(),
                    reason: "burst sampling exceeds maximum",
                });
            }
            samp
        } else {
            DEFAULT_BURST_SAMPLING
        };

        let _ = interval
            .checked_mul(sampling)
            .ok_or_else(|| SanitizeError::Incompatible {
                path: "burstObservatory.pingConfig".into(),
                reason: "burst parameters overflow",
            })?;

        if let Some(method_val) = ping_cfg.get("httpMethod") {
            let method_str = method_val
                .as_str()
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.httpMethod".into(),
                    reason: "httpMethod must be a string",
                })?;
            let m = method_str.trim().to_ascii_uppercase();
            if m != "GET" && m != "HEAD" {
                return Err(SanitizeError::Incompatible {
                    path: "burstObservatory.pingConfig.httpMethod".into(),
                    reason: "unsupported HTTP method",
                });
            }
        }
    }

    Ok(())
}

/// Nodes in the provider internal routing graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GraphNode {
    Outbound(String),
    UntaggedOutbound(usize),
    VirtualInbound(String),
    Balancer(String),
}

/// Validate that balancers using `leastPing`, `leastLoad`, or `fallbackTag` have all their candidates observed.
pub fn validate_balancer_observatory_coverage(
    balancers: &[Value],
    outbounds: &[Value],
    observatory: Option<&Value>,
    burst_observatory: Option<&Value>,
) -> Result<(), SanitizeError> {
    let obs_obj = observatory.or(burst_observatory);
    let obs_prefixes: Vec<&str> = obs_obj
        .and_then(|o| o.get("subjectSelector"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();

    let observed_tags: HashSet<&str> = outbounds
        .iter()
        .filter_map(|o| o.get("tag").and_then(Value::as_str))
        .filter(|tag| obs_prefixes.iter().any(|p| tag.starts_with(p)))
        .collect();

    for (i, b) in balancers.iter().enumerate() {
        let path = format!("routing.balancers[{i}]");
        let strategy = b.get("strategy");
        let strat_type = match strategy {
            Some(Value::String(s)) => Some(s.as_str()),
            Some(Value::Object(o)) => o.get("type").and_then(Value::as_str),
            _ => None,
        };

        let has_fallback = b.get("fallbackTag").is_some();
        let is_least = strat_type.is_some_and(|t| t == "leastPing" || t == "leastLoad");

        if is_least || has_fallback {
            let members = b.get("selector").and_then(Value::as_array);
            if let Some(members) = members {
                let all_observed = members
                    .iter()
                    .filter_map(Value::as_str)
                    .all(|m| observed_tags.contains(m));
                if !all_observed {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.strategy"),
                        reason: "balancer members not covered by observatory",
                    });
                }
            }
        }
    }
    Ok(())
}

pub fn validate_routing_graph_acyclic(
    outbounds: &[Value],
    balancers: &[Value],
    rules: &[Value],
    virtual_inbound_tags: &HashSet<String>,
) -> Result<(), SanitizeError> {
    let incompatible = |reason| SanitizeError::Incompatible {
        path: "routing".into(),
        reason,
    };
    let declared_count = outbounds
        .len()
        .saturating_add(balancers.len())
        .saturating_add(virtual_inbound_tags.len());
    if declared_count > MAX_GRAPH_NODES {
        return Err(incompatible("routing graph exceeds node limit"));
    }

    let outbound_nodes: Vec<GraphNode> = outbounds
        .iter()
        .enumerate()
        .map(|(index, outbound)| {
            outbound
                .get("tag")
                .and_then(Value::as_str)
                .map(|tag| GraphNode::Outbound(tag.to_owned()))
                .unwrap_or(GraphNode::UntaggedOutbound(index))
        })
        .collect();
    let mut adj: HashMap<GraphNode, Vec<GraphNode>> = HashMap::new();
    for node in &outbound_nodes {
        adj.entry(node.clone()).or_default();
    }
    for tag in virtual_inbound_tags {
        adj.entry(GraphNode::VirtualInbound(tag.clone()))
            .or_default();
    }
    for balancer in balancers {
        if let Some(tag) = balancer.get("tag").and_then(Value::as_str) {
            adj.entry(GraphNode::Balancer(tag.to_owned())).or_default();
        }
    }

    for (outbound, node) in outbounds.iter().zip(&outbound_nodes) {
        let edges = adj.entry(node.clone()).or_default();
        if outbound["protocol"] == "loopback"
            && let Some(tag) = outbound["settings"]["inboundTag"].as_str()
        {
            edges.push(GraphNode::VirtualInbound(tag.to_owned()));
        }
        if let Some(tag) = outbound["proxySettings"]["tag"].as_str() {
            edges.push(GraphNode::Outbound(tag.to_owned()));
        }
        let mut dialers = Vec::new();
        collect_dialer_proxies(outbound, &mut dialers);
        edges.extend(dialers.into_iter().map(GraphNode::Outbound));
    }

    for balancer in balancers {
        let Some(tag) = balancer["tag"].as_str() else {
            continue;
        };
        let edges = adj.entry(GraphNode::Balancer(tag.to_owned())).or_default();
        let prefixes: Vec<&str> = balancer["selector"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for outbound in outbounds {
            if let Some(tag) = outbound["tag"].as_str()
                && prefixes.iter().any(|prefix| tag.starts_with(prefix))
            {
                edges.push(GraphNode::Outbound(tag.to_owned()));
            }
        }
        if let Some(tag) = balancer["fallbackTag"].as_str() {
            edges.push(GraphNode::Outbound(tag.to_owned()));
        }
    }

    // A rule may finish one network without finishing the other. Only reachable
    // transitions enter the graph; an implicit fallback exists for uncovered traffic.
    for context in virtual_inbound_tags {
        let edges = adj
            .entry(GraphNode::VirtualInbound(context.clone()))
            .or_default();
        let mut covered = [false, false];
        for rule in rules {
            let Some(rule) = rule.as_object() else {
                continue;
            };
            let applies = match rule.get("inboundTag") {
                Some(Value::Array(tags)) => tags.iter().any(|tag| tag.as_str() == Some(context)),
                Some(Value::String(tag)) => tag == context,
                None => true,
                _ => false,
            };
            if !applies {
                continue;
            }
            let matches_network = |network: &str| match rule.get("network") {
                None => true,
                Some(Value::String(value)) => value.split(',').any(|value| value == network),
                Some(Value::Array(values)) => {
                    values.iter().any(|value| value.as_str() == Some(network))
                }
                _ => false,
            };
            if !["tcp", "udp"]
                .iter()
                .enumerate()
                .any(|(index, network)| !covered[index] && matches_network(network))
            {
                continue;
            }
            if let Some(tag) = rule.get("outboundTag").and_then(Value::as_str) {
                edges.push(GraphNode::Outbound(tag.to_owned()));
            } else if let Some(tag) = rule.get("balancerTag").and_then(Value::as_str) {
                edges.push(GraphNode::Balancer(tag.to_owned()));
            }
            for (index, network) in ["tcp", "udp"].iter().enumerate() {
                covered[index] |= rule_covers_network(rule, network);
            }
            if covered.iter().all(|covered| *covered) {
                break;
            }
        }
        if covered.iter().any(|covered| !covered)
            && let Some(first) = outbound_nodes.first()
        {
            edges.push(first.clone());
        }
    }

    let all_nodes: HashSet<GraphNode> = adj
        .keys()
        .cloned()
        .chain(adj.values().flatten().cloned())
        .collect();
    if all_nodes.len() > MAX_GRAPH_NODES {
        return Err(incompatible("routing graph exceeds node limit"));
    }

    // Cache complete suffix lengths, not just visited flags. Otherwise starting
    // at a shared suffix could conceal a longer path from a later DFS root.
    let mut depths: HashMap<GraphNode, usize> = HashMap::new();
    let mut active = HashSet::new();
    for root in all_nodes {
        if depths.contains_key(&root) {
            continue;
        }
        let mut stack = vec![(root.clone(), 0usize)];
        active.insert(root);
        while let Some((node, next)) = stack.last_mut() {
            let neighbors = adj.get(node).map(Vec::as_slice).unwrap_or_default();
            if let Some(child) = neighbors.get(*next) {
                *next += 1;
                if active.contains(child) {
                    return Err(incompatible("unsupported routing cycle/structure"));
                }
                if !depths.contains_key(child) {
                    active.insert(child.clone());
                    stack.push((child.clone(), 0));
                    if stack.len() > MAX_GRAPH_DEPTH {
                        return Err(incompatible("routing graph exceeds depth limit"));
                    }
                }
            } else {
                let depth = neighbors
                    .iter()
                    .filter_map(|child| depths.get(child))
                    .max()
                    .copied()
                    .unwrap_or(0)
                    + 1;
                if depth > MAX_GRAPH_DEPTH {
                    return Err(incompatible("routing graph exceeds depth limit"));
                }
                let (node, _) = stack.pop().expect("the DFS stack has an active node");
                active.remove(&node);
                depths.insert(node, depth);
            }
        }
    }
    Ok(())
}

fn collect_dialer_proxies(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                if k == "dialerProxy" {
                    if let Some(s) = child.as_str().filter(|s| !s.trim().is_empty()) {
                        out.push(s.to_string());
                    }
                } else {
                    collect_dialer_proxies(child, out);
                }
            }
        }
        Value::Array(a) => {
            for child in a {
                collect_dialer_proxies(child, out);
            }
        }
        _ => {}
    }
}

/// Whether a port selector covers every usable TCP or UDP port.
pub(crate) fn ports_cover_all(value: &Value) -> bool {
    fn ranges(value: &Value, out: &mut Vec<(u16, u16)>) -> Option<()> {
        match value {
            Value::Number(number) => {
                let port = u16::try_from(number.as_u64()?).ok()?;
                out.push((port, port));
            }
            Value::String(value) => {
                for item in value.split(',') {
                    let item = item.trim();
                    let (start, end) = match item.split_once('-') {
                        Some((start, end)) => {
                            (start.trim().parse().ok()?, end.trim().parse().ok()?)
                        }
                        None => {
                            let port = item.parse().ok()?;
                            (port, port)
                        }
                    };
                    if start > end {
                        return None;
                    }
                    out.push((start, end));
                }
            }
            Value::Array(values) => {
                for value in values {
                    ranges(value, out)?;
                }
            }
            _ => return None,
        }
        Some(())
    }
    let mut parsed = Vec::new();
    if ranges(value, &mut parsed).is_none() {
        return false;
    }
    parsed.sort_unstable();
    let mut covered = 0u32;
    for (start, end) in parsed {
        if u32::from(start) > covered + 1 {
            return false;
        }
        covered = covered.max(u32::from(end));
        if covered == u32::from(u16::MAX) {
            return true;
        }
    }
    false
}

/// Check if a rule unconditionally covers all traffic of the specified `network` ("tcp" or "udp").
///
/// Ignores `inboundTag` (caller must verify inbound context).
/// Accounts for all accepted conditions: `domain`, `domains`, `ip`, `port`, `sourcePort`, `protocol`.
/// If any restrictive condition is present, returns `false`.
/// If `network` condition is specified, checks for exact token ("tcp" or "udp").
pub(crate) fn rule_covers_network(rule: &serde_json::Map<String, Value>, network: &str) -> bool {
    let has_condition = |key: &str| {
        rule.get(key).is_some_and(|v| match v {
            Value::Null => false,
            Value::String(s) => !s.trim().is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            _ => true,
        })
    };

    for key in &["domain", "domains", "ip", "protocol"] {
        if has_condition(key) {
            return false;
        }
    }
    for key in ["port", "sourcePort"] {
        if let Some(value) = rule.get(key)
            && has_condition(key)
            && !ports_cover_all(value)
        {
            return false;
        }
    }

    let target_net = network.trim().to_ascii_lowercase();

    match rule.get("network") {
        None => true,
        Some(Value::Null) => true,
        Some(Value::String(s)) => {
            let s = s.trim().to_ascii_lowercase();
            if s.is_empty() {
                true
            } else {
                s.split(',').map(str::trim).any(|tok| tok == target_net)
            }
        }
        Some(Value::Array(arr)) => {
            if arr.is_empty() {
                true
            } else {
                arr.iter()
                    .filter_map(Value::as_str)
                    .any(|token| token == target_net)
            }
        }
        Some(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_probe_url() {
        assert!(validate_probe_url("https://www.example.com/generate_204"));
        assert!(validate_probe_url("http://example.org:8080/test?k=v"));

        // Schemes
        assert!(!validate_probe_url("ftp://example.com/"));
        assert!(!validate_probe_url("ws://example.com/"));

        // Userinfo / fragments
        assert!(!validate_probe_url("https://user:pass@example.com/"));
        assert!(!validate_probe_url("https://example.com/#frag"));

        // Loopback / localhost
        assert!(!validate_probe_url("http://localhost/"));
        assert!(!validate_probe_url("http://sub.localhost/"));
        assert!(!validate_probe_url("http://app.local/"));
        assert!(!validate_probe_url("http://127.0.0.1/"));
        assert!(!validate_probe_url("http://127.0.1.1:8080/"));
        assert!(!validate_probe_url("http://[::1]/"));

        // IPv4-mapped IPv6 (::ffff:127.0.0.1 and private ranges)
        assert!(!validate_probe_url("http://[::ffff:127.0.0.1]/"));
        assert!(!validate_probe_url("http://[::ffff:10.0.0.1]/"));
        assert!(!validate_probe_url("http://[::ffff:192.168.1.1]/"));

        // Private IPv4
        assert!(!validate_probe_url("http://10.0.0.1/"));
        assert!(!validate_probe_url("http://172.16.0.1/"));
        assert!(!validate_probe_url("http://172.31.255.255/"));
        assert!(!validate_probe_url("http://192.168.1.1/"));
        assert!(!validate_probe_url("http://169.254.169.254/"));

        // Private / link-local IPv6
        assert!(!validate_probe_url("http://[fc00::1]/"));
        assert!(!validate_probe_url("http://[fe80::1]/"));
    }

    #[test]
    fn test_parse_duration_string() {
        assert_eq!(parse_duration_string("10s"), Some(10));
        assert_eq!(parse_duration_string("1m"), Some(60));
        assert_eq!(parse_duration_string("2h"), Some(7200));
        assert_eq!(parse_duration_string("500ms"), Some(0));
        assert_eq!(parse_duration_string("1500ms"), Some(1));
        // Bare numbers rejected
        assert_eq!(parse_duration_string("30"), None);
        assert_eq!(parse_duration_string(""), None);
        assert_eq!(parse_duration_string("abc"), None);
    }

    #[test]
    fn test_validate_stream_security() {
        let clean = json!({
            "network": "tcp",
            "security": "tls",
            "tlsSettings": { "serverName": "example.com" }
        });
        assert!(validate_stream_security(&clean, "outbounds[0].streamSettings").is_ok());

        // Arbitrary intermediate key name is not leaked in path
        let with_cert = json!({
            "security": "tls",
            "secret_custom_key": {
                "certificateFile": "/path/to/cert.crt"
            }
        });
        let err = validate_stream_security(&with_cert, "outbounds[0].streamSettings").unwrap_err();
        assert_eq!(
            err,
            SanitizeError::Incompatible {
                path: "outbounds[0].streamSettings.certificateFile".into(),
                reason: "local certificate files are unsupported",
            }
        );

        // Non-canonical alias rejected
        let with_alias = json!({
            "security": "tls",
            "CertificateFile": "/path/to/cert.crt"
        });
        assert!(matches!(
            validate_stream_security(&with_alias, "outbounds[0].streamSettings"),
            Err(SanitizeError::Incompatible { reason, .. })
            if reason == "non-canonical schema field alias"
        ));
    }

    #[test]
    fn test_validate_dialer_proxies() {
        let mut known = HashSet::new();
        known.insert("proxy-1".to_string());

        let stream_ok = json!({
            "sockopt": { "dialerProxy": "proxy-1" }
        });
        assert!(validate_dialer_proxies(&stream_ok, "outbounds[0].streamSettings", &known).is_ok());

        let stream_bad = json!({
            "arbitrary_layer": {
                "dialerProxy": "unknown"
            }
        });
        assert_eq!(
            validate_dialer_proxies(&stream_bad, "outbounds[0].streamSettings", &known)
                .unwrap_err(),
            SanitizeError::Incompatible {
                path: "outbounds[0].streamSettings.dialerProxy".into(),
                reason: "references unknown outbound tag",
            }
        );
    }

    #[test]
    fn test_cycle_detection_finds_loop() {
        let outbounds = vec![
            json!({
                "tag": "a",
                "protocol": "vless",
                "streamSettings": { "sockopt": { "dialerProxy": "b" } }
            }),
            json!({
                "tag": "b",
                "protocol": "vless",
                "streamSettings": { "sockopt": { "dialerProxy": "a" } }
            }),
        ];
        let vtags = HashSet::new();
        let res = validate_routing_graph_acyclic(&outbounds, &[], &[], &vtags);
        assert!(matches!(
            res,
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing" && reason == "unsupported routing cycle/structure"
        ));
    }

    #[test]
    fn test_cycle_detection_allows_diamond_dag() {
        let outbounds = vec![
            json!({ "tag": "entry-1", "protocol": "vless", "streamSettings": { "sockopt": { "dialerProxy": "exit" } } }),
            json!({ "tag": "entry-2", "protocol": "vless", "streamSettings": { "sockopt": { "dialerProxy": "exit" } } }),
            json!({ "tag": "exit", "protocol": "vless" }),
        ];
        let vtags = HashSet::new();
        assert!(validate_routing_graph_acyclic(&outbounds, &[], &[], &vtags).is_ok());
    }

    #[test]
    fn test_iterative_dfs_bounded_against_deep_graph() {
        let mut outbounds = Vec::new();
        for i in 0..1050 {
            outbounds.push(json!({
                "tag": format!("n_{i}"),
                "protocol": "vless",
                "streamSettings": {
                    "sockopt": {
                        "dialerProxy": format!("n_{}", i + 1)
                    }
                }
            }));
        }
        let vtags = HashSet::new();
        let res = validate_routing_graph_acyclic(&outbounds, &[], &[], &vtags);
        // Exceeds node limit without stack overflow!
        assert!(matches!(
            res,
            Err(SanitizeError::Incompatible { path, reason })
            if path == "routing" && reason == "routing graph exceeds node limit"
        ));
    }

    #[test]
    fn test_rule_covers_network() {
        let empty_rule = json!({}).as_object().unwrap().clone();
        assert!(rule_covers_network(&empty_rule, "tcp"));
        assert!(rule_covers_network(&empty_rule, "udp"));

        let tcp_rule = json!({ "network": "tcp" }).as_object().unwrap().clone();
        assert!(rule_covers_network(&tcp_rule, "tcp"));
        assert!(!rule_covers_network(&tcp_rule, "udp"));

        let both_rule = json!({ "network": "tcp,udp" }).as_object().unwrap().clone();
        assert!(rule_covers_network(&both_rule, "tcp"));
        assert!(rule_covers_network(&both_rule, "udp"));

        let array_rule = json!({ "network": ["tcp", "udp"] })
            .as_object()
            .unwrap()
            .clone();
        assert!(rule_covers_network(&array_rule, "tcp"));
        assert!(rule_covers_network(&array_rule, "udp"));

        let domain_rule = json!({ "domain": ["example.com"] })
            .as_object()
            .unwrap()
            .clone();
        assert!(!rule_covers_network(&domain_rule, "tcp"));
        assert!(!rule_covers_network(&domain_rule, "udp"));

        let port_rule = json!({ "port": "443" }).as_object().unwrap().clone();
        assert!(!rule_covers_network(&port_rule, "tcp"));
    }
}
