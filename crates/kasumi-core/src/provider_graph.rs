//! Validated connection graph for provider Xray configurations.
//!
//! A provider profile is an exit strategy: Kasumi's own routing (user rules,
//! Global/Rules/Custom modes, DNS, listeners) decides direct / block / which profile.
//! A provider config contributes only its connection graph: outbounds, chains
//! (dialerProxy), balancers, one observation engine, and internal loopback contexts.
//! External provider routing rules (geo/direct/block/conditional entry rules) are
//! ignored with a warning; internal context rules are preserved.

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use serde_json::{Map, Value, json};
use url::Url;

use crate::custom_sanitize::{SanitizeError, is_service_outbound, provider_outbounds_identity};
use crate::custom_target::Target;
use crate::profile::{Custom, CustomOrigin, Profile};
use crate::xray_config::{BuildKind, XRAY_RULE_CONDITIONS, parse_json_safe};

pub const BALANCER_STRATEGIES: [&str; 4] = ["random", "roundRobin", "leastPing", "leastLoad"];
pub const MAX_SELECTOR_MEMBERS: usize = 64;
pub const MAX_GRAPH_NODES: usize = 1024;
pub const MAX_GRAPH_DEPTH: usize = 256;
pub const MIN_PROBE_INTERVAL: Duration = Duration::from_secs(10);
pub const MAX_BURST_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_BURST_SAMPLING: u64 = 20;
pub const DEFAULT_BURST_SAMPLING: u64 = 10;
pub const DEFAULT_BURST_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_BURST_TIMEOUT: Duration = Duration::from_secs(5);

/// Rule keys that carry no condition: the rule's dispatch target, the legacy
/// `type` label Xray ignores, and its observability label. Everything else a provider may
/// write on a rule is a condition from Xray's own list.
const RULE_METADATA_KEYS: [&str; 4] = ["type", "ruleTag", "outboundTag", "balancerTag"];

/// These select a context or its TCP/UDP coverage, rather than external
/// policy. `port` is classified by its coverage below.
const RULE_SCOPE_KEYS: [&str; 3] = ["inboundTag", "network", "port"];

pub const ALLOWED_OBSERVATORY_KEYS: [&str; 5] = [
    "subjectSelector",
    "probeURL",
    "probeUrl",
    "probeInterval",
    "enableConcurrency",
];

pub const ALLOWED_BURST_OBSERVATORY_KEYS: [&str; 2] = ["subjectSelector", "pingConfig"];

pub const ALLOWED_PING_CONFIG_KEYS: [&str; 5] = [
    "destination",
    "interval",
    "connectivity",
    "timeout",
    "sampling",
];

fn parse_duration_unit(u: &str) -> Option<u64> {
    match u {
        "ns" => Some(1),
        "us" | "µs" => Some(1_000),
        "ms" => Some(1_000_000),
        "s" => Some(1_000_000_000),
        "m" => Some(60 * 1_000_000_000),
        "h" => Some(60 * 60 * 1_000_000_000),
        _ => None,
    }
}

fn duration_leading_int(s: &str) -> Option<(u64, &str)> {
    let mut end = 0;
    while end < s.len() && s.as_bytes()[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    let val = s[..end].parse::<u64>().ok()?;
    Some((val, &s[end..]))
}

fn duration_leading_fraction(s: &str) -> (u64, f64, &str) {
    let mut end = 0;
    while end < s.len() && s.as_bytes()[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return (0, 0.0, s);
    }
    let frac_str = &s[..end];
    let mut scale = 1.0;
    let mut val = 0.0;
    for b in frac_str.bytes() {
        scale /= 10.0;
        val += ((b - b'0') as f64) * scale;
    }
    let nanos = (val * 1_000_000_000.0).round() as u64;
    (nanos, val, &s[end..])
}

pub fn parse_duration_string(mut s: &str) -> Option<Duration> {
    if s.is_empty() {
        return None;
    }
    if s == "0" {
        return Some(Duration::ZERO);
    }
    if s.starts_with('-') {
        return None;
    }
    let mut total_nanos: u128 = 0;
    while !s.is_empty() {
        let mut int_part = 0u64;
        let mut frac_val = 0.0f64;
        let mut has_int = false;
        let mut has_frac = false;

        if let Some((v, rem)) = duration_leading_int(s) {
            int_part = v;
            has_int = true;
            s = rem;
        }

        if s.starts_with('.') {
            s = &s[1..];
            let (_, fv, rem) = duration_leading_fraction(s);
            frac_val = fv;
            has_frac = true;
            s = rem;
        }

        if !has_int && !has_frac {
            return None;
        }

        let mut unit_end = 0;
        while unit_end < s.len()
            && !s.as_bytes()[unit_end].is_ascii_digit()
            && s.as_bytes()[unit_end] != b'.'
        {
            unit_end += 1;
        }
        if unit_end == 0 {
            return None;
        }
        let unit_str = &s[..unit_end];
        s = &s[unit_end..];

        let unit_scale = parse_duration_unit(unit_str)? as u128;
        let int_contrib = (int_part as u128).checked_mul(unit_scale)?;
        let frac_contrib = (frac_val * (unit_scale as f64)).round() as u128;
        total_nanos = total_nanos
            .checked_add(int_contrib)?
            .checked_add(frac_contrib)?;
    }
    let secs = (total_nanos / 1_000_000_000) as u64;
    let nanos = (total_nanos % 1_000_000_000) as u32;
    Some(Duration::new(secs, nanos))
}

fn validate_ipv4_host(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || octets[0] >= 224
    {
        return false;
    }
    true
}

pub fn validate_probe_url(raw: &str) -> bool {
    let Ok(u) = Url::parse(raw) else {
        return false;
    };
    if u.scheme() != "http" && u.scheme() != "https" {
        return false;
    }
    let Some(host_str) = u.host_str() else {
        return false;
    };
    if host_str.is_empty() {
        return false;
    }
    if let Ok(ip) = Ipv4Addr::from_str(host_str) {
        if !validate_ipv4_host(ip) {
            return false;
        }
    } else if let Ok(ip) = Ipv6Addr::from_str(host_str) {
        if ip.is_loopback() || ip.is_unspecified() {
            return false;
        }
        let segs = ip.segments();
        if (segs[0] & 0xfe00) == 0xfc00
            || (segs[0] & 0xffc0) == 0xfe80
            || (segs[0] & 0xff00) == 0xff00
        {
            return false;
        }
    } else {
        if host_str.eq_ignore_ascii_case("localhost") {
            return false;
        }
        if !host_str
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return false;
        }
    }
    if let Some(port) = u.port()
        && port == 0
    {
        return false;
    }
    true
}

/// Validate that a streamSettings object contains no local file access paths.
/// Uses fixed structural field paths to prevent leaking arbitrary nested keys into diagnostics.
pub fn validate_stream_security(v: &Value, base_path: &str) -> Result<(), SanitizeError> {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                for canonical in ["dialerProxy", "sockopt", "tlsSettings"] {
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

pub(crate) fn ports_cover_all(value: &Value) -> bool {
    let mut covered = [false; 65536];
    let ranges: Vec<String> = match value {
        Value::String(s) => s.split(',').map(|p| p.trim().to_string()).collect(),
        Value::Number(n) => vec![n.to_string()],
        Value::Array(a) => a
            .iter()
            .filter_map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
            })
            .collect(),
        _ => return false,
    };
    for r in ranges {
        if r.is_empty() {
            continue;
        }
        if let Some((start, end)) = r.split_once('-') {
            let start: u32 = start.trim().parse().unwrap_or(0);
            let end: u32 = end.trim().parse().unwrap_or(0);
            if start >= 1 && end <= 65535 && start <= end {
                for p in start..=end {
                    covered[p as usize] = true;
                }
            }
        } else if let Ok(p) = r.parse::<u32>()
            && (1..=65535).contains(&p)
        {
            covered[p as usize] = true;
        }
    }
    (1..=65535).all(|p| covered[p])
}

pub(crate) fn rule_covers_network(rule: &Map<String, Value>, network: &str) -> bool {
    let Some(net) = rule.get("network") else {
        return true;
    };
    match net {
        Value::String(s) => s
            .split(',')
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(network)),
        Value::Array(arr) => arr
            .iter()
            .filter_map(Value::as_str)
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(network)),
        _ => false,
    }
}

pub(crate) fn validate_network_field(
    rule: &Map<String, Value>,
    path: &str,
) -> Result<(), SanitizeError> {
    if let Some(net) = rule.get("network") {
        match net {
            Value::String(s) => {
                for candidate in s.split(',') {
                    let c = candidate.trim();
                    if !["tcp", "udp"].contains(&c) {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.network"),
                            reason: "unknown network protocol",
                        });
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    let Some(s) = item.as_str() else {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.network"),
                            reason: "network array items must be strings",
                        });
                    };
                    if !["tcp", "udp"].contains(&s.trim()) {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.network"),
                            reason: "unknown network protocol",
                        });
                    }
                }
            }
            _ => {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.network"),
                    reason: "invalid network specification",
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn is_rule_conditional(rule: &Map<String, Value>) -> bool {
    for key in XRAY_RULE_CONDITIONS {
        if RULE_SCOPE_KEYS.contains(&key) {
            continue;
        }
        if let Some(v) = rule.get(key) {
            match v {
                Value::Null => {}
                Value::String(s) if s.trim().is_empty() => {}
                Value::Array(a) if a.is_empty() => {}
                Value::Object(o) if o.is_empty() => {}
                _ => return true,
            }
        }
    }
    if let Some(port_val) = rule.get("port")
        && !ports_cover_all(port_val)
    {
        return true;
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetRef {
    Outbound(String),
    Balancer(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct FragmentOutbound {
    pub tag: String,
    pub orig_tag: String,
    pub raw: Value,
    pub is_service: bool,
    pub is_loopback: bool,
    pub loopback_inbound: Option<String>,
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FragmentBalancer {
    pub tag: String,
    pub strategy: Option<Value>,
    pub members: Vec<String>,
    /// Where an empty pick goes. Xray sends it to the config's first outbound
    /// when no fallbackTag is named, so that edge is recorded explicitly for
    /// strategies that can pick nothing; random and roundRobin never do.
    pub fallback_tag: Option<String>,
    pub has_explicit_fallback: bool,
    pub resolved_costs: Option<Vec<(String, serde_json::Number)>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FragmentObservatory {
    pub is_burst: bool,
    pub subjects: Vec<String>,
    pub raw: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FragmentContext {
    pub virtual_tag: String,
    pub target: TargetRef,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderFragment {
    pub outbounds: Vec<FragmentOutbound>,
    pub balancers: Vec<FragmentBalancer>,
    pub observatory: Option<FragmentObservatory>,
    pub contexts: Vec<FragmentContext>,
    pub default_handler: String,
    pub entry: TargetRef,
    pub plain_entry: bool,
    pub dropped_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ActiveOutbounds {
    pub outbounds: Vec<Value>,
    pub rules: Vec<Value>,
    pub balancers: Vec<Value>,
    pub target: Target,
    pub observatory: Option<Value>,
    pub burst_observatory: Option<Value>,
}

impl ProviderFragment {
    pub fn build(
        mut raw_outbounds: Vec<Value>,
        routing: Option<&Value>,
        observatory: Option<&Value>,
        burst_observatory: Option<&Value>,
        inbound_tags: &[String],
    ) -> Result<Self, SanitizeError> {
        if raw_outbounds.is_empty() {
            return Err(SanitizeError::NoOutbounds);
        }
        if raw_outbounds.len() > MAX_GRAPH_NODES {
            return Err(SanitizeError::Incompatible {
                path: "outbounds".into(),
                reason: "routing graph exceeds node limit",
            });
        }

        let orig_outbound_tags: Vec<String> = raw_outbounds
            .iter()
            .filter_map(|o| o.get("tag").and_then(Value::as_str).map(str::to_string))
            .collect();
        let mut occupied: HashSet<String> = orig_outbound_tags.iter().cloned().collect();

        let original_tags: Vec<String> = raw_outbounds
            .iter()
            .map(|o| {
                o.get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        // Assign synthetic tags to unnamed outbounds
        for (i, ob) in raw_outbounds.iter_mut().enumerate() {
            if ob.get("tag").and_then(Value::as_str).is_some() {
                continue;
            }
            let mut suffix = 0usize;
            let tag = loop {
                let candidate = format!("kasumi-unnamed-{i}-{suffix}");
                if occupied.insert(candidate.clone()) {
                    break candidate;
                }
                suffix += 1;
            };
            ob["tag"] = tag.into();
        }

        let mut seen_tags = HashSet::new();
        for (i, ob) in raw_outbounds.iter().enumerate() {
            let tag = ob["tag"].as_str().unwrap().to_string();
            if !seen_tags.insert(tag) {
                return Err(SanitizeError::Incompatible {
                    path: format!("outbounds[{i}].tag"),
                    reason: "duplicate outbound tag",
                });
            }
        }

        let default_handler = raw_outbounds[0]["tag"].as_str().unwrap().to_string();

        let mut fragment_outbounds = Vec::new();
        let mut virtual_tags = HashSet::new();

        for (i, ob) in raw_outbounds.into_iter().enumerate() {
            let tag = ob["tag"].as_str().unwrap().to_string();
            let protocol = ob
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let is_service = is_service_outbound(&ob);
            let is_loopback = protocol == "loopback";
            let mut loopback_inbound = None;

            if is_loopback {
                let vtag_opt = ob
                    .get("settings")
                    .and_then(|s| s.get("inboundTag"))
                    .and_then(Value::as_str);
                let Some(vtag) = vtag_opt.filter(|s| !s.trim().is_empty()) else {
                    return Err(SanitizeError::Incompatible {
                        path: format!("outbounds[{i}].settings.inboundTag"),
                        reason: "loopback requires non-empty inboundTag",
                    });
                };
                if vtag != vtag.trim() {
                    return Err(SanitizeError::Incompatible {
                        path: format!("outbounds[{i}].settings.inboundTag"),
                        reason: "inboundTag cannot contain leading or trailing whitespace",
                    });
                }
                if inbound_tags.iter().any(|t| t == vtag) {
                    return Err(SanitizeError::Incompatible {
                        path: format!("outbounds[{i}].settings.inboundTag"),
                        reason: "virtual inbound tag collides with inbound tag",
                    });
                }
                virtual_tags.insert(vtag.to_string());
                loopback_inbound = Some(vtag.to_string());
            }

            let mut dialer_proxy = None;
            // Xray dials through only one of these. With both set, the graph would
            // record one hop while the core might take the other. A null or empty
            // value names no hop, as in Xray.
            let dialer_proxy_ref = ob
                .get("streamSettings")
                .and_then(|ss| ss.get("sockopt"))
                .and_then(|so| so.get("dialerProxy"))
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty());
            let proxy_settings_ref = ob
                .get("proxySettings")
                .and_then(|ps| ps.get("tag"))
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty());
            // Unlike dialerProxy, a present proxySettings object is always built
            // by Xray, which refuses one without a tag at load time.
            if ob.get("proxySettings").is_some_and(|ps| !ps.is_null())
                && proxy_settings_ref.is_none()
            {
                return Err(SanitizeError::Incompatible {
                    path: format!("outbounds[{i}].proxySettings.tag"),
                    reason: "proxySettings requires a tag",
                });
            }
            if dialer_proxy_ref.is_some() && proxy_settings_ref.is_some() {
                return Err(SanitizeError::Incompatible {
                    path: format!("outbounds[{i}].proxySettings.tag"),
                    reason: "both dialerProxy and proxySettings.tag are set",
                });
            }
            if let Some(dp) = dialer_proxy_ref.or(proxy_settings_ref) {
                if dp == tag {
                    return Err(SanitizeError::Incompatible {
                        path: format!("outbounds[{i}].streamSettings.sockopt.dialerProxy"),
                        reason: "self-referential dialerProxy",
                    });
                }
                if !occupied.contains(dp) {
                    return Err(SanitizeError::Incompatible {
                        path: format!("outbounds[{i}].streamSettings.sockopt.dialerProxy"),
                        reason: "unknown dialerProxy target",
                    });
                }
                dialer_proxy = Some(dp.to_string());
            }

            fragment_outbounds.push(FragmentOutbound {
                tag,
                orig_tag: original_tags[i].clone(),
                raw: ob,
                is_service,
                is_loopback,
                loopback_inbound,
                dialer_proxy,
            });
        }

        let mut fragment_balancers = Vec::new();
        let mut balancer_tags = HashSet::new();
        let mut total_cost_rules = 0usize;
        let raw_balancers = routing
            .and_then(|r| r.get("balancers"))
            .and_then(Value::as_array);

        if let Some(balancers) = raw_balancers {
            for (i, b) in balancers.iter().enumerate() {
                let path = format!("routing.balancers[{i}]");
                let Some(b_obj) = b.as_object() else {
                    return Err(SanitizeError::Incompatible {
                        path,
                        reason: "balancer must be an object",
                    });
                };
                let tag = b_obj
                    .get("tag")
                    .and_then(Value::as_str)
                    .ok_or_else(|| SanitizeError::Incompatible {
                        path: format!("{path}.tag"),
                        reason: "balancer tag must be a string",
                    })?
                    .to_string();
                if tag.is_empty() {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.tag"),
                        reason: "balancer tag cannot be empty",
                    });
                }
                if seen_tags.contains(&tag) || !balancer_tags.insert(tag.clone()) {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.tag"),
                        reason: "duplicate balancer tag",
                    });
                }

                let strat_val = b_obj.get("strategy");
                // Xray reads the strategy as an object with a `type`; a bare string
                // does not parse there, so it is not passed on either.
                let (strat_type, raw_costs) = match strat_val {
                    Some(Value::Object(o)) => {
                        let st = o.get("type").and_then(Value::as_str);
                        let costs = o.get("settings").and_then(|s| s.get("costs"));
                        (st, costs)
                    }
                    None => (None, None),
                    _ => {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.strategy"),
                            reason: "unknown balancer strategy",
                        });
                    }
                };
                if let Some(st) = strat_type
                    && !BALANCER_STRATEGIES.contains(&st)
                {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.strategy"),
                        reason: "unknown balancer strategy",
                    });
                }
                if let Some(costs) = raw_costs
                    && !costs.is_null()
                {
                    if !costs.is_array() {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.strategy.settings.costs"),
                            reason: "balancer costs must be an array",
                        });
                    }
                    if strat_type != Some("leastLoad")
                        && costs.as_array().is_some_and(|a| !a.is_empty())
                    {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.strategy.settings.costs"),
                            reason: "leastLoad costs is not supported",
                        });
                    }
                }

                let sel_arr = b_obj
                    .get("selector")
                    .and_then(Value::as_array)
                    .ok_or_else(|| SanitizeError::Incompatible {
                        path: format!("{path}.selector"),
                        reason: "balancer requires selector array",
                    })?;
                let prefixes: Vec<&str> = sel_arr.iter().filter_map(Value::as_str).collect();
                if prefixes.len() != sel_arr.len() {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.selector"),
                        reason: "selector items must be strings",
                    });
                }

                let mut members = Vec::new();
                for ob in &fragment_outbounds {
                    let orig = &ob.orig_tag;
                    let matches_selector = prefixes.iter().any(|p| {
                        if p.is_empty() {
                            true
                        } else if orig.is_empty() {
                            false
                        } else {
                            *p == orig.as_str() || orig.starts_with(p)
                        }
                    });
                    if matches_selector && !members.contains(&ob.tag) {
                        if ob.is_service || ob.is_loopback {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{path}.selector"),
                                reason: "balancer selector matches service or loopback outbound",
                            });
                        }
                        members.push(ob.tag.clone());
                    }
                }
                if members.is_empty() {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.selector"),
                        reason: "balancer selector matches no outbounds",
                    });
                }
                if members.len() > MAX_SELECTOR_MEMBERS {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.selector"),
                        reason: "balancer selector exceeds maximum member limit",
                    });
                }

                let (fallback_tag, has_explicit_fallback) =
                    match b_obj.get("fallbackTag").and_then(Value::as_str) {
                        Some(fb) => {
                            if !seen_tags.contains(fb) {
                                return Err(SanitizeError::Incompatible {
                                    path: format!("{path}.fallbackTag"),
                                    reason: "unknown fallbackTag outbound",
                                });
                            }
                            (Some(fb.to_string()), true)
                        }
                        None => (
                            is_observation_strategy(strat_val).then(|| default_handler.clone()),
                            false,
                        ),
                    };

                let resolved_costs = if strat_type == Some("leastLoad")
                    && let Some(costs) = raw_costs
                    && !costs.is_null()
                    && costs.as_array().is_some_and(|a| !a.is_empty())
                {
                    let member_orig_tags: Vec<(&str, &str)> = members
                        .iter()
                        .map(|m| {
                            let ob = fragment_outbounds.iter().find(|o| o.tag == *m).unwrap();
                            (ob.tag.as_str(), ob.orig_tag.as_str())
                        })
                        .collect();
                    Some(crate::costs::resolve_leastload_costs(
                        costs,
                        &member_orig_tags,
                        &path,
                        &mut total_cost_rules,
                    )?)
                } else {
                    None
                };

                fragment_balancers.push(FragmentBalancer {
                    tag,
                    strategy: strat_val.cloned(),
                    members,
                    fallback_tag,
                    has_explicit_fallback,
                    resolved_costs,
                });
            }
        }

        let total_nodes = fragment_outbounds.len() + fragment_balancers.len() + virtual_tags.len();
        if total_nodes > MAX_GRAPH_NODES {
            return Err(SanitizeError::Incompatible {
                path: "routing".into(),
                reason: "routing graph exceeds node limit",
            });
        }

        if observatory.is_some() && burst_observatory.is_some() {
            return Err(SanitizeError::Incompatible {
                path: "observatory".into(),
                reason: "cannot specify both observatory and burstObservatory",
            });
        }

        let mut fragment_observatory = None;
        let mut obs_subjects: HashSet<String> = HashSet::new();

        if let Some(obs) = observatory {
            let path = "observatory";
            let Some(obj) = obs.as_object() else {
                return Err(SanitizeError::Incompatible {
                    path: path.into(),
                    reason: "observatory must be an object",
                });
            };
            for k in obj.keys() {
                if !ALLOWED_OBSERVATORY_KEYS.contains(&k.as_str()) {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.{k}"),
                        reason: "unsupported observatory key",
                    });
                }
            }
            let probe_url = obj
                .get("probeURL")
                .or_else(|| obj.get("probeUrl"))
                .and_then(Value::as_str)
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: format!("{path}.probeUrl"),
                    reason: "missing probe URL",
                })?;
            if !validate_probe_url(probe_url) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.probeUrl"),
                    reason: "invalid probe URL",
                });
            }
            if let Some(dur_str) = obj.get("probeInterval").and_then(Value::as_str) {
                let dur =
                    parse_duration_string(dur_str).ok_or_else(|| SanitizeError::Incompatible {
                        path: format!("{path}.probeInterval"),
                        reason: "invalid duration string",
                    })?;
                if dur < MIN_PROBE_INTERVAL {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.probeInterval"),
                        reason: "probe interval below minimum",
                    });
                }
            }
            let sel_arr = obj
                .get("subjectSelector")
                .and_then(Value::as_array)
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "missing subjectSelector",
                })?;
            let prefixes: Vec<&str> = sel_arr.iter().filter_map(Value::as_str).collect();
            if prefixes.len() != sel_arr.len() {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "selector items must be strings",
                });
            }
            let mut subjects = Vec::new();
            for ob in &fragment_outbounds {
                let orig = &ob.orig_tag;
                let matches_selector = prefixes.iter().any(|p| {
                    if p.is_empty() {
                        true
                    } else if orig.is_empty() {
                        false
                    } else {
                        *p == orig.as_str() || orig.starts_with(p)
                    }
                });
                if matches_selector && !subjects.contains(&ob.tag) {
                    if ob.is_service || ob.is_loopback {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.subjectSelector"),
                            reason: "observatory selector matches service or loopback outbound",
                        });
                    }
                    subjects.push(ob.tag.clone());
                }
            }
            if subjects.is_empty() {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "observatory selector matches no outbounds",
                });
            }
            if subjects.len() > MAX_SELECTOR_MEMBERS {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "observatory selector exceeds maximum members",
                });
            }
            obs_subjects = subjects.iter().cloned().collect();
            fragment_observatory = Some(FragmentObservatory {
                is_burst: false,
                subjects,
                raw: obs.clone(),
            });
        } else if let Some(bobs) = burst_observatory {
            let path = "burstObservatory";
            let Some(obj) = bobs.as_object() else {
                return Err(SanitizeError::Incompatible {
                    path: path.into(),
                    reason: "burstObservatory must be an object",
                });
            };
            for k in obj.keys() {
                if !ALLOWED_BURST_OBSERVATORY_KEYS.contains(&k.as_str()) {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.{k}"),
                        reason: "unsupported burstObservatory key",
                    });
                }
            }
            let ping_cfg = obj
                .get("pingConfig")
                .and_then(Value::as_object)
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: format!("{path}.pingConfig"),
                    reason: "missing pingConfig",
                })?;
            for k in ping_cfg.keys() {
                if !ALLOWED_PING_CONFIG_KEYS.contains(&k.as_str()) {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.pingConfig.{k}"),
                        reason: "unsupported pingConfig key",
                    });
                }
            }
            if ping_cfg.get("connectivity").is_some() {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.pingConfig.connectivity"),
                    reason: "unsupported burst connectivity check",
                });
            }
            let dest = ping_cfg
                .get("destination")
                .and_then(Value::as_str)
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: format!("{path}.pingConfig.destination"),
                    reason: "missing destination URL",
                })?;
            if !validate_probe_url(dest) {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.pingConfig.destination"),
                    reason: "invalid destination URL",
                });
            }
            if let Some(interval_str) = ping_cfg.get("interval").and_then(Value::as_str) {
                let dur = parse_duration_string(interval_str).ok_or_else(|| {
                    SanitizeError::Incompatible {
                        path: format!("{path}.pingConfig.interval"),
                        reason: "invalid duration string",
                    }
                })?;
                if dur < MIN_PROBE_INTERVAL {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.pingConfig.interval"),
                        reason: "burst interval below minimum",
                    });
                }
            }
            if let Some(timeout_str) = ping_cfg.get("timeout").and_then(Value::as_str) {
                let dur = parse_duration_string(timeout_str).ok_or_else(|| {
                    SanitizeError::Incompatible {
                        path: format!("{path}.pingConfig.timeout"),
                        reason: "invalid duration string",
                    }
                })?;
                if dur.is_zero() || dur > MAX_BURST_TIMEOUT {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.pingConfig.timeout"),
                        reason: "burst timeout exceeds maximum",
                    });
                }
            }
            if let Some(sampling) = ping_cfg.get("sampling").and_then(Value::as_u64)
                && (sampling == 0 || sampling > MAX_BURST_SAMPLING)
            {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.pingConfig.sampling"),
                    reason: "burst sampling exceeds maximum",
                });
            }
            let sel_arr = obj
                .get("subjectSelector")
                .and_then(Value::as_array)
                .ok_or_else(|| SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "missing subjectSelector",
                })?;
            let prefixes: Vec<&str> = sel_arr.iter().filter_map(Value::as_str).collect();
            if prefixes.len() != sel_arr.len() {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "selector items must be strings",
                });
            }
            let mut subjects = Vec::new();
            for ob in &fragment_outbounds {
                let orig = &ob.orig_tag;
                let matches_selector = prefixes.iter().any(|p| {
                    if p.is_empty() {
                        true
                    } else if orig.is_empty() {
                        false
                    } else {
                        *p == orig.as_str() || orig.starts_with(p)
                    }
                });
                if matches_selector && !subjects.contains(&ob.tag) {
                    if ob.is_service || ob.is_loopback {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.subjectSelector"),
                            reason: "observatory selector matches service or loopback outbound",
                        });
                    }
                    subjects.push(ob.tag.clone());
                }
            }
            if subjects.is_empty() {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "observatory selector matches no outbounds",
                });
            }
            if subjects.len() > MAX_SELECTOR_MEMBERS {
                return Err(SanitizeError::Incompatible {
                    path: format!("{path}.subjectSelector"),
                    reason: "observatory selector exceeds maximum members",
                });
            }
            obs_subjects = subjects.iter().cloned().collect();
            fragment_observatory = Some(FragmentObservatory {
                is_burst: true,
                subjects,
                raw: bobs.clone(),
            });
        }

        let mut dropped_warnings = Vec::new();

        // Validate balancer observatory coverage
        for (i, b) in fragment_balancers.iter_mut().enumerate() {
            // A random or roundRobin balancer that names a fallback makes Xray
            // require an observatory, and without one Xray refuses to start.
            // Such a balancer never had health data to fall back on, so the
            // fallback is dropped (keeping its plain member choice) rather than
            // inventing probe traffic the provider did not configure.
            if fragment_observatory.is_none()
                && b.has_explicit_fallback
                && !is_observation_strategy(b.strategy.as_ref())
            {
                b.fallback_tag = None;
                b.has_explicit_fallback = false;
                dropped_warnings.push(format!("routing.balancers[{i}].fallbackTag"));
                continue;
            }
            if is_observation_strategy(b.strategy.as_ref()) || b.has_explicit_fallback {
                if fragment_observatory.is_none() {
                    return Err(SanitizeError::Incompatible {
                        path: format!("routing.balancers[{i}].strategy"),
                        reason: "balancer members not covered by observatory",
                    });
                }
                for m in &b.members {
                    if !obs_subjects.contains(m) {
                        return Err(SanitizeError::Incompatible {
                            path: format!("routing.balancers[{i}].strategy"),
                            reason: "balancer members not covered by observatory",
                        });
                    }
                }
            }
        }

        let raw_rules = routing
            .and_then(|r| r.get("rules"))
            .and_then(Value::as_array);

        struct ValidatedRule {
            inbound_tags: Vec<String>,
            is_virtual: bool,
            is_conditional: bool,
            target: TargetRef,
            map: Map<String, Value>,
        }

        let mut validated_rules = Vec::new();
        if let Some(rules) = raw_rules {
            for (i, r) in rules.iter().enumerate() {
                let path = format!("routing.rules[{i}]");
                let Some(r_obj) = r.as_object() else {
                    return Err(SanitizeError::Incompatible {
                        path,
                        reason: "rule must be an object",
                    });
                };
                for k in r_obj.keys() {
                    let known = RULE_METADATA_KEYS.contains(&k.as_str())
                        || XRAY_RULE_CONDITIONS.contains(&k.as_str());
                    if !known {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.{k}"),
                            reason: "unsupported rule field",
                        });
                    }
                }
                // Xray parses every routing rule as a field rule and never reads
                // `type`, so providers commonly omit it; it is not checked here.
                validate_network_field(r_obj, &path)?;

                let ob_tag = r_obj.get("outboundTag").and_then(Value::as_str);
                let bal_tag = r_obj.get("balancerTag").and_then(Value::as_str);
                let target = match (ob_tag, bal_tag) {
                    (Some(ot), None) => {
                        if !seen_tags.contains(ot) {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{path}.outboundTag"),
                                reason: "unknown outbound tag",
                            });
                        }
                        TargetRef::Outbound(ot.to_string())
                    }
                    (None, Some(bt)) => {
                        if !balancer_tags.contains(bt) {
                            return Err(SanitizeError::Incompatible {
                                path: format!("{path}.balancerTag"),
                                reason: "unknown balancer tag",
                            });
                        }
                        TargetRef::Balancer(bt.to_string())
                    }
                    _ => {
                        return Err(SanitizeError::Incompatible {
                            path,
                            reason: "rule must specify either outboundTag or balancerTag",
                        });
                    }
                };

                let in_tags: Vec<String> = match r_obj.get("inboundTag") {
                    Some(Value::String(s)) => vec![s.to_string()],
                    Some(Value::Array(a)) => {
                        let mut res = Vec::new();
                        for item in a {
                            if let Some(s) = item.as_str() {
                                res.push(s.to_string());
                            } else {
                                return Err(SanitizeError::Incompatible {
                                    path: format!("{path}.inboundTag"),
                                    reason: "inboundTag elements must be strings",
                                });
                            }
                        }
                        res
                    }
                    None => Vec::new(),
                    _ => {
                        return Err(SanitizeError::Incompatible {
                            path: format!("{path}.inboundTag"),
                            reason: "invalid inboundTag",
                        });
                    }
                };

                let virtual_count = in_tags
                    .iter()
                    .filter(|t| virtual_tags.contains(t.as_str()))
                    .count();
                let is_virtual = virtual_count == in_tags.len() && !in_tags.is_empty();
                if virtual_count > 0 && !is_virtual {
                    return Err(SanitizeError::Incompatible {
                        path: format!("{path}.inboundTag"),
                        reason: "cannot mix virtual and real inbound tags in a rule",
                    });
                }

                let is_conditional = is_rule_conditional(r_obj);
                if is_virtual && is_conditional {
                    return Err(SanitizeError::Incompatible {
                        path,
                        reason: "context-scoped conditional rules are not supported",
                    });
                }
                if !is_virtual && is_conditional {
                    dropped_warnings.push(format!("routing.rules[{i}]"));
                }

                validated_rules.push(ValidatedRule {
                    inbound_tags: in_tags,
                    is_virtual,
                    is_conditional,
                    target,
                    map: r_obj.clone(),
                });
            }
        }

        // Context targets
        let mut fragment_contexts = Vec::new();
        for vtag in &virtual_tags {
            let applicable: Vec<&ValidatedRule> = validated_rules
                .iter()
                .filter(|r| {
                    if r.is_virtual {
                        r.inbound_tags.iter().any(|t| t == vtag)
                    } else {
                        r.inbound_tags.is_empty() && !r.is_conditional
                    }
                })
                .collect();

            let tcp_target = applicable
                .iter()
                .find(|r| rule_covers_network(&r.map, "tcp"))
                .map(|r| r.target.clone())
                .unwrap_or_else(|| TargetRef::Outbound(default_handler.clone()));

            let udp_target = applicable
                .iter()
                .find(|r| rule_covers_network(&r.map, "udp"))
                .map(|r| r.target.clone())
                .unwrap_or_else(|| TargetRef::Outbound(default_handler.clone()));

            let target = if tcp_target == udp_target {
                tcp_target
            } else {
                let udp_is_service = match &udp_target {
                    TargetRef::Outbound(t) => fragment_outbounds
                        .iter()
                        .find(|o| o.tag == *t)
                        .map(|o| o.is_service)
                        .unwrap_or(false),
                    TargetRef::Balancer(_) => false,
                };
                if udp_is_service {
                    dropped_warnings.push(format!("routing.context[{vtag}].udpPolicy"));
                    tcp_target
                } else {
                    return Err(SanitizeError::Incompatible {
                        path: format!("routing.context[{vtag}]"),
                        reason: "ambiguous TCP and UDP targets",
                    });
                }
            };

            fragment_contexts.push(FragmentContext {
                virtual_tag: vtag.clone(),
                target,
            });
        }

        // External entry target
        let mut listener_unconditional_targets: Vec<(Vec<String>, TargetRef)> = Vec::new();
        for r in &validated_rules {
            if !r.is_virtual && !r.inbound_tags.is_empty() && !r.is_conditional {
                let mut tags = r.inbound_tags.clone();
                tags.sort();
                listener_unconditional_targets.push((tags, r.target.clone()));
            }
        }
        if !listener_unconditional_targets.is_empty() {
            let first_target = &listener_unconditional_targets[0].1;
            for (_tags, target) in &listener_unconditional_targets[1..] {
                if target != first_target {
                    return Err(SanitizeError::Incompatible {
                        path: "routing.rules".into(),
                        reason: "inbound rules have ambiguous targets",
                    });
                }
            }
        }

        let entry_applicable: Vec<&ValidatedRule> = validated_rules
            .iter()
            .filter(|r| !r.is_virtual && !r.is_conditional)
            .collect();

        let entry_tcp_target = entry_applicable
            .iter()
            .find(|r| rule_covers_network(&r.map, "tcp"))
            .map(|r| r.target.clone())
            .unwrap_or_else(|| TargetRef::Outbound(default_handler.clone()));

        let entry_udp_target = entry_applicable
            .iter()
            .find(|r| rule_covers_network(&r.map, "udp"))
            .map(|r| r.target.clone())
            .unwrap_or_else(|| TargetRef::Outbound(default_handler.clone()));

        let entry = if entry_tcp_target == entry_udp_target {
            entry_tcp_target
        } else {
            let udp_is_service = match &entry_udp_target {
                TargetRef::Outbound(t) => fragment_outbounds
                    .iter()
                    .find(|o| o.tag == *t)
                    .map(|o| o.is_service)
                    .unwrap_or(false),
                TargetRef::Balancer(_) => false,
            };
            if udp_is_service {
                dropped_warnings.push("routing.udpPolicy".to_string());
                entry_tcp_target
            } else {
                return Err(SanitizeError::Incompatible {
                    path: "routing.rules".into(),
                    reason: "ambiguous TCP and UDP targets",
                });
            }
        };

        // A loopback entry only re-enters routing, so what Kasumi's traffic
        // actually reaches is its context's target. Follow those hops (a cycle
        // among them is rejected by the graph check below) before deciding
        // whether the default route is a proxy.
        let mut effective_entry = entry.clone();
        for _ in 0..=fragment_contexts.len() {
            let TargetRef::Outbound(t) = &effective_entry else {
                break;
            };
            let Some(next) = fragment_outbounds
                .iter()
                .find(|o| o.tag == *t)
                .and_then(|o| o.loopback_inbound.as_deref())
                .and_then(|v| fragment_contexts.iter().find(|c| c.virtual_tag == v))
                .map(|c| c.target.clone())
            else {
                break;
            };
            effective_entry = next;
        }
        match &effective_entry {
            TargetRef::Outbound(t) => {
                let ob = fragment_outbounds.iter().find(|o| o.tag == *t).unwrap();
                if ob.is_service {
                    return Err(SanitizeError::Incompatible {
                        path: "routing".into(),
                        reason: "the profile's default route is not a proxy",
                    });
                }
            }
            TargetRef::Balancer(bt) => {
                let b = fragment_balancers.iter().find(|b| b.tag == *bt).unwrap();
                let all_service = b.members.iter().all(|m| {
                    fragment_outbounds
                        .iter()
                        .find(|o| o.tag == *m)
                        .map(|o| o.is_service)
                        .unwrap_or(false)
                });
                if all_service {
                    return Err(SanitizeError::Incompatible {
                        path: "routing.balancers".into(),
                        reason: "the profile's default route is not a proxy",
                    });
                }
            }
        }

        // Cycle detection
        let n_ob = fragment_outbounds.len();
        let n_bal = fragment_balancers.len();
        let n_ctx = fragment_contexts.len();
        let total_nodes = n_ob + n_bal + n_ctx;

        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); total_nodes];

        let ob_idx = |tag: &str| -> usize {
            fragment_outbounds
                .iter()
                .position(|o| o.tag == tag)
                .unwrap()
        };
        let bal_idx = |tag: &str| -> usize {
            n_ob + fragment_balancers
                .iter()
                .position(|b| b.tag == tag)
                .unwrap()
        };
        let ctx_idx = |vtag: &str| -> usize {
            n_ob + n_bal
                + fragment_contexts
                    .iter()
                    .position(|c| c.virtual_tag == vtag)
                    .unwrap()
        };
        let target_idx = |target: &TargetRef| -> usize {
            match target {
                TargetRef::Outbound(t) => ob_idx(t),
                TargetRef::Balancer(t) => bal_idx(t),
            }
        };

        for (i, b) in fragment_balancers.iter().enumerate() {
            let u = n_ob + i;
            for m in &b.members {
                adj[u].push(ob_idx(m));
            }
            if let Some(fallback) = &b.fallback_tag {
                adj[u].push(ob_idx(fallback));
            }
        }

        for (i, c) in fragment_contexts.iter().enumerate() {
            let u = n_ob + n_bal + i;
            adj[u].push(target_idx(&c.target));
        }

        for (i, ob) in fragment_outbounds.iter().enumerate() {
            if ob.is_loopback
                && let Some(ref vtag) = ob.loopback_inbound
            {
                adj[i].push(ctx_idx(vtag));
            }
            if let Some(ref dp) = ob.dialer_proxy {
                adj[i].push(ob_idx(dp));
            }
        }

        let mut state = vec![0u8; total_nodes];
        let mut depths = vec![0usize; total_nodes];
        fn dfs(
            u: usize,
            adj: &[Vec<usize>],
            state: &mut [u8],
            depths: &mut [usize],
        ) -> Result<(), SanitizeError> {
            state[u] = 1;
            let mut max_child_depth = 0;
            for &v in &adj[u] {
                if state[v] == 1 {
                    return Err(SanitizeError::Incompatible {
                        path: "routing".into(),
                        reason: "routing graph contains a cycle",
                    });
                }
                if state[v] == 0 {
                    dfs(v, adj, state, depths)?;
                }
                if depths[v] > max_child_depth {
                    max_child_depth = depths[v];
                }
            }
            let node_depth = max_child_depth + 1;
            if node_depth > MAX_GRAPH_DEPTH {
                return Err(SanitizeError::Incompatible {
                    path: "routing".into(),
                    reason: "routing graph exceeds depth limit",
                });
            }
            depths[u] = node_depth;
            state[u] = 2;
            Ok(())
        }

        for u in 0..total_nodes {
            if state[u] == 0 {
                dfs(u, &adj, &mut state, &mut depths)?;
            }
        }

        let plain_entry = match &entry {
            TargetRef::Outbound(t) => {
                let ob = fragment_outbounds.iter().find(|o| o.tag == *t).unwrap();
                let is_loopback = ob.is_loopback;
                let in_balancer = fragment_balancers
                    .iter()
                    .any(|b| b.members.contains(t) || b.fallback_tag.as_ref() == Some(t));
                let in_obs = fragment_observatory
                    .as_ref()
                    .is_some_and(|o| o.subjects.contains(t));
                let in_dialer = fragment_outbounds
                    .iter()
                    .any(|o| o.dialer_proxy.as_deref() == Some(t.as_str()));
                let in_context = fragment_contexts
                    .iter()
                    .any(|c| c.target == TargetRef::Outbound(t.clone()));
                !is_loopback && !in_balancer && !in_obs && !in_dialer && !in_context
            }
            TargetRef::Balancer(_) => false,
        };

        Ok(Self {
            outbounds: fragment_outbounds,
            balancers: fragment_balancers,
            observatory: fragment_observatory,
            contexts: fragment_contexts,
            default_handler,
            entry,
            plain_entry,
            dropped_warnings,
        })
    }

    pub fn render(&self, raw: &str) -> Result<ActiveOutbounds, String> {
        let seed = provider_outbounds_identity(raw).unwrap_or_else(|| {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(raw.as_bytes());
            digest.iter().map(|b| format!("{b:02x}")).collect()
        });

        let mut names_outbounds = BTreeMap::new();
        let mut names_balancers = BTreeMap::new();
        let mut names_vtags = BTreeMap::new();

        let plain_tag = if self.plain_entry {
            match &self.entry {
                TargetRef::Outbound(t) => Some(t.clone()),
                _ => None,
            }
        } else {
            None
        };

        for (i, ob) in self.outbounds.iter().enumerate() {
            if plain_tag.as_deref() == Some(ob.tag.as_str()) {
                names_outbounds.insert(ob.tag.clone(), "proxy".to_string());
            } else {
                let gen_tag = format!("ks-provider:{seed}:o:{i:08x}:");
                names_outbounds.insert(ob.tag.clone(), gen_tag);
            }
        }

        for (i, b) in self.balancers.iter().enumerate() {
            let gen_tag = format!("ks-provider:{seed}:b:{i:08x}:");
            names_balancers.insert(b.tag.clone(), gen_tag);
        }

        let mut sorted_vtags: Vec<String> = self
            .contexts
            .iter()
            .map(|c| c.virtual_tag.clone())
            .collect();
        sorted_vtags.sort();
        for (i, vtag) in sorted_vtags.into_iter().enumerate() {
            let gen_tag = format!("ks-provider:{seed}:v:{i:08x}:");
            names_vtags.insert(vtag, gen_tag);
        }

        let mut outbounds = Vec::new();
        if !self.plain_entry {
            outbounds.push(json!({
                "tag": "proxy",
                "protocol": "loopback",
                "settings": { "inboundTag": "proxy-select" },
            }));
        }

        for ob in &self.outbounds {
            let mut val = ob.raw.clone();
            let new_tag = names_outbounds.get(&ob.tag).unwrap();
            val["tag"] = new_tag.as_str().into();
            retarget_dialers(&mut val, &names_outbounds);
            retarget(
                val.get_mut("proxySettings").and_then(|p| p.get_mut("tag")),
                &names_outbounds,
            );
            if ob.is_loopback {
                retarget(
                    val.get_mut("settings")
                        .and_then(|s| s.get_mut("inboundTag")),
                    &names_vtags,
                );
            }
            outbounds.push(val);
        }

        let mut balancers = Vec::new();
        for b in &self.balancers {
            let new_tag = names_balancers.get(&b.tag).unwrap();
            let new_fallback = b
                .fallback_tag
                .as_ref()
                .map(|fallback| names_outbounds.get(fallback).unwrap());
            let new_selector: Vec<Value> = b
                .members
                .iter()
                .map(|m| Value::String(names_outbounds.get(m).unwrap().clone()))
                .collect();
            let mut b_val = json!({
                "tag": new_tag,
                "selector": new_selector,
            });
            // Only observation-driven strategies, or a balancer that already
            // names a fallback, can return an empty pick. Giving random or
            // roundRobin a fallbackTag would also make Xray start filtering
            // their members by health, which the provider did not ask for.
            if let Some(fallback) = new_fallback {
                b_val["fallbackTag"] = Value::String(fallback.clone());
            }
            if let Some(costs) = &b.resolved_costs {
                let mut strat = b
                    .strategy
                    .clone()
                    .unwrap_or_else(|| json!({"type": "leastLoad"}));
                let mut settings = strat.get("settings").cloned().unwrap_or_else(|| json!({}));
                let rendered_costs: Vec<Value> = costs
                    .iter()
                    .map(|(member_id, val)| {
                        json!({
                            "match": names_outbounds.get(member_id).unwrap(),
                            "regexp": false,
                            "value": val,
                        })
                    })
                    .collect();
                settings["costs"] = Value::Array(rendered_costs);
                strat["settings"] = settings;
                b_val["strategy"] = strat;
            } else if let Some(st) = &b.strategy {
                b_val["strategy"] = st.clone();
            }
            balancers.push(b_val);
        }

        let mut obs_out = None;
        let mut burst_obs_out = None;
        if let Some(obs) = &self.observatory {
            let mut val = obs.raw.clone();
            let new_subjects: Vec<Value> = obs
                .subjects
                .iter()
                .map(|s| Value::String(names_outbounds.get(s).unwrap().clone()))
                .collect();
            val["subjectSelector"] = Value::Array(new_subjects);
            if obs.is_burst {
                burst_obs_out = Some(val);
            } else {
                obs_out = Some(val);
            }
        }

        let mut rules = Vec::new();
        if !self.plain_entry {
            let mut select_rule = json!({
                "type": "field",
                "inboundTag": ["proxy-select"],
                "network": "tcp,udp",
            });
            match &self.entry {
                TargetRef::Outbound(t) => {
                    select_rule["outboundTag"] = names_outbounds.get(t).unwrap().as_str().into();
                }
                TargetRef::Balancer(t) => {
                    select_rule["balancerTag"] = names_balancers.get(t).unwrap().as_str().into();
                }
            }
            rules.push(select_rule);
        }

        let mut sorted_contexts = self.contexts.clone();
        sorted_contexts.sort_by(|a, b| a.virtual_tag.cmp(&b.virtual_tag));
        for ctx in &sorted_contexts {
            let namespaced_vtag = names_vtags.get(&ctx.virtual_tag).unwrap();
            let mut rule = json!({
                "type": "field",
                "inboundTag": [namespaced_vtag],
                "network": "tcp,udp",
            });
            match &ctx.target {
                TargetRef::Outbound(t) => {
                    rule["outboundTag"] = names_outbounds.get(t).unwrap().as_str().into();
                }
                TargetRef::Balancer(t) => {
                    rule["balancerTag"] = names_balancers.get(t).unwrap().as_str().into();
                }
            }
            rules.push(rule);
        }

        let target = match &self.entry {
            TargetRef::Outbound(t) => {
                let rendered_tag = names_outbounds.get(t).unwrap().clone();
                Target::Outbound(rendered_tag)
            }
            TargetRef::Balancer(t) => {
                let rendered_tag = names_balancers.get(t).unwrap().clone();
                let b = self.balancers.iter().find(|b| b.tag == *t).unwrap();
                let rendered_members = b
                    .members
                    .iter()
                    .map(|m| names_outbounds.get(m).unwrap().clone())
                    .collect();
                Target::Balancer {
                    tag: rendered_tag,
                    members: rendered_members,
                }
            }
        };

        Ok(ActiveOutbounds {
            outbounds,
            rules,
            balancers,
            target,
            observatory: obs_out,
            burst_observatory: burst_obs_out,
        })
    }
}

pub fn compile_custom_profile(
    c: &Custom,
    _profiles: &[Profile],
    kind: BuildKind,
) -> Result<ActiveOutbounds, String> {
    let reject = |reason: &str| match kind {
        BuildKind::Runtime => format!("provider config rejected: {reason}"),
        BuildKind::Probe => format!("cannot be tested: {reason}"),
    };
    let raw =
        parse_json_safe(&c.raw).ok_or_else(|| reject("custom profile contains invalid JSON"))?;
    let sanitized =
        crate::custom_sanitize::sanitize_provider_xray(&raw).map_err(|e| reject(&e.to_string()))?;

    if c.origin == CustomOrigin::Provider && c.meta.via.is_some() && !sanitized.fragment.plain_entry
    {
        return Err("provider config rejected: chaining (.via) on expanded loopback/fallback graphs is not supported".into());
    }

    sanitized.fragment.render(&c.raw).map_err(|e| reject(&e))
}

/// Whether a balancer strategy picks from observation results, and so can
/// come back empty when no member is currently qualified.
fn is_observation_strategy(strategy: Option<&Value>) -> bool {
    let kind = strategy.and_then(|s| s.get("type")).and_then(Value::as_str);
    matches!(kind, Some("leastPing" | "leastLoad"))
}

fn retarget(v: Option<&mut Value>, renames: &BTreeMap<String, String>) {
    if let Some(v) = v
        && let Some(new) = v.as_str().and_then(|t| renames.get(t))
    {
        *v = new.as_str().into();
    }
}

fn retarget_dialers(v: &mut Value, renames: &BTreeMap<String, String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                if k.eq_ignore_ascii_case("headers") {
                    continue;
                }
                if k == "dialerProxy" {
                    retarget(Some(child), renames);
                } else {
                    retarget_dialers(child, renames);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|c| retarget_dialers(c, renames)),
        _ => {}
    }
}
