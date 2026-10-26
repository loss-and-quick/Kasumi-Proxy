//! Build a complete Xray `config.json` from a Profile + AdvancedSettings.
//! Builds a `serde_json::Value` directly. The emitted config is validated against
//! the real core on PR by `core-compat.yml` (`tests/core_validation.rs`); targeted
//! invariants (e.g. inbound/routing shape) are covered by the unit tests below.

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Value, json};

use crate::chain::chain_hops;
use crate::config_shared::{build_ws_path, parse_pem_chain, split_delimited, split_list};
use crate::core::{core_conflict, xray_builds};
use crate::custom_sanitize::{
    drop_pinned_allow_insecure, is_service_outbound, provider_outbounds_identity,
    sanitize_provider_xray,
};
use crate::custom_target::{Target, default_target};
use crate::enums::{Fingerprint, HeaderType, Security};
use crate::mixins::Transport;
use crate::profile::{Custom, CustomOrigin, Profile, WG_DEFAULT_LOCAL_ADDRESS};
use crate::state::{
    AdvancedSettings, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT, DEFAULT_REMOTE_DNS,
    FAKEIP_INET4_RANGE, RoutingRule, force_socks_port,
};

fn parse_json_safe(s: &str) -> Option<Value> {
    serde_json::from_str(s).ok()
}

/// The wire string of a serde enum (e.g. `Network::Ws` → `"ws"`).
fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

// ---------- outbound protocol builders ----------

fn build_outbound_base(p: &Profile) -> Option<Map<String, Value>> {
    let ep = p.endpoint();
    let map = match p {
        Profile::Vmess(v) => json!({
            "tag": "proxy", "protocol": "vmess",
            "settings": { "vnext": [{
                "address": v.endpoint.address, "port": v.endpoint.port,
                "users": [{ "id": v.uuid, "alterId": v.alter_id, "security": wire(&v.encryption) }],
            }]},
        }),
        Profile::Vless(v) => {
            let mut user = json!({
                "id": v.uuid,
                "encryption": if v.encryption.is_empty() { "none".to_string() } else { v.encryption.clone() },
            });
            if v.flow != crate::enums::Flow::Empty {
                user["flow"] = wire(&v.flow).into();
            }
            json!({
                "tag": "proxy", "protocol": "vless",
                "settings": { "vnext": [{ "address": v.endpoint.address, "port": v.endpoint.port, "users": [user] }]},
            })
        }
        Profile::Trojan(t) => {
            // Xray rejects any trojan `flow` ("Flow for Trojan" was removed), so a
            // link that carries one connects without it.
            let server = json!({ "address": t.endpoint.address, "port": t.endpoint.port, "password": t.password });
            json!({ "tag": "proxy", "protocol": "trojan", "settings": { "servers": [server] } })
        }
        Profile::Shadowsocks(ss) => json!({
            "tag": "proxy", "protocol": "shadowsocks",
            "settings": { "servers": [{ "address": ss.endpoint.address, "port": ss.endpoint.port, "method": wire(&ss.method), "password": ss.password }]},
        }),
        Profile::Socks(sk) => {
            let mut server = json!({ "address": sk.endpoint.address, "port": sk.endpoint.port });
            if !sk.username.is_empty() {
                server["users"] = json!([{ "user": sk.username, "pass": sk.password }]);
            }
            json!({ "tag": "proxy", "protocol": "socks", "settings": { "servers": [server] } })
        }
        Profile::Http(h) => {
            let mut server = json!({ "address": h.endpoint.address, "port": h.endpoint.port });
            if !h.username.is_empty() {
                server["users"] = json!([{ "user": h.username, "pass": h.password }]);
            }
            json!({ "tag": "proxy", "protocol": "http", "settings": { "servers": [server] } })
        }
        Profile::Wireguard(w) => return Some(build_wireguard_outbound(w)),
        Profile::Hysteria2(_) => return Some(build_hysteria2_outbound(p)),
        // tuic / anytls / naive / shadowtls / custom can't build on xray.
        _ => return None,
    };
    let _ = ep;
    map.as_object().cloned()
}

fn build_wireguard_outbound(w: &crate::profile::Wireguard) -> Map<String, Value> {
    let reserved: Vec<i64> = w.reserved.iter().map(|&b| b as i64).collect();
    let mut address = split_delimited(&w.local_address);
    if address.is_empty() {
        address.push(WG_DEFAULT_LOCAL_ADDRESS.to_string());
    }
    let mut settings = json!({
        "secretKey": w.secret_key,
        "address": address,
        "mtu": if w.mtu != 0 { w.mtu } else { 1420 },
    });
    if w.workers != 0 {
        settings["numWorkers"] = w.workers.into();
    }
    if !reserved.is_empty() {
        settings["reserved"] = reserved.into();
    }
    let mut peer = json!({
        "publicKey": w.peer_public_key,
        "endpoint": format!("{}:{}", crate::share::host_for_uri(&w.endpoint.address), w.endpoint.port),
        "allowedIPs": ["0.0.0.0/0", "::/0"],
    });
    if !w.pre_shared_key.is_empty() {
        peer["preSharedKey"] = w.pre_shared_key.clone().into();
    }
    if w.persistent_keepalive != 0 {
        peer["keepAlive"] = w.persistent_keepalive.into();
    }
    settings["peers"] = json!([peer]);
    json!({ "tag": "proxy", "protocol": "wireguard", "settings": settings })
        .as_object()
        .cloned()
        .unwrap()
}

fn build_hysteria2_outbound(p: &Profile) -> Map<String, Value> {
    let Profile::Hysteria2(h) = p else {
        unreachable!()
    };
    let mut quic = Map::new();
    if !h.ports.trim().is_empty() && h.ports.contains([':', '-', ',']) {
        let interval = h
            .hop_interval
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite() && *v >= 5.0)
            .map(|v| {
                // Match JS Number→String (integers print without a decimal point).
                if v.fract() == 0.0 {
                    format!("{}", v as i64)
                } else {
                    format!("{v}")
                }
            })
            .unwrap_or_else(|| "30".to_string());
        quic.insert(
            "udpHop".into(),
            json!({ "ports": h.ports.replace(':', "-"), "interval": interval }),
        );
    }
    if h.up_mbps > 0 || h.down_mbps > 0 {
        quic.insert("congestion".into(), "brutal".into());
        if h.up_mbps > 0 {
            quic.insert("brutalUp".into(), format!("{}mbps", h.up_mbps).into());
        }
        if h.down_mbps > 0 {
            quic.insert("brutalDown".into(), format!("{}mbps", h.down_mbps).into());
        }
    } else {
        quic.insert("congestion".into(), "bbr".into());
    }
    let mut finalmask = json!({ "quicParams": quic });
    if h.obfs_type == crate::enums::Hysteria2Obfs::Salamander && !h.obfs_password.is_empty() {
        finalmask["udp"] =
            json!([{ "type": "salamander", "settings": { "password": h.obfs_password } }]);
    }
    // Xray 26.10 checks that the stream network is `hysteria`, not just that
    // `hysteriaSettings` is present.
    json!({
        "tag": "proxy", "protocol": "hysteria",
        "settings": { "version": 2, "address": h.endpoint.address, "port": h.endpoint.port },
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "sockopt": {},
            "tlsSettings": build_tls_security(p),
            "hysteriaSettings": { "version": 2, "auth": h.password },
            "finalmask": finalmask,
        },
    })
    .as_object()
    .cloned()
    .unwrap()
}

// ---------- stream settings builders ----------

fn build_tls_security(p: &Profile) -> Value {
    let tls = p.tls().unwrap();
    let host = p
        .transport()
        .map(|t| t.host().to_string())
        .unwrap_or_default();
    let address = p.endpoint().map(|e| e.address.clone()).unwrap_or_default();
    let server_name = if !tls.sni.is_empty() {
        tls.sni.clone()
    } else if !host.is_empty() {
        host
    } else {
        address
    };
    let mut m = Map::new();
    m.insert("serverName".into(), server_name.into());
    if tls.fingerprint != Fingerprint::Empty {
        m.insert("fingerprint".into(), wire(&tls.fingerprint).into());
    }
    if !tls.alpn.is_empty() {
        m.insert("alpn".into(), tls.alpn.clone().into());
    }
    if !tls.tls_min_version.is_empty() {
        m.insert("minVersion".into(), tls.tls_min_version.clone().into());
    }
    if !tls.tls_max_version.is_empty() {
        m.insert("maxVersion".into(), tls.tls_max_version.clone().into());
    }
    if !tls.tls_cipher_suites.is_empty() {
        // xray takes the suites as a single delimited string.
        m.insert(
            "cipherSuites".into(),
            tls.tls_cipher_suites.join(",").into(),
        );
    }
    if !tls.tls_curve_preferences.is_empty() {
        m.insert(
            "curvePreferences".into(),
            tls.tls_curve_preferences.clone().into(),
        );
    }
    let certs: Vec<Value> = parse_pem_chain(&tls.cert)
        .map(|list| {
            list.iter()
                .map(|cert| {
                    let lines: Vec<String> = cert
                        .split('\n')
                        .map(|l| l.trim_end_matches('\r').to_string())
                        .filter(|l| !l.is_empty())
                        .collect();
                    json!({ "certificate": lines })
                })
                .collect()
        })
        .unwrap_or_default();
    let has_certs = !certs.is_empty();
    if has_certs {
        m.insert("certificates".into(), certs.into());
    }
    if tls.disable_system_root || has_certs {
        m.insert("disableSystemRoot".into(), true.into());
    }
    if !tls.pcs.is_empty() {
        m.insert("pinnedPeerCertSha256".into(), tls.pcs.clone().into());
    }
    if !tls.ech.is_empty() {
        m.insert("echConfigList".into(), tls.ech.clone().into());
    }
    if !tls.vcn.is_empty() {
        m.insert("verifyPeerCertByName".into(), tls.vcn.clone().into());
    }
    if tls.reject_unknown_sni {
        m.insert("rejectUnknownSni".into(), true.into());
    }
    if tls.enable_session_resumption {
        m.insert("enableSessionResumption".into(), true.into());
    }
    Value::Object(m)
}

fn build_reality_security(p: &Profile) -> Value {
    let tls = p.tls().unwrap();
    let mut m = Map::new();
    m.insert("serverName".into(), tls.sni.clone().into());
    if tls.fingerprint != Fingerprint::Empty {
        m.insert("fingerprint".into(), wire(&tls.fingerprint).into());
    }
    m.insert("publicKey".into(), tls.public_key.clone().into());
    if !tls.short_id.is_empty() {
        m.insert("shortId".into(), tls.short_id.clone().into());
    }
    if !tls.spider_x.is_empty() {
        m.insert("spiderX".into(), tls.spider_x.clone().into());
    }
    if !tls.pqv.is_empty() {
        m.insert("mldsa65Verify".into(), tls.pqv.clone().into());
    }
    Value::Object(m)
}

/// `(transportKey, value)` for the profile's network, or `None`.
fn build_transport_setting(p: &Profile) -> Option<(&'static str, Value)> {
    let t = p.transport()?;
    let tls = p.tls();
    let sni = tls.map(|x| x.sni.clone()).unwrap_or_default();
    let host_or_sni = if t.host().is_empty() {
        sni.clone()
    } else {
        t.host().to_string()
    };
    match t {
        Transport::Ws(w) => {
            let path = build_ws_path(
                if w.path.is_empty() { "/" } else { &w.path },
                w.early_data,
                &w.early_data_header,
            );
            let mut v = json!({ "path": path, "host": host_or_sni });
            if w.heartbeat_period != 0 {
                v["heartbeatPeriod"] = w.heartbeat_period.into();
            }
            if w.accept_proxy_protocol {
                v["acceptProxyProtocol"] = true.into();
            }
            if !w.headers.is_empty() {
                v["header"] = json!(w.headers);
            }
            Some(("wsSettings", v))
        }
        Transport::Httpupgrade(h) => {
            let mut v = json!({ "path": if h.path.is_empty() { "/".into() } else { h.path.clone() }, "host": host_or_sni });
            if h.accept_proxy_protocol {
                v["acceptProxyProtocol"] = true.into();
            }
            if h.early_data != 0 {
                v["ed"] = h.early_data.into();
            }
            Some(("httpupgradeSettings", v))
        }
        Transport::Grpc(g) => {
            // The parser already folds the host/path fallbacks into authority and
            // service_name, so both are read straight here.
            let mut v = json!({
                "serviceName": g.service_name.clone(),
                "authority": g.authority.clone(),
            });
            if g.mode == "multi" {
                v["multiMode"] = true.into();
            }
            if g.idle_timeout != 0 {
                v["idle_timeout"] = g.idle_timeout.into();
            }
            if g.health_check_timeout != 0 {
                v["health_check_timeout"] = g.health_check_timeout.into();
            }
            if g.permit_without_stream {
                v["permit_without_stream"] = true.into();
            }
            if g.initial_window_size != 0 {
                // Xray's own config key carries the historical "windows" typo.
                v["initial_windows_size"] = g.initial_window_size.into();
            }
            if !g.user_agent.is_empty() {
                v["user_agent"] = g.user_agent.clone().into();
            }
            Some(("grpcSettings", v))
        }
        Transport::Xhttp(x) => {
            let mut v = json!({ "path": if x.path.is_empty() { "/".into() } else { x.path.clone() }, "host": host_or_sni });
            if !x.mode.is_empty() {
                v["mode"] = x.mode.clone().into();
            }
            if !x.extra.is_empty() {
                v["extra"] =
                    parse_json_safe(&x.extra).unwrap_or_else(|| Value::String(x.extra.clone()));
            }
            Some(("xhttpSettings", v))
        }
        Transport::Tcp(tc) => {
            if tc.header_type != HeaderType::Http {
                return None;
            }
            let headers = if tc.host.is_empty() {
                json!({})
            } else {
                json!({ "Host": split_delimited(&tc.host) })
            };
            Some((
                "tcpSettings",
                json!({ "header": { "type": "http", "request": { "path": [if tc.path.is_empty() { "/".into() } else { tc.path.clone() }], "headers": headers } } }),
            ))
        }
        Transport::Kcp(k) => {
            let mut v = Map::new();
            if k.mtu != 0 {
                v.insert("mtu".into(), k.mtu.into());
            }
            if k.tti != 0 {
                v.insert("tti".into(), k.tti.into());
            }
            if k.uplink != 0 {
                v.insert("uplinkCapacity".into(), k.uplink.into());
            }
            if k.downlink != 0 {
                v.insert("downlinkCapacity".into(), k.downlink.into());
            }
            if k.cwnd_multiplier != 0 {
                v.insert("cwndMultiplier".into(), k.cwnd_multiplier.into());
            }
            // Xray 26.10 rejects a maxSendingWindow below the MTU (it divides
            // down to a zero-packet window); leave those to the core default.
            let mtu = if k.mtu > 0 { k.mtu } else { 1350 };
            if k.max_sending_window >= mtu {
                v.insert("maxSendingWindow".into(), k.max_sending_window.into());
            }
            Some(("kcpSettings", Value::Object(v)))
        }
        Transport::H2(_) | Transport::Quic(_) => None,
    }
}

fn build_fragment_settings(s: &AdvancedSettings) -> Option<Value> {
    if !s.fragment {
        return None;
    }
    Some(json!({
        "packets": if s.fragment_packets.is_empty() { "tlshello".to_string() } else { s.fragment_packets.clone() },
        "length": s.fragment_length.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| "50-100".into()),
        "delay": s.fragment_delay.clone().filter(|x| !x.is_empty()).unwrap_or_else(|| "10-20".into()),
    }))
}

fn build_mux_settings(p: &Profile, s: &AdvancedSettings) -> Option<Value> {
    if !p.mux_enabled() {
        return None;
    }
    let mut v = json!({
        "enabled": true,
        "concurrency": if s.mux_concurrency != 0 { s.mux_concurrency } else { 8 },
    });
    if let Some(xc) = s.mux_xudp_concurrency {
        v["xudpConcurrency"] = xc.into();
    }
    if let Some(x443) = s.mux_xudp443 {
        v["xudpProxyUDP443"] = wire(&x443).into();
    }
    Some(v)
}

fn empty_stream(p: &Profile) -> Map<String, Value> {
    let network = p
        .transport()
        .map(|t| wire(&t.network()))
        .unwrap_or_else(|| "tcp".into());
    let security = p
        .tls()
        .map(|x| wire(&x.security))
        .unwrap_or_else(|| "none".into());
    json!({ "network": network, "security": security, "sockopt": {} })
        .as_object()
        .cloned()
        .unwrap()
}

fn is_stream(p: &Profile) -> bool {
    p.transport().is_some()
}

/// Build the outbound `proxy` object for a profile (None if it can't run on xray).
fn build_outbound(p: &Profile, s: &AdvancedSettings) -> Option<Value> {
    if !xray_builds(p) {
        return None;
    }
    let mut outbound = build_outbound_base(p)?;
    // hysteria2 already carries complete streamSettings.
    if matches!(p, Profile::Hysteria2(_)) {
        return Some(Value::Object(outbound));
    }

    // TLS / Reality apply to stream protocols and http.
    if let Some(tls) = p.tls() {
        if tls.security == Security::Tls {
            let mut stream = outbound
                .get("streamSettings")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_else(|| empty_stream(p));
            stream.insert("tlsSettings".into(), build_tls_security(p));
            outbound.insert("streamSettings".into(), Value::Object(stream));
        } else if tls.security == Security::Reality {
            let mut stream = outbound
                .get("streamSettings")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_else(|| empty_stream(p));
            stream.insert("realitySettings".into(), build_reality_security(p));
            outbound.insert("streamSettings".into(), Value::Object(stream));
        }
    }

    // Transport + fragment + mux apply to stream protocols only.
    if is_stream(p) {
        let mut stream = outbound
            .get("streamSettings")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_else(|| empty_stream(p));
        stream.insert(
            "network".into(),
            wire(&p.transport().unwrap().network()).into(),
        );
        if let Some((key, value)) = build_transport_setting(p) {
            stream.insert(key.into(), value);
        }
        if let Some(fragment) = build_fragment_settings(s) {
            let mut finalmask = stream
                .get("finalmask")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            finalmask.insert(
                "tcp".into(),
                json!([{ "type": "fragment", "settings": fragment }]),
            );
            stream.insert("finalmask".into(), Value::Object(finalmask));
        }
        outbound.insert("streamSettings".into(), Value::Object(stream));

        if let Some(mux) = build_mux_settings(p, s) {
            outbound.insert("mux".into(), mux);
        }
    }

    Some(Value::Object(outbound))
}

// ---------- routing / dns / rules ----------

const SPECIAL_OUTBOUND_TAGS: [&str; 3] = ["proxy", "direct", "block"];
const DNS_OUT: &str = "dns-out";
/// The fictional inbound tag `proxy` re-enters routing on when a provider's
/// default path is a balancer: a loopback outbound hands the traffic back to the
/// router as if it had arrived on this inbound, where one rule sends it on.
const PROXY_SELECT: &str = "proxy-select";

/// The field-rule keys Xray matches on (`RawFieldRule` in Xray's
/// infra/conf/router.go). Xray refuses to start on a rule with none of them set:
/// "this rule has no effective fields".
const XRAY_RULE_CONDITIONS: [&str; 17] = [
    "domain",
    "domains",
    "ip",
    "port",
    "network",
    "sourceIP",
    "source",
    "sourcePort",
    "user",
    "vlessRoute",
    "inboundTag",
    "protocol",
    "attrs",
    "localIP",
    "localPort",
    "process",
    "localOS",
];

/// Whether an Xray field rule has a condition Xray accepts.
pub fn xray_rule_has_condition(rule: &Map<String, Value>) -> bool {
    let set = |v: &Value| match v {
        Value::Null => false,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    };
    XRAY_RULE_CONDITIONS
        .iter()
        .any(|k| rule.get(*k).is_some_and(set))
}

/// `None` when the rule names domains or IPs but every entry is blank or a `#`
/// comment: left with its port or network alone it would match far more.
fn build_rule_object(rule: &RoutingRule, resolve: &dyn Fn(&str) -> String) -> Option<Value> {
    let mut m = Map::new();
    m.insert("type".into(), "field".into());
    for (key, list) in [("domain", &rule.domain), ("ip", &rule.ip)] {
        let Some(list) = list.as_ref().filter(|l| !l.is_empty()) else {
            continue;
        };
        let kept: Vec<&str> = list
            .iter()
            .map(|e| e.trim())
            .filter(|e| !e.is_empty() && !e.starts_with('#'))
            .collect();
        if kept.is_empty() {
            return None;
        }
        m.insert(key.into(), json!(kept));
    }
    if let Some(port) = &rule.port
        && !port.is_empty()
    {
        m.insert("port".into(), port.clone().into());
    }
    if let Some(net) = &rule.network {
        m.insert("network".into(), wire(net).into());
    }
    if let Some(proto) = &rule.protocol
        && !proto.is_empty()
    {
        m.insert("protocol".into(), json!(proto));
    }
    if let Some(process) = &rule.process
        && !process.is_empty()
    {
        m.insert("process".into(), json!(process));
    }
    if let Some(source) = &rule.source_ip
        && !source.is_empty()
    {
        m.insert("sourceIP".into(), json!(source));
    }
    m.insert("outboundTag".into(), resolve(&rule.outbound_tag).into());
    Some(Value::Object(m))
}

struct ProfileOutbounds {
    outbounds: Vec<Value>,
    resolved: std::collections::HashMap<String, String>,
}

fn build_profile_outbounds(
    active: &Profile,
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
) -> ProfileOutbounds {
    let mut resolved = std::collections::HashMap::new();
    let mut outbounds = Vec::new();
    if s.routing_mode == crate::state::RoutingMode::Rules {
        let mut referenced: Vec<String> = Vec::new();
        for r in routing_rules {
            if r.enabled
                && !SPECIAL_OUTBOUND_TAGS.contains(&r.outbound_tag.as_str())
                && !referenced.contains(&r.outbound_tag)
            {
                referenced.push(r.outbound_tag.clone());
            }
        }
        for id in referenced {
            if id == active.meta().id {
                resolved.insert(id, "proxy".to_string());
                continue;
            }
            match profiles.iter().find(|p| p.meta().id == id) {
                Some(profile) => match build_outbound(profile, s) {
                    Some(mut ob) => {
                        if let Some(obj) = ob.as_object_mut() {
                            obj.insert("tag".into(), id.clone().into());
                        }
                        outbounds.push(ob);
                        resolved.insert(id.clone(), id);
                    }
                    None => {
                        resolved.insert(id, "proxy".to_string());
                    }
                },
                None => {
                    resolved.insert(id, "proxy".to_string());
                }
            }
        }
    }
    ProfileOutbounds {
        outbounds,
        resolved,
    }
}

/// Make `ob` dial its server through the outbound tagged `via`.
fn set_dialer_proxy(ob: &mut Value, via: &str) {
    let stream = ob
        .as_object_mut()
        .expect("outbound is an object")
        .entry("streamSettings")
        .or_insert_with(|| json!({}));
    let sockopt = stream
        .as_object_mut()
        .expect("streamSettings is an object")
        .entry("sockopt")
        .or_insert_with(|| json!({}));
    sockopt["dialerProxy"] = via.into();
}

/// Chain the outbound built for `p` to its hops ([`chain_hops`]): `ob` dials
/// through the first hop, each hop through the next, and every hop not yet in the
/// config is appended to `outbounds`, tagged by its profile id like the routing
/// targets (`emitted` holds the tags already present).
fn attach_chain(
    p: &Profile,
    ob: &mut Value,
    s: &AdvancedSettings,
    profiles: &[Profile],
    outbounds: &mut Vec<Value>,
    emitted: &mut HashSet<String>,
) -> Result<(), String> {
    let hops = chain_hops(p, profiles)?;
    let Some(first) = hops.first() else {
        return Ok(());
    };
    set_dialer_proxy(ob, &first.meta().id);
    for (i, hop) in hops.iter().enumerate() {
        let tag = &hop.meta().id;
        if !emitted.insert(tag.clone()) {
            continue;
        }
        let mut hop_ob = build_outbound(hop, s).ok_or_else(|| match core_conflict(hop) {
            Some(c) => format!("proxy chain hop \"{}\": {c}", hop.meta().remarks),
            None => format!(
                "proxy chain hop \"{}\" ({:?}) requires sing-box",
                hop.meta().remarks,
                hop.protocol()
            ),
        })?;
        hop_ob["tag"] = tag.as_str().into();
        if let Some(next) = hops.get(i + 1) {
            set_dialer_proxy(&mut hop_ob, &next.meta().id);
        }
        outbounds.push(hop_ob);
    }
    Ok(())
}

fn parse_hosts(v: &str) -> Option<Value> {
    if v.trim().is_empty() {
        return None;
    }
    if let Some(Value::Object(o)) = parse_json_safe(v.trim()) {
        return Some(Value::Object(o));
    }
    let mut out = Map::new();
    for line in v.split('\n') {
        let mut parts = line.splitn(2, '=');
        let host = parts.next().unwrap_or("").trim();
        let ip = parts.next().unwrap_or("").trim();
        if !host.is_empty() && !ip.is_empty() {
            out.insert(host.to_string(), ip.to_string().into());
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

fn build_dns(s: &AdvancedSettings) -> Value {
    let remote = split_list(s.remote_dns.as_deref().unwrap_or(""), &DEFAULT_REMOTE_DNS);
    let mut servers: Vec<Value> = remote.into_iter().map(Value::from).collect();
    if s.fake_dns {
        servers.insert(
            0,
            json!({ "address": "fakeip", "domains": ["regexp:.+"], "expectIPs": ["geoip:!private"] }),
        );
    }
    let query_strategy = if s.ipv6_enabled.unwrap_or(false) {
        "UseIP"
    } else {
        "UseIPv4"
    };
    let mut m = json!({ "servers": servers, "queryStrategy": query_strategy });
    if let Some(hosts) = parse_hosts(s.dns_hosts.as_deref().unwrap_or("")) {
        m["hosts"] = hosts;
    }
    m
}

/// `provider_rules` go after Kasumi's own rules, so Kasumi's direct/block win, but
/// before the catch-all to `proxy`, which would leave them unreachable.
fn build_routing(
    s: &AdvancedSettings,
    dns_outbound_tag: &str,
    routing_rules: &[RoutingRule],
    resolve: &dyn Fn(&str) -> String,
    internal_rules: &[Value],
    provider_rules: &[Value],
) -> Value {
    let domain_strategy = wire(&s.domain_strategy);
    // Bypass-geo rule for the always-on `force-in` inbound — pushed first so traffic
    // arriving there reaches `proxy` ahead of the geo/user rules.
    let force_rule = json!({ "type": "field", "inboundTag": ["force-in"], "network": "tcp,udp", "outboundTag": "proxy" });
    let dns_rule = json!({ "type": "field", "inboundTag": ["socks-in", "http-in"], "port": 53, "outboundTag": dns_outbound_tag });
    let final_rule = json!({ "type": "field", "inboundTag": ["socks-in", "http-in"], "network": "tcp,udp", "outboundTag": "proxy" });

    // The proxy-select alias rule sends re-entering loopback traffic to its
    // balancer, and internal loopback fallback rules route internal cascades.
    // They must precede user rules: a user rule without inboundTag
    // (the normal case) targeting `proxy` would otherwise match the
    // re-entering connection and send it into an infinite loop or capture it.
    let mut prefix_rules = vec![force_rule];
    prefix_rules.extend(internal_rules.iter().cloned());
    prefix_rules.push(dns_rule);

    if s.routing_mode == crate::state::RoutingMode::Rules && !routing_rules.is_empty() {
        let mut rules: Vec<Value> = prefix_rules;
        // xray can't tell which Android package opened a connection. Dropping just
        // the package condition would widen the rule to every app, so a rule that
        // names packages is left out on xray entirely.
        // A rule left with no condition matches nothing here and stops Xray.
        rules.extend(
            routing_rules
                .iter()
                .filter(|r| r.enabled && r.package_name.as_ref().is_none_or(Vec::is_empty))
                .filter_map(|r| build_rule_object(r, resolve))
                .filter(|r| r.as_object().is_some_and(xray_rule_has_condition)),
        );
        rules.extend(provider_rules.iter().cloned());
        rules.push(final_rule);
        return json!({ "domainStrategy": domain_strategy, "rules": rules });
    }

    if s.routing_mode == crate::state::RoutingMode::Custom
        && let Some(cr) = s.custom_routing.as_deref().filter(|x| !x.trim().is_empty())
        && let Some(Value::Array(parsed)) = parse_json_safe(cr)
    {
        let mut rules: Vec<Value> = prefix_rules;
        rules.extend(
            parsed
                .into_iter()
                .filter(|r| r.as_object().is_none_or(xray_rule_has_condition)),
        );
        rules.extend(provider_rules.iter().cloned());
        rules.push(final_rule);
        return json!({ "domainStrategy": domain_strategy, "rules": rules });
    }

    let mut rules: Vec<Value> = prefix_rules;
    if s.fake_dns {
        rules.push(json!({ "type": "field", "ip": [FAKEIP_INET4_RANGE], "outboundTag": "proxy" }));
    }
    rules.extend(provider_rules.iter().cloned());
    rules.push(final_rule);
    json!({ "domainStrategy": domain_strategy, "rules": rules })
}

/// A probe's test-core config, and the `proxy` target it was built around.
pub struct ProbeConfig {
    pub config: Value,
    pub target: Target,
}

/// Whether a build is the config Kasumi launches or a probe's test core.
#[derive(Clone, Copy)]
enum BuildKind {
    Runtime,
    Probe,
}

/// Build the full Xray config object from a profile + settings.
pub fn build_xray_config(
    p: &Profile,
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
) -> Result<Value, String> {
    build_config(p, s, routing_rules, profiles, BuildKind::Runtime).map(|(config, _)| config)
}

/// Build the config a probe's test core runs: Kasumi's inbounds on the leased
/// ports and the profile's default path, without the user's routing and without a
/// provider's conditional rules. Identical to [`build_xray_config`] for a typed
/// profile; a custom one runs the sanitised view of itself, so the probe measures
/// the path Kasumi will really send traffic through.
pub fn build_xray_probe_config(
    p: &Profile,
    s: &AdvancedSettings,
    profiles: &[Profile],
) -> Result<ProbeConfig, String> {
    let (config, target) = build_config(p, s, &[], profiles, BuildKind::Probe)?;
    Ok(ProbeConfig { config, target })
}

fn build_config(
    p: &Profile,
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
    kind: BuildKind,
) -> Result<(Value, Target), String> {
    if let Profile::Custom(_) = p
        && let Some(c) = core_conflict(p)
    {
        return Err(c.to_string());
    }
    let provider = match (p, kind) {
        // A user's own config runs as written: nothing it says may be rewritten.
        (Profile::Custom(c), BuildKind::Runtime) if c.origin == CustomOrigin::User => {
            return match parse_json_safe(&c.raw) {
                Some(mut v @ Value::Object(_)) => {
                    // Runs as written, but for the key xray refuses that a pin makes moot.
                    drop_pinned_allow_insecure(&mut v, "", &mut Vec::new());
                    Ok((v, Target::Outbound("proxy".into())))
                }
                _ => Err("custom profile contains invalid JSON".to_string()),
            };
        }
        // A custom probe owns its listeners but preserves the same internal path
        // compiler as provider runtime: the reported target must carry its traffic.
        (Profile::Custom(c), _) => compile_custom_graph(c, kind)?,
        _ => ActiveOutbounds {
            outbounds: vec![build_outbound(p, s).ok_or_else(|| match core_conflict(p) {
                Some(c) => c.to_string(),
                None => format!("{:?} requires sing-box", p.protocol()),
            })?],
            rules: Vec::new(),
            internal_rules: Vec::new(),
            balancers: Vec::new(),
            target: Target::Outbound("proxy".into()),
            observatory: None,
            burst_observatory: None,
        },
    };
    let po = build_profile_outbounds(p, s, routing_rules, profiles);
    let resolve = |tag: &str| -> String {
        if SPECIAL_OUTBOUND_TAGS.contains(&tag) {
            tag.to_string()
        } else {
            po.resolved
                .get(tag)
                .cloned()
                .unwrap_or_else(|| "proxy".into())
        }
    };

    let socks_port = s.local_socks_port.unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
    let http_port = s.local_http_port.unwrap_or(DEFAULT_LOCAL_HTTP_PORT);
    let force_port = force_socks_port(socks_port, http_port);
    let dns_outbound_tag = if s.dns_via_proxy { "proxy" } else { "direct" };
    let listen = if s.allow_non_localhost {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    let log_level = s
        .log_level
        .map(|l| wire(&l))
        .unwrap_or_else(|| "warning".into());

    // Optional auth on the user-facing socks/http inbound (Settings →
    // socksUsername/socksPassword, both required). xray gates socks behind
    // `auth: "password"` + `accounts`; http just takes `accounts`.
    let socks_auth = s
        .socks_username
        .as_deref()
        .filter(|u| !u.is_empty())
        .zip(s.socks_password.as_deref().filter(|p| !p.is_empty()));
    let socks_settings = match socks_auth {
        Some((u, p)) => {
            json!({ "auth": "password", "accounts": [{ "user": u, "pass": p }], "udp": true })
        }
        None => json!({ "auth": "noauth", "udp": true }),
    };
    let http_settings = match socks_auth {
        Some((u, p)) => {
            json!({ "allowTransparent": false, "accounts": [{ "user": u, "pass": p }] })
        }
        None => json!({ "allowTransparent": false }),
    };

    let mut inbounds = vec![
        json!({
            "tag": "socks-in", "port": socks_port, "listen": listen, "protocol": "socks",
            "settings": socks_settings,
            "sniffing": { "enabled": s.domain_sniffing, "destOverride": ["http", "tls", "quic"], "routeOnly": s.route_only },
        }),
        json!({
            "tag": "http-in", "port": http_port, "listen": listen, "protocol": "http",
            "settings": http_settings,
        }),
    ];
    // Always-on bypass-geo inbound: routes straight to `proxy` (see `force_rule`),
    // used by the app's own fetches and per-app force-proxy. Localhost-only and
    // noauth regardless of `allow_non_localhost` — it must never be reachable off-box.
    inbounds.push(json!({
        "tag": "force-in", "port": force_port, "listen": "127.0.0.1", "protocol": "socks",
        "settings": { "auth": "noauth", "udp": true },
    }));

    let ActiveOutbounds {
        outbounds: mut head,
        rules: provider_rules,
        internal_rules,
        balancers,
        target,
        observatory,
        burst_observatory,
    } = provider;

    let mut targets = po.outbounds.clone();
    let mut hops: Vec<Value> = Vec::new();
    let mut emitted: HashSet<String> = targets
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    // User raw runtime ignores external chain metadata; its isolated probe must
    // not invent a chain that the config it measures never uses.
    if !matches!(p, Profile::Custom(c) if c.origin == CustomOrigin::User) {
        for entry in chain_entries(&head, &target)? {
            attach_chain(p, &mut head[entry], s, profiles, &mut hops, &mut emitted)?;
        }
    }
    for target in &mut targets {
        let id = target["tag"].as_str().unwrap_or_default().to_string();
        if let Some(tp) = profiles.iter().find(|x| x.meta().id == id) {
            attach_chain(tp, target, s, profiles, &mut hops, &mut emitted)?;
        }
    }

    let mut outbounds = head;
    outbounds.extend(targets);
    outbounds.extend(hops);
    outbounds.push(json!({ "protocol": "freedom", "tag": "direct" }));
    outbounds.push(json!({ "protocol": "blackhole", "tag": "block" }));

    let mut routing = build_routing(
        s,
        dns_outbound_tag,
        routing_rules,
        &resolve,
        &internal_rules,
        &provider_rules,
    );
    if !balancers.is_empty() {
        routing["balancers"] = balancers.into();
    }
    let mut config_map = json!({
        "log": { "loglevel": log_level },
        "dns": build_dns(s),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing,
    });
    if let Some(obs) = observatory {
        config_map["observatory"] = obs;
    }
    if let Some(bobs) = burst_observatory {
        config_map["burstObservatory"] = bobs;
    }
    Ok((config_map, target))
}

/// The active profile's outbounds, `proxy` first, and for a provider config the
/// routing between them and the target `proxy` stands for.
struct ActiveOutbounds {
    outbounds: Vec<Value>,
    rules: Vec<Value>,
    internal_rules: Vec<Value>,
    balancers: Vec<Value>,
    target: Target,
    observatory: Option<Value>,
    burst_observatory: Option<Value>,
}

struct ProviderNames {
    outbounds: BTreeMap<String, String>,
    balancers: BTreeMap<String, String>,
    virtual_inbounds: BTreeMap<String, String>,
}

fn build_provider_names(
    raw: &str,
    outbounds: &[Value],
    balancers: &[Value],
    virtual_tags: &HashSet<String>,
) -> Result<(ProviderNames, String), String> {
    // The seed comes from the validated connection content, not the profile id: a
    // refresh that only re-rolls a REALITY pick or id keeps every generated name,
    // so an unchanged graph is not mistaken for a changed one.
    let identity = provider_outbounds_identity(raw)
        .ok_or("provider config rejected: cannot establish a stable namespace seed")?;
    let seed = identity;
    let seed = seed.as_str();

    let mut names = ProviderNames {
        outbounds: BTreeMap::new(),
        balancers: BTreeMap::new(),
        virtual_inbounds: BTreeMap::new(),
    };

    for (i, ob) in outbounds.iter().enumerate() {
        let gen_tag = format!("ks-provider:{seed}:o:{i:08x}:");
        if let Some(orig_tag) = ob.get("tag").and_then(Value::as_str) {
            names
                .outbounds
                .insert(orig_tag.to_string(), gen_tag.clone());
        }
    }

    for (i, b) in balancers.iter().enumerate() {
        let gen_tag = format!("ks-provider:{seed}:b:{i:08x}:");
        if let Some(orig_tag) = b.get("tag").and_then(Value::as_str) {
            names.balancers.insert(orig_tag.to_string(), gen_tag);
        }
    }

    let mut sorted_vtags: Vec<String> = virtual_tags.iter().cloned().collect();
    sorted_vtags.sort();
    for (i, vtag) in sorted_vtags.into_iter().enumerate() {
        let gen_tag = format!("ks-provider:{seed}:v:{i:08x}:");
        names.virtual_inbounds.insert(vtag, gen_tag);
    }

    Ok((names, seed.to_string()))
}

/// Fit a provider config's sanitised outbounds into Kasumi's skeleton using a uniform
/// client-owned loopback alias. The target the profile itself carries its traffic to is
/// reached through `proxy` (loopback → `PROXY_SELECT` rule → namespaced target), so that
/// outer user routing chooses the profile once and internal transitions stay inside the
/// provider graph without recursion or capture. Provider outbounds, balancers, and
/// virtual inbounds receive prefix-free namespaced tags, preserving prefix-free observer
/// matching and tag independence.
fn compile_custom_graph(c: &Custom, kind: BuildKind) -> Result<ActiveOutbounds, String> {
    let reject = |reason: &str| match kind {
        BuildKind::Runtime => format!("provider config rejected: {reason}"),
        BuildKind::Probe => format!("cannot be tested: {reason}"),
    };
    let raw =
        parse_json_safe(&c.raw).ok_or_else(|| reject("custom profile contains invalid JSON"))?;
    let mut sanitized = sanitize_provider_xray(&raw).map_err(|e| reject(&e.to_string()))?;
    // Source selectors cannot name anonymous outbounds. Snapshot their matching
    // universe before assigning compiler-local identities to otherwise valid nodes.
    let orig_outbound_tags: Vec<String> = sanitized
        .outbounds
        .iter()
        .filter_map(|outbound| outbound["tag"].as_str().map(str::to_owned))
        .collect();
    let mut occupied: HashSet<String> = orig_outbound_tags.iter().cloned().collect();
    for (index, outbound) in sanitized.outbounds.iter_mut().enumerate() {
        if outbound["tag"].as_str().is_some() {
            continue;
        }
        let mut suffix = 0usize;
        let tag = loop {
            let candidate = format!("kasumi-unnamed-{index}-{suffix}");
            if occupied.insert(candidate.clone()) {
                break candidate;
            }
            suffix += 1;
        };
        outbound["tag"] = tag.into();
    }

    // Simultaneous standard and burst observatory is unsupported.
    if sanitized.observatory.is_some() && sanitized.burst_observatory.is_some() {
        return Err(reject(
            "cannot specify both observatory and burstObservatory",
        ));
    }

    // Capture original semantics BEFORE transforms
    let orig_first_outbound_tag = sanitized
        .outbounds
        .first()
        .and_then(|o| o["tag"].as_str())
        .map(str::to_string)
        .ok_or_else(|| reject("no default outbound"))?;

    let mut target = default_target(&sanitized);

    let routing = sanitized.routing.clone().unwrap_or(Value::Null);
    let mut raw_balancers: Vec<Value> =
        routing["balancers"].as_array().cloned().unwrap_or_default();
    let raw_rules: Vec<Value> = routing["rules"].as_array().cloned().unwrap_or_default();

    // Check expanded graph for .via chaining limitation BEFORE adding the generated alias loopback
    let is_expanded_fallback = sanitized
        .outbounds
        .iter()
        .any(|o| o["protocol"] == "loopback")
        || raw_balancers.iter().any(|b| b.get("fallbackTag").is_some());
    if c.origin == CustomOrigin::Provider && c.meta.via.is_some() && is_expanded_fallback {
        return Err("provider config rejected: chaining (.via) on expanded loopback/fallback graphs is not supported".into());
    }

    // Collect all original virtual inbound tags
    let mut orig_virtual_tags: HashSet<String> =
        sanitized.virtual_inbound_tags.iter().cloned().collect();
    for ob in &sanitized.outbounds {
        if ob["protocol"] == "loopback"
            && let Some(inbound) = ob
                .get("settings")
                .and_then(|s| s.get("inboundTag"))
                .and_then(Value::as_str)
        {
            orig_virtual_tags.insert(inbound.to_string());
        }
    }

    // Build prefix-free ProviderNames
    let (names, seed) = build_provider_names(
        &c.raw,
        &sanitized.outbounds,
        &raw_balancers,
        &orig_virtual_tags,
    )?;

    // Expand balancer prefix selectors against original outbound tags, then rewrite using names.outbounds
    for b in &mut raw_balancers {
        if let Some(sel) = b.get_mut("selector").and_then(Value::as_array_mut) {
            let prefixes: Vec<String> = sel
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            let mut expanded: Vec<Value> = Vec::new();
            for orig in &orig_outbound_tags {
                if prefixes.iter().any(|p| p == orig || orig.starts_with(p))
                    && !expanded.iter().any(|v| v.as_str() == Some(orig.as_str()))
                    && let Some(new_tag) = names.outbounds.get(orig)
                {
                    expanded.push(Value::from(new_tag.as_str()));
                }
            }
            if !expanded.is_empty() {
                *sel = expanded;
            }
        }
    }

    // Expand observatory subjectSelector prefixes against original outbound tags, then rewrite using names.outbounds
    for obs_opt in [&mut sanitized.observatory, &mut sanitized.burst_observatory].iter_mut() {
        if let Some(obs_val) = obs_opt.as_mut()
            && let Some(obj) = obs_val.as_object_mut()
            && let Some(sel) = obj.get_mut("subjectSelector").and_then(Value::as_array_mut)
        {
            let prefixes: Vec<String> = sel
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            let mut expanded: Vec<Value> = Vec::new();
            for orig in &orig_outbound_tags {
                if prefixes.iter().any(|p| p == orig || orig.starts_with(p))
                    && !expanded.iter().any(|v| v.as_str() == Some(orig.as_str()))
                    && let Some(new_tag) = names.outbounds.get(orig)
                {
                    expanded.push(Value::from(new_tag.as_str()));
                }
            }
            if !expanded.is_empty() {
                *sel = expanded;
            }
        }
    }

    // Transform outbounds
    let mut outbounds: Vec<Value> = Vec::new();
    for (i, mut ob) in sanitized.outbounds.into_iter().enumerate() {
        let ordinal = format!("ks-provider:{seed}:o:{i:08x}:");
        ob["tag"] = ordinal.into();

        retarget_dialers(&mut ob, &names.outbounds);
        retarget(
            ob.get_mut("proxySettings").and_then(|p| p.get_mut("tag")),
            &names.outbounds,
        );
        if ob["protocol"] == "loopback" {
            retarget(
                ob.get_mut("settings").and_then(|s| s.get_mut("inboundTag")),
                &names.virtual_inbounds,
            );
        }
        outbounds.push(ob);
    }

    // Transform balancers
    let mut balancers: Vec<Value> = Vec::new();
    for mut b in raw_balancers {
        retarget(b.get_mut("tag"), &names.balancers);
        retarget(b.get_mut("fallbackTag"), &names.outbounds);
        balancers.push(b);
    }

    // Transform rules into internal rules and entry rules
    let mut internal_rules: Vec<Value> = Vec::new();
    let mut sorted_vtags: Vec<String> = orig_virtual_tags.into_iter().collect();
    sorted_vtags.sort();

    let namespaced_fallback_outbound = names
        .outbounds
        .get(&orig_first_outbound_tag)
        .cloned()
        .unwrap_or(orig_first_outbound_tag);

    for orig_vtag in &sorted_vtags {
        let Some(namespaced_vtag) = names.virtual_inbounds.get(orig_vtag) else {
            continue;
        };
        let mut tcp_covered = false;
        let mut udp_covered = false;

        for r in &raw_rules {
            let applies = match r.get("inboundTag") {
                Some(Value::Array(arr)) => {
                    arr.iter().any(|t| t.as_str() == Some(orig_vtag.as_str()))
                }
                Some(Value::String(s)) => s == orig_vtag,
                None => true,
                _ => false,
            };
            if applies {
                let mut scoped = r.clone();
                scoped["inboundTag"] = json!([namespaced_vtag]);
                retarget(scoped.get_mut("outboundTag"), &names.outbounds);
                retarget(scoped.get_mut("balancerTag"), &names.balancers);

                if let Some(obj) = scoped.as_object() {
                    let covers_tcp = crate::provider_graph::rule_covers_network(obj, "tcp");
                    let covers_udp = crate::provider_graph::rule_covers_network(obj, "udp");

                    internal_rules.push(scoped);

                    if covers_tcp {
                        tcp_covered = true;
                    }
                    if covers_udp {
                        udp_covered = true;
                    }
                    if tcp_covered && udp_covered {
                        break;
                    }
                }
            }
        }

        if !tcp_covered && !udp_covered {
            internal_rules.push(json!({
                "type": "field",
                "inboundTag": [namespaced_vtag],
                "network": "tcp,udp",
                "outboundTag": namespaced_fallback_outbound,
            }));
        } else if !tcp_covered {
            internal_rules.push(json!({
                "type": "field",
                "inboundTag": [namespaced_vtag],
                "network": "tcp",
                "outboundTag": namespaced_fallback_outbound,
            }));
        } else if !udp_covered {
            internal_rules.push(json!({
                "type": "field",
                "inboundTag": [namespaced_vtag],
                "network": "udp",
                "outboundTag": namespaced_fallback_outbound,
            }));
        }
    }

    // Entry rules
    let mut entry_rules: Vec<Value> = raw_rules
        .iter()
        .filter(|r| {
            let is_virt = match r.get("inboundTag") {
                Some(Value::Array(arr)) => {
                    !arr.is_empty()
                        && arr.iter().all(|t| {
                            t.as_str()
                                .is_some_and(|s| sorted_vtags.contains(&s.to_string()))
                        })
                }
                Some(Value::String(s)) => sorted_vtags.contains(&s.to_string()),
                None => false,
                _ => false,
            };
            !is_virt
        })
        .cloned()
        .collect();

    for r in &mut entry_rules {
        retarget(r.get_mut("outboundTag"), &names.outbounds);
        retarget(r.get_mut("balancerTag"), &names.balancers);
        if let Some(obj) = r.as_object_mut()
            && obj.contains_key("inboundTag")
        {
            // Map recorded ingress references to Kasumi's controlled real entry tags
            obj.insert("inboundTag".into(), json!(["socks-in", "http-in"]));
        }
    }

    // Retarget target
    match &mut target {
        Target::Outbound(tag) => {
            if let Some(new_tag) = names.outbounds.get(tag) {
                *tag = new_tag.clone();
            }
        }
        Target::Balancer { tag, members } => {
            if let Some(new_tag) = names.balancers.get(tag) {
                *tag = new_tag.clone();
            }
            for m in members.iter_mut() {
                if let Some(new_m) = names.outbounds.get(m) {
                    *m = new_m.clone();
                }
            }
        }
    }

    // Generate client alias LAST: public `proxy` loopback is always client-owned
    outbounds.insert(
        0,
        json!({
            "tag": "proxy",
            "protocol": "loopback",
            "settings": { "inboundTag": PROXY_SELECT }
        }),
    );

    let proxy_select_rule = match &target {
        Target::Outbound(namespaced_tag) => json!({
            "type": "field", "inboundTag": [PROXY_SELECT],
            "network": "tcp,udp", "outboundTag": namespaced_tag.as_str(),
        }),
        Target::Balancer { tag, .. } => json!({
            "type": "field", "inboundTag": [PROXY_SELECT],
            "network": "tcp,udp", "balancerTag": tag.as_str(),
        }),
    };
    internal_rules.insert(0, proxy_select_rule);

    // Validate observatory prefix-free coverage
    for obs_val in [&sanitized.observatory, &sanitized.burst_observatory]
        .into_iter()
        .flatten()
    {
        if let Some(sel_arr) = obs_val.get("subjectSelector").and_then(Value::as_array) {
            for sel_val in sel_arr {
                let Some(sel) = sel_val.as_str() else {
                    continue;
                };
                let matched: Vec<&Value> = outbounds
                    .iter()
                    .filter(|o| {
                        o["tag"]
                            .as_str()
                            .is_some_and(|t| t == sel || t.starts_with(sel))
                    })
                    .collect();
                if matched.is_empty() {
                    return Err(reject("observatory selector matches no outbounds"));
                }
                for m in matched {
                    if is_service_outbound(m) || m["protocol"] == "loopback" {
                        return Err(reject(
                            "observatory selector matches service or loopback outbound",
                        ));
                    }
                }
            }
        }
    }

    let rules = match kind {
        BuildKind::Runtime => entry_rules,
        BuildKind::Probe => Vec::new(),
    };

    Ok(ActiveOutbounds {
        outbounds,
        rules,
        internal_rules,
        balancers,
        target,
        observatory: sanitized.observatory,
        burst_observatory: sanitized.burst_observatory,
    })
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

/// Where a profile's own `via` chain attaches: the outbound(s) whose socket
/// reaches the provider's servers. A balancer has one entry per member, since the
/// alias itself dials nothing; [`attach_chain`] keeps the hops unique across them.
fn chain_entries(head: &[Value], target: &Target) -> Result<Vec<usize>, String> {
    match target {
        Target::Outbound(tag) => {
            let at = head
                .iter()
                .position(|o| o["tag"].as_str() == Some(tag.as_str()))
                .unwrap_or(0);
            Ok(vec![direct_dialer(head, at)?])
        }
        Target::Balancer { members, .. } => {
            let mut entries: Vec<usize> = Vec::new();
            for member in members {
                let Some(at) = head
                    .iter()
                    .position(|o| o["tag"].as_str() == Some(member.as_str()))
                else {
                    continue;
                };
                let dialer = direct_dialer(head, at)?;
                if !entries.contains(&dialer) {
                    entries.push(dialer);
                }
            }
            Ok(entries)
        }
    }
}

/// Index of the outbound in `head`, starting at `start`, that connects to its
/// server itself: `proxy`, or the last of the outbounds it dials through. A
/// profile's own `via` chain attaches there, in front of the provider's.
fn direct_dialer(head: &[Value], start: usize) -> Result<usize, String> {
    let mut at = start;
    let mut seen = HashSet::new();
    while let Some(next) = head[at]["streamSettings"]["sockopt"]["dialerProxy"].as_str() {
        if !seen.insert(at) {
            return Err(
                "provider config rejected: outbounds dial through each other in a loop".into(),
            );
        }
        match head.iter().position(|o| o["tag"] == next) {
            Some(i) => at = i,
            None => break,
        }
    }
    Ok(at)
}

/// Answer DNS that reaches the local inbounds with xray's own DNS module, instead of
/// forwarding the query to the address it was sent to. Used when a desktop tun
/// sends the system's DNS into the core: that address is often the LAN router,
/// which the proxy server cannot reach. The port-53 rule now goes to a `dns`
/// outbound (A/AAAA through `dns.servers`, fake DNS and `hosts`; other query types
/// are refused at once rather than left to time out), and the module's own
/// upstream queries take the outbound the rule used to name, so "DNS via proxy"
/// still decides how DNS leaves. Idempotent.
pub fn hijack_inbound_dns(cfg: &mut Value) {
    const DNS_MODULE: &str = "dns-module";
    let Some(rules) = cfg
        .get_mut("routing")
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    let Some(rule) = rules.iter_mut().find(|r| {
        r.get("port").is_some_and(|p| p == 53 || p == "53")
            && r.get("inboundTag")
                .and_then(Value::as_array)
                .is_some_and(|t| t.iter().any(|t| t == "socks-in"))
    }) else {
        return;
    };
    let Some(upstream) = rule
        .get("outboundTag")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return;
    };
    if upstream == DNS_OUT {
        return;
    }
    rule["outboundTag"] = DNS_OUT.into();
    rules.insert(
        0,
        json!({ "type": "field", "inboundTag": [DNS_MODULE], "outboundTag": upstream }),
    );
    if let Some(outbounds) = cfg.get_mut("outbounds").and_then(Value::as_array_mut) {
        outbounds.push(json!({
            "tag": DNS_OUT, "protocol": "dns", "settings": { "nonIPQuery": "reject" },
        }));
    }
    if let Some(dns) = cfg.get_mut("dns").and_then(Value::as_object_mut) {
        dns.insert("tag".into(), DNS_MODULE.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hijacks_inbound_dns_into_the_dns_module() {
        let s = AdvancedSettings {
            dns_via_proxy: true,
            ..Default::default()
        };
        let p = crate::share::parse_share_link(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@srv.example:443?security=tls#x",
            None,
        )
        .unwrap();
        let mut cfg = build_xray_config(&p, &s, &[], &[]).unwrap();
        hijack_inbound_dns(&mut cfg);
        let once = cfg.clone();
        hijack_inbound_dns(&mut cfg);
        assert_eq!(cfg, once, "idempotent");

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inboundTag"], json!(["dns-module"]));
        assert_eq!(rules[0]["outboundTag"], "proxy");
        let port53 = rules.iter().find(|r| r["port"] == 53).unwrap();
        assert_eq!(port53["outboundTag"], "dns-out");
        assert_eq!(cfg["dns"]["tag"], "dns-module");
        let out = cfg["outbounds"].as_array().unwrap();
        assert_eq!(out.iter().filter(|o| o["protocol"] == "dns").count(), 1);
    }

    fn chained(uri: &str, id: &str, via: Option<&str>) -> Profile {
        let mut p = crate::share::parse_share_link(uri, None).unwrap();
        p.meta_mut().id = id.into();
        p.meta_mut().via = via.map(str::to_string);
        p
    }

    #[test]
    fn chain_dials_each_hop_through_the_next() {
        let all = vec![
            chained(
                "vless://u@exit.ex:443?type=ws&security=tls&sni=exit.ex",
                "exit",
                Some("mid"),
            ),
            chained(
                "trojan://pw@mid.ex:443?security=tls&sni=mid.ex",
                "mid",
                Some("entry"),
            ),
            chained("ss://YWVzLTEyOC1nY206cHc@entry.ex:8388", "entry", None),
        ];
        let cfg = build_xray_config(&all[0], &AdvancedSettings::default(), &[], &all).unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let by_tag = |t: &str| obs.iter().find(|o| o["tag"] == t).unwrap();
        assert_eq!(
            by_tag("proxy")["streamSettings"]["sockopt"]["dialerProxy"],
            "mid"
        );
        assert_eq!(
            by_tag("mid")["streamSettings"]["sockopt"]["dialerProxy"],
            "entry"
        );
        // The entry hop connects directly (no stream settings of its own to carry).
        assert!(
            by_tag("entry")["streamSettings"]["sockopt"]
                .get("dialerProxy")
                .is_none()
        );
        assert_eq!(obs.iter().filter(|o| o["tag"] == "mid").count(), 1);
    }

    #[test]
    fn chain_with_a_hop_xray_cannot_run_is_an_error() {
        let all = vec![
            chained(
                "vless://u@exit.ex:443?security=tls&sni=exit.ex",
                "exit",
                Some("t"),
            ),
            chained("tuic://u:pw@t.ex:443?sni=t.ex", "t", None),
        ];
        let err = build_xray_config(&all[0], &AdvancedSettings::default(), &[], &all).unwrap_err();
        assert!(err.contains("requires sing-box"), "{err}");
    }

    #[test]
    fn quic_transport_is_never_built_for_xray() {
        let s = AdvancedSettings::default();
        let ss_quic =
            "ss://Y2hhY2hhMjAtcG9seTEzMDU6cHc=@q.ex:8388?plugin=v2ray-plugin%3Bmode%3Dquic#q";
        let alone = chained(ss_quic, "q", None);
        let err = build_xray_config(&alone, &s, &[], std::slice::from_ref(&alone)).unwrap_err();
        assert!(err.contains("requires sing-box"), "{err}");

        let all = vec![
            chained(
                "vless://u@exit.ex:443?security=tls&sni=exit.ex",
                "exit",
                Some("q"),
            ),
            chained(ss_quic, "q", None),
        ];
        let err = build_xray_config(&all[0], &s, &[], &all).unwrap_err();
        assert!(err.contains("requires sing-box"), "{err}");
    }

    /// UDP over TCP is off, as on sing-box: xray applies `uot` only to the 2022
    /// ciphers, and their servers need not accept it.
    #[test]
    fn shadowsocks_2022_sends_udp_natively() {
        let p = crate::share::parse_share_link(
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206TVRJek5EVTJOemc1TUdGaVkyUmxaZz09@ss.example:8388#x",
            None,
        )
        .unwrap();
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let server = &cfg["outbounds"][0]["settings"]["servers"][0];
        assert_eq!(server["method"], "2022-blake3-aes-128-gcm");
        assert!(server.get("uot").is_none(), "{server}");
    }

    #[test]
    fn allow_insecure_is_never_written() {
        let insecure = "vless://u@x.ex:443?type=xhttp&security=tls&sni=x.ex&allowInsecure=1";
        // With a pin, xray checks the certificate against it instead.
        let pinned = crate::share::parse_share_link(&format!("{insecure}&pcs=aabb"), None).unwrap();
        let cfg = build_xray_config(&pinned, &AdvancedSettings::default(), &[], &[]).unwrap();
        let tls = &cfg["outbounds"][0]["streamSettings"]["tlsSettings"];
        assert_eq!(tls["pinnedPeerCertSha256"], "aabb");
        assert!(tls.get("allowInsecure").is_none(), "{tls}");
        // Without one the build is refused rather than run with the check back on.
        let unpinned = crate::share::parse_share_link(insecure, None).unwrap();
        let err = build_xray_config(&unpinned, &AdvancedSettings::default(), &[], &[]).unwrap_err();
        assert_eq!(
            err,
            crate::contract::CoreConflict::UnpinnedInsecureTls.to_string()
        );
    }

    #[test]
    fn an_unpinned_insecure_hop_is_refused() {
        let mut exit = crate::share::parse_share_link(
            "vless://u@e.ex:443?type=tcp&security=tls&sni=e.ex",
            None,
        )
        .unwrap();
        exit.meta_mut().via = Some("hop".into());
        let mut hop = crate::share::parse_share_link(
            "vless://u@h.ex:443?type=xhttp&security=tls&sni=h.ex&allowInsecure=1#hop",
            None,
        )
        .unwrap();
        hop.meta_mut().id = "hop".into();
        let profiles = [exit.clone(), hop];
        let err =
            build_xray_config(&exit, &AdvancedSettings::default(), &[], &profiles).unwrap_err();
        assert_eq!(
            err,
            format!(
                "proxy chain hop \"hop\": {}",
                crate::contract::CoreConflict::UnpinnedInsecureTls
            )
        );
    }

    #[test]
    fn trojan_flow_is_left_out() {
        let p = crate::share::parse_share_link(
            "trojan://pw@t.ex:443?security=tls&sni=t.ex&flow=xtls-rprx-vision",
            None,
        )
        .unwrap();
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let server = &cfg["outbounds"][0]["settings"]["servers"][0];
        assert_eq!(server["password"], "pw");
        assert!(server.get("flow").is_none(), "{server}");
    }

    fn sample() -> Profile {
        crate::share::parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None)
            .unwrap()
    }

    fn source_rule(outbound: &str) -> RoutingRule {
        RoutingRule {
            id: "r".into(),
            remarks: "r".into(),
            enabled: true,
            outbound_tag: outbound.into(),
            domain: None,
            ip: None,
            port: None,
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        }
    }

    #[test]
    fn process_and_source_pass_through_and_package_rules_are_skipped() {
        let p = sample();
        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Rules,
            ..Default::default()
        };
        let rules = vec![
            RoutingRule {
                process: Some(vec!["curl".into(), "/opt/games/".into()]),
                source_ip: Some(vec!["192.168.1.0/24".into()]),
                ..source_rule("direct")
            },
            RoutingRule {
                domain: Some(vec!["example.com".into()]),
                package_name: Some(vec!["com.example.app".into()]),
                ..source_rule("block")
            },
        ];
        let cfg = build_xray_config(&p, &s, &rules, std::slice::from_ref(&p)).unwrap();
        let emitted = cfg["routing"]["rules"].as_array().unwrap();
        let r = emitted.iter().find(|r| r.get("process").is_some()).unwrap();
        assert_eq!(r["process"], json!(["curl", "/opt/games/"]));
        assert_eq!(r["sourceIP"], json!(["192.168.1.0/24"]));
        // Emitting the package rule without its package would block example.com
        // for every app.
        assert!(emitted.iter().all(|r| r["outboundTag"] != "block"));
    }

    #[test]
    fn rules_without_a_condition_are_left_out() {
        let p = sample();
        let every_rule_matches_something = |cfg: &Value| {
            cfg["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| xray_rule_has_condition(r.as_object().unwrap()))
        };
        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Rules,
            ..Default::default()
        };
        let rules = vec![
            source_rule("block"),
            RoutingRule {
                domain: Some(vec![]),
                ip: Some(vec![]),
                port: Some("  ".into()),
                ..source_rule("block")
            },
            // Commented-out domains leave the rule out, not widened to port 443.
            RoutingRule {
                domain: Some(vec!["# geosite:ru".into(), " ".into()]),
                port: Some("443".into()),
                ..source_rule("block")
            },
            RoutingRule {
                domain: Some(vec!["example.com".into()]),
                ..source_rule("direct")
            },
        ];
        let cfg = build_xray_config(&p, &s, &rules, std::slice::from_ref(&p)).unwrap();
        assert!(every_rule_matches_something(&cfg));
        let emitted = cfg["routing"]["rules"].as_array().unwrap();
        assert!(emitted.iter().all(|r| r["outboundTag"] != "block"));
        assert!(
            emitted
                .iter()
                .any(|r| r["domain"] == json!(["example.com"]))
        );

        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Custom,
            custom_routing: Some(
                r#"[{"type":"field","outboundTag":"block"},
                    {"type":"field","domain":[],"outboundTag":"block"},
                    {"type":"field","inboundTag":["socks-in"],"port":"443","outboundTag":"direct"}]"#
                    .into(),
            ),
            ..Default::default()
        };
        let cfg = build_xray_config(&p, &s, &[], std::slice::from_ref(&p)).unwrap();
        assert!(every_rule_matches_something(&cfg));
        let emitted = cfg["routing"]["rules"].as_array().unwrap();
        assert!(emitted.iter().all(|r| r["outboundTag"] != "block"));
        assert!(emitted.iter().any(|r| r["port"] == "443"));
    }

    #[test]
    fn a_rule_target_xray_cannot_build_goes_through_the_proxy() {
        use crate::core::rule_target_fallback;
        use crate::enums::CoreEngine;
        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Rules,
            ..Default::default()
        };
        let p = sample();
        let mut targets: Vec<Profile> = [
            "tuic://u:pw@t.ex:443?sni=t.ex",
            "vless://u@e.x:443?type=h2&security=tls",
            "vless://u@e.x:443?type=ws&security=tls&sni=e.x&allowInsecure=1",
            "vless://u@e.x:443?type=xhttp&security=tls&sni=e.x&allowInsecure=1",
            "vless://u@e.x:443?type=xhttp&security=tls&sni=e.x",
            "hysteria2://pw@h.x:443?sni=h.x",
        ]
        .iter()
        .map(|uri| crate::share::parse_share_link(uri, None).unwrap())
        .collect();
        targets.push(custom("user", &json!({ "outbounds": [] })));
        for (i, t) in targets.iter_mut().enumerate() {
            t.meta_mut().id = format!("t{i}");
        }
        let mut all = targets.clone();
        all.push(p.clone());
        let mut fell_back = Vec::new();
        for t in &targets {
            let id = &t.meta().id;
            let rules = [RoutingRule {
                domain: Some(vec!["example.com".into()]),
                ..source_rule(id)
            }];
            let cfg = build_xray_config(&p, &s, &rules, &all).unwrap();
            let rule = cfg["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r.get("domain").is_some())
                .unwrap();
            let falls_back = rule_target_fallback(t, CoreEngine::Xray).is_some();
            let expected = if falls_back { "proxy" } else { id.as_str() };
            assert_eq!(rule["outboundTag"], expected, "{t:?}");
            fell_back.push(falls_back);
        }
        assert_eq!(fell_back, [true, true, true, true, false, false, true]);
    }

    #[test]
    fn force_in_inbound_is_always_present_and_localhost_only() {
        let p = sample();
        let cfg = build_xray_config(
            &p,
            &AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&p),
        )
        .unwrap();
        let force = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == "force-in")
            .expect("force-in inbound present");
        // Internal bypass-geo port: localhost-only and noauth, never off-box.
        assert_eq!(force["listen"], "127.0.0.1");
        assert_eq!(force["settings"]["auth"], "noauth");
        // Its rule routes straight to proxy and is the first routing rule.
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inboundTag"][0], "force-in");
        assert_eq!(rules[0]["outboundTag"], "proxy");
    }

    #[test]
    fn force_in_rule_outranks_a_geoip_direct_rule() {
        // A user "geoip:ru → direct" rule must not capture force-in traffic.
        let p = sample();
        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Rules,
            ..Default::default()
        };
        let geo = RoutingRule {
            id: "g".into(),
            remarks: "ru".into(),
            enabled: true,
            outbound_tag: "direct".into(),
            domain: None,
            ip: Some(vec!["geoip:ru".into()]),
            port: None,
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        };
        let cfg = build_xray_config(&p, &s, std::slice::from_ref(&geo), std::slice::from_ref(&p))
            .unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        let force_idx = rules
            .iter()
            .position(|r| r["inboundTag"][0] == "force-in")
            .unwrap();
        let geo_idx = rules.iter().position(|r| r["ip"][0] == "geoip:ru").unwrap();
        assert!(force_idx < geo_idx, "force-in rule must precede geoip:ru");
    }

    #[test]
    fn socks_auth_gates_the_local_inbounds() {
        let p =
            crate::share::parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None)
                .unwrap();
        let mut s = AdvancedSettings {
            socks_username: Some("alice".into()),
            socks_password: Some("s3cret".into()),
            ..Default::default()
        };
        let cfg = build_xray_config(&p, &s, &[], std::slice::from_ref(&p)).unwrap();
        let inbounds = cfg["inbounds"].as_array().unwrap();
        let socks = inbounds.iter().find(|i| i["tag"] == "socks-in").unwrap();
        assert_eq!(socks["settings"]["auth"], "password");
        assert_eq!(socks["settings"]["accounts"][0]["user"], "alice");
        assert_eq!(socks["settings"]["accounts"][0]["pass"], "s3cret");
        let http = inbounds.iter().find(|i| i["tag"] == "http-in").unwrap();
        assert_eq!(http["settings"]["accounts"][0]["user"], "alice");

        // A half-set credential leaves the inbound open (no accidental lockout).
        s.socks_password = Some(String::new());
        let cfg = build_xray_config(&p, &s, &[], std::slice::from_ref(&p)).unwrap();
        let socks = cfg["inbounds"].as_array().unwrap()[0].clone();
        assert_eq!(socks["settings"]["auth"], "noauth");
    }

    fn wireguard(local_address: &str) -> crate::profile::Wireguard {
        let p: Profile = serde_json::from_value(json!({
            "protocol": "wireguard",
            "meta": { "id": "w", "remarks": "r", "groupId": "g-main" },
            "endpoint": { "address": "e.x", "port": 51820 },
            "secretKey": "sk",
            "peerPublicKey": "pk",
            "localAddress": local_address,
        }))
        .unwrap();
        let Profile::Wireguard(w) = p else { panic!() };
        w
    }

    #[test]
    fn wireguard_peer_endpoint_brackets_ipv6() {
        let mut w = wireguard("");
        w.endpoint.address = "2001:db8::4".into();
        let out = build_wireguard_outbound(&w);
        assert_eq!(
            out["settings"]["peers"][0]["endpoint"],
            "[2001:db8::4]:51820"
        );
    }

    #[test]
    fn wireguard_address_splits_on_either_separator_and_is_never_empty() {
        let out = build_wireguard_outbound(&wireguard("10.0.0.2/32\n fd00::2/128 "));
        assert_eq!(
            out["settings"]["address"],
            json!(["10.0.0.2/32", "fd00::2/128"])
        );
        // A blank or separator-only value falls back to the default address:
        // xray rejects a wireguard outbound with an empty address list.
        for blank in ["", " , \n "] {
            let out = build_wireguard_outbound(&wireguard(blank));
            assert_eq!(
                out["settings"]["address"],
                json!([WG_DEFAULT_LOCAL_ADDRESS])
            );
        }
    }

    #[test]
    fn tcp_http_host_header_entries_are_split_and_trimmed() {
        let p: Profile = serde_json::from_value(json!({
            "protocol": "vless",
            "meta": { "id": "v", "remarks": "r", "groupId": "g-main" },
            "endpoint": { "address": "e.x", "port": 443 },
            "uuid": "u",
            "transport": {
                "kind": "tcp",
                "headerType": "http",
                "host": "a.example, b.example\nc.example",
            },
        }))
        .unwrap();
        let (key, v) = build_transport_setting(&p).unwrap();
        assert_eq!(key, "tcpSettings");
        assert_eq!(
            v["header"]["request"]["headers"]["Host"],
            json!(["a.example", "b.example", "c.example"])
        );
    }

    fn custom(origin: &str, raw: &Value) -> Profile {
        serde_json::from_value(json!({
            "protocol": "custom",
            "meta": { "id": "c", "remarks": "C", "groupId": "g-main" },
            "raw": raw.to_string(),
            "origin": origin,
        }))
        .unwrap()
    }

    fn provider_vless(tag: &str, host: &str) -> Value {
        json!({
            "tag": tag, "protocol": "vless",
            "settings": { "vnext": [{ "address": host, "port": 443,
                "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
            "streamSettings": { "network": "tcp", "security": "tls", "sockopt": { "mark": 255 } },
        })
    }

    fn provider_raw() -> Value {
        json!({
            "log": { "loglevel": "debug", "error": "/data/adb/kasumi-proxy/x" },
            "inbounds": [{ "tag": "in", "protocol": "socks", "listen": "0.0.0.0", "port": 1080 }],
            "api": { "tag": "api", "services": ["HandlerService"] },
            "stats": {},
            "outbounds": [
                { "tag": "direct", "protocol": "freedom" },
                provider_vless("main", "main.example"),
                provider_vless("backup", "backup.example"),
            ],
            "routing": { "rules": [
                { "type": "field", "inboundTag": ["in"], "domain": ["geosite:ru"], "outboundTag": "direct" },
                { "type": "field", "domain": ["b.example"], "outboundTag": "backup" },
                { "type": "field", "domain": ["m.example"], "outboundTag": "main" },
            ]},
        })
    }

    fn tags(cfg: &Value) -> Vec<&str> {
        cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn provider_custom_built_into_kasumi_skeleton() {
        let p = custom("provider", &provider_raw());
        let typed = build_xray_config(&sample(), &AdvancedSettings::default(), &[], &[]).unwrap();
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();

        assert_eq!(cfg["inbounds"], typed["inbounds"]);
        assert_eq!(cfg["log"], typed["log"]);
        assert_eq!(cfg["dns"], typed["dns"]);
        for key in ["api", "stats", "policy", "reverse"] {
            assert!(cfg.get(key).is_none(), "{key} survived");
        }
        // Public proxy is always client-owned loopback alias to proxy-select
        assert_eq!(
            cfg["outbounds"][0],
            json!({
                "tag": "proxy",
                "protocol": "loopback",
                "settings": { "inboundTag": "proxy-select" }
            })
        );
        let obs = cfg["outbounds"].as_array().unwrap();
        // Provider outbounds are namespaced prefix-free
        assert!(obs[1]["tag"].as_str().unwrap().starts_with("ks-provider:"));
        let text = cfg.to_string();
        assert!(
            !text.contains("/data/adb") && !text.contains("\"mark\""),
            "{text}"
        );

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // First prefix rule is force-in -> proxy
        assert_eq!(rules[0]["inboundTag"][0], "force-in");
        assert_eq!(rules[0]["outboundTag"], "proxy");
        // With a service first, the first usable ruled target is backup, not
        // main merely because its server declaration appears earlier.
        let backup_tag = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "backup.example")
            .unwrap()["tag"]
            .as_str()
            .unwrap();
        assert_eq!(rules[1]["inboundTag"][0], "proxy-select");
        assert_eq!(rules[1]["outboundTag"], backup_tag);
        // Catch-all to proxy is last
        assert_eq!(rules.last().unwrap()["outboundTag"], "proxy");
    }

    /// A provider config whose routing sends everything to a balancer, while its
    /// first outbound is a server nothing routes to (tagged `proxy`, so the tag
    /// Kasumi needs is taken).
    fn balancer_raw() -> Value {
        json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [
                provider_vless("proxy", "decoy.example"),
                provider_vless("main", "main.example"),
                provider_vless("main-2", "main2.example"),
                { "tag": "direct", "protocol": "freedom" },
            ],
            "routing": {
                "balancers": [
                    { "tag": "balancer-main", "selector": ["main"],
                      "strategy": { "type": "random" } },
                ],
                "rules": [
                    { "type": "field", "domain": ["geosite:ru"], "outboundTag": "direct" },
                    { "type": "field", "inboundTag": ["in"], "network": "tcp,udp", "balancerTag": "balancer-main" },
                ],
            },
        })
    }

    fn by_tag<'a>(cfg: &'a Value, tag: &str) -> &'a Value {
        cfg["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == tag)
            .unwrap_or_else(|| panic!("no outbound {tag} in {}", tags(cfg).join(",")))
    }

    #[test]
    fn proxy_aliases_the_balancer_the_provider_routes_to() {
        let p = custom("provider", &balancer_raw());
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();

        // `proxy` is a loopback alias: Kasumi's traffic re-enters routing as if it
        // had arrived on `proxy-select`, where one rule sends it to the balancer.
        assert_eq!(
            cfg["outbounds"][0],
            json!({ "tag": "proxy", "protocol": "loopback",
                    "settings": { "inboundTag": "proxy-select" } })
        );
        let b = &cfg["routing"]["balancers"][0];
        let b_tag = b["tag"].as_str().unwrap();
        assert!(b_tag.starts_with("ks-provider:"));

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["inboundTag"][0], "force-in");
        assert_eq!(rules[0]["outboundTag"], "proxy");
        let second_pass = rules
            .iter()
            .position(|r| r["inboundTag"][0] == "proxy-select")
            .expect("the alias rule is there");
        assert_eq!(
            rules[second_pass],
            json!({ "type": "field", "inboundTag": ["proxy-select"],
                    "network": "tcp,udp", "balancerTag": b_tag })
        );
        let geosite = rules
            .iter()
            .position(|r| r.get("domain").is_some_and(|d| d[0] == "geosite:ru"))
            .unwrap();
        assert!(second_pass < geosite);
    }

    /// When a user has a routing rule targeting the active profile (or `proxy`),
    /// the re-entering `proxy-select` loopback connection must not match that
    /// user rule again, which would loop forever. The `proxy-select` rule must
    /// precede user rules.
    #[test]
    fn proxy_select_precedes_user_routing_rules() {
        let p = custom("provider", &balancer_raw());
        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Rules,
            ..Default::default()
        };
        let user_rule = RoutingRule {
            domain: Some(vec!["example.com".into()]),
            outbound_tag: "proxy".into(),
            ..source_rule("proxy")
        };
        let cfg = build_xray_config(&p, &s, &[user_rule], &[]).unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();

        let proxy_select_pos = rules
            .iter()
            .position(|r| {
                r.get("inboundTag")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|t| t == "proxy-select"))
            })
            .expect("proxy-select rule present");
        let user_rule_pos = rules
            .iter()
            .position(|r| {
                r.get("domain")
                    .and_then(Value::as_array)
                    .is_some_and(|a| a.iter().any(|t| t == "example.com"))
            })
            .expect("user rule present");

        assert!(
            proxy_select_pos < user_rule_pos,
            "proxy-select ({proxy_select_pos}) must come before user rule ({user_rule_pos})"
        );
    }

    #[test]
    fn proxy_is_the_outbound_the_provider_routes_to() {
        let raw = json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [
                provider_vless("decoy", "decoy.example"),
                provider_vless("main", "main.example"),
            ],
            "routing": { "rules": [
                { "type": "field", "domain": ["m.example"], "outboundTag": "decoy" },
                { "type": "field", "network": "tcp,udp", "outboundTag": "main" },
            ]},
        });
        let cfg = build_xray_config(
            &custom("provider", &raw),
            &AdvancedSettings::default(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(cfg["outbounds"][0]["tag"], "proxy");
        assert_eq!(cfg["outbounds"][0]["protocol"], "loopback");
        let obs = cfg["outbounds"].as_array().unwrap();
        let main_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main.example")
            .unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[1]["inboundTag"][0], "proxy-select");
        assert_eq!(rules[1]["outboundTag"], main_ob["tag"]);
    }

    #[test]
    fn a_provider_config_without_rules_keeps_its_shape() {
        let raw = json!({ "outbounds": [
            provider_vless("one", "one.example"),
            provider_vless("two", "two.example"),
        ]});
        let cfg = build_xray_config(
            &custom("provider", &raw),
            &AdvancedSettings::default(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(cfg["outbounds"][0]["tag"], "proxy");
        assert_eq!(cfg["outbounds"][0]["protocol"], "loopback");
        let obs = cfg["outbounds"].as_array().unwrap();
        let one_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "one.example")
            .unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[1]["inboundTag"][0], "proxy-select");
        assert_eq!(rules[1]["outboundTag"], one_ob["tag"]);
    }

    #[test]
    fn a_provider_config_without_tags_still_gets_a_proxy() {
        let raw = json!({ "outbounds": [
            { "protocol": "vless", "settings": { "vnext": [{ "address": "only.example",
                "port": 443, "users": [
                    { "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] } },
            { "protocol": "freedom" },
        ]});
        let cfg = build_xray_config(
            &custom("provider", &raw),
            &AdvancedSettings::default(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(cfg["outbounds"][0]["tag"], "proxy");
        assert_eq!(cfg["outbounds"][0]["protocol"], "loopback");
        let obs = cfg["outbounds"].as_array().unwrap();
        let only_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "only.example")
            .unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[1]["inboundTag"][0], "proxy-select");
        assert_eq!(rules[1]["outboundTag"], only_ob["tag"]);
    }

    #[test]
    fn via_attaches_to_every_balancer_member() {
        let mut p = custom("provider", &balancer_raw());
        p.meta_mut().via = Some("entry".into());
        let all = vec![
            p.clone(),
            chained("ss://YWVzLTEyOC1nY206cHc@entry.ex:8388", "entry", None),
        ];
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &all).unwrap();

        let obs = cfg["outbounds"].as_array().unwrap();
        let main_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main.example")
            .unwrap();
        let main2_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main2.example")
            .unwrap();
        assert_eq!(main_ob["streamSettings"]["sockopt"]["dialerProxy"], "entry");
        assert_eq!(
            main2_ob["streamSettings"]["sockopt"]["dialerProxy"],
            "entry"
        );

        // The alias dials nothing of its own, and the decoy is on no such path.
        assert!(by_tag(&cfg, "proxy").get("streamSettings").is_none());
        let decoy_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "decoy.example")
            .unwrap();
        assert!(
            decoy_ob["streamSettings"]["sockopt"]
                .get("dialerProxy")
                .is_none()
        );

        // One hop serves every member.
        assert_eq!(obs.iter().filter(|o| o["tag"] == "entry").count(), 1);
    }

    #[test]
    fn probe_config_of_a_provider_keeps_the_balancer_and_drops_its_rules() {
        let p = custom("provider", &balancer_raw());
        let probe = build_xray_probe_config(&p, &AdvancedSettings::default(), &[]).unwrap();
        let cfg = probe.config;

        let b = &cfg["routing"]["balancers"][0];
        let b_tag = b["tag"].as_str().unwrap();
        assert!(b_tag.starts_with("ks-provider:"));
        let members: Vec<&str> = b["selector"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            probe.target.describe(),
            format!("balancer {b_tag} ({})", members.join(", "))
        );
        assert_eq!(cfg["routing"]["balancers"][0]["tag"], b_tag);
        assert_eq!(
            cfg["inbounds"],
            build_xray_config(&sample(), &AdvancedSettings::default(), &[], &[]).unwrap()["inbounds"]
        );
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // A provider rule would only capture the probe's own traffic.
        assert!(rules.iter().all(|r| r.get("domain").is_none()), "{rules:?}");
        assert!(
            rules
                .iter()
                .any(|r| r["inboundTag"][0] == "proxy-select" && r["balancerTag"] == b_tag)
        );
    }

    #[test]
    fn probe_config_of_a_user_custom_owns_the_inbounds() {
        let raw = json!({
            "inbounds": [{ "tag": "mine", "protocol": "socks", "listen": "0.0.0.0", "port": 10808 }],
            "outbounds": [provider_vless("user-exit", "srv.example")],
        });
        let p = custom("user", &raw);
        let s = AdvancedSettings {
            local_socks_port: Some(19080),
            local_http_port: Some(19081),
            ..Default::default()
        };
        let cfg = build_xray_probe_config(&p, &s, &[]).unwrap();

        let Target::Outbound(target) = &cfg.target else {
            panic!("the user's single-server probe must report an outbound");
        };
        assert!(target.starts_with("ks-provider:"));
        let text = cfg.config.to_string();
        assert!(
            !text.contains("10808") && !text.contains("\"mine\""),
            "{text}"
        );
        assert_eq!(cfg.config["inbounds"][0]["tag"], "socks-in");
        assert_eq!(cfg.config["inbounds"][0]["port"], 19080);
        assert_eq!(cfg.config["inbounds"][1]["port"], 19081);
        let measured = cfg.config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"].as_str() == Some(target.as_str()))
            .unwrap();
        assert_eq!(measured["settings"]["vnext"][0]["address"], "srv.example");
        assert_eq!(cfg.config["outbounds"][0]["protocol"], "loopback");
        assert!(
            cfg.config["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| {
                    rule["inboundTag"] == json!(["proxy-select"])
                        && rule["outboundTag"] == target.as_str()
                })
        );
        // The runtime config still runs it exactly as written.
        assert_eq!(
            build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap(),
            raw
        );
    }

    #[test]
    fn unnamed_default_is_not_replaced_by_a_later_outbound_named_proxy() {
        let mut first = provider_vless("temporary", "first.example");
        first.as_object_mut().unwrap().remove("tag");
        let raw = json!({ "outbounds": [first, provider_vless("proxy", "later.example")] });
        for origin in ["provider", "user"] {
            let profile = custom(origin, &raw);
            let probe =
                build_xray_probe_config(&profile, &AdvancedSettings::default(), &[]).unwrap();
            let Target::Outbound(tag) = &probe.target else {
                panic!("an unnamed default must still select its original outbound");
            };
            assert_eq!(
                by_tag(&probe.config, tag)["settings"]["vnext"][0]["address"],
                "first.example"
            );
        }
    }

    #[test]
    fn temporary_outbound_names_do_not_expand_source_selectors() {
        let mut first = provider_vless("temporary", "unnamed.example");
        first.as_object_mut().unwrap().remove("tag");
        let raw = json!({
            "outbounds": [first,
                provider_vless("kasumi-unnamed-0-0", "named1.example"),
                provider_vless("kasumi-unnamed-0", "named2.example")],
            "routing": {
                "balancers": [{ "tag": "selected", "selector": ["kasumi-unnamed-0"], "strategy": { "type": "random" } }],
                "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "selected" }]
            }
        });
        for origin in ["provider", "user"] {
            let probe =
                build_xray_probe_config(&custom(origin, &raw), &AdvancedSettings::default(), &[])
                    .unwrap();
            let members = probe.config["routing"]["balancers"][0]["selector"]
                .as_array()
                .unwrap();
            assert_eq!(members.len(), 2);
            for member in members {
                let outbound = by_tag(&probe.config, member.as_str().unwrap());
                assert!(matches!(
                    outbound["settings"]["vnext"][0]["address"].as_str(),
                    Some("named1.example" | "named2.example")
                ));
            }
        }
    }

    #[test]
    fn unnamed_loopback_default_keeps_its_virtual_dispatch() {
        let raw = json!({
            "outbounds": [
                { "protocol": "loopback", "settings": { "inboundTag": "inside" } },
                provider_vless("proxy", "exit.example")
            ],
            "routing": { "rules": [
                { "type": "field", "inboundTag": ["inside"], "outboundTag": "proxy" }
            ] }
        });
        let probe =
            build_xray_probe_config(&custom("user", &raw), &AdvancedSettings::default(), &[])
                .unwrap();
        let Target::Outbound(tag) = &probe.target else {
            panic!("expected the loopback entry")
        };
        let entry = by_tag(&probe.config, tag);
        assert_eq!(entry["protocol"], "loopback");
        let context = &entry["settings"]["inboundTag"];
        assert!(
            probe.config["routing"]["rules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|rule| rule["inboundTag"]
                    .as_array()
                    .is_some_and(|tags| tags.contains(context)))
        );
    }

    #[test]
    fn user_custom_probe_routes_to_its_reported_balancer_and_keeps_fallback() {
        let mut raw = balancer_raw();
        raw["outbounds"].as_array_mut().unwrap().push(json!({
            "tag": "reenter", "protocol": "loopback",
            "settings": { "inboundTag": "fallback-in" }
        }));
        raw["routing"]["balancers"][0]["fallbackTag"] = "reenter".into();
        raw["routing"]["rules"].as_array_mut().unwrap().insert(
            0,
            json!({
                "type": "field", "inboundTag": ["fallback-in"], "outboundTag": "main-2"
            }),
        );
        raw["observatory"] = json!({
            "subjectSelector": ["main"], "probeURL": "https://probe.example/health",
            "probeInterval": "10s"
        });
        let mut profile = custom("user", &raw);
        // Runtime executes the raw config, not a chain described outside it.
        profile.meta_mut().via = Some("not-part-of-the-raw-config".into());
        let probe = build_xray_probe_config(&profile, &AdvancedSettings::default(), &[]).unwrap();
        let Target::Balancer { tag, .. } = &probe.target else {
            panic!("a user balancer probe must report its selected balancer");
        };
        let rules = probe.config["routing"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|rule| rule["inboundTag"] == json!(["proxy-select"])
                    && rule["balancerTag"] == tag.as_str())
        );
        let fallback = probe.config["routing"]["balancers"][0]["fallbackTag"]
            .as_str()
            .unwrap();
        let fallback_outbound = by_tag(&probe.config, fallback);
        assert_eq!(fallback_outbound["protocol"], "loopback");
        let context = &fallback_outbound["settings"]["inboundTag"];
        assert!(rules.iter().any(|rule| {
            rule["inboundTag"]
                .as_array()
                .is_some_and(|tags| tags.contains(context))
        }));
        assert!(probe.config.get("observatory").is_some());
        assert_eq!(
            build_xray_config(&profile, &AdvancedSettings::default(), &[], &[]).unwrap(),
            raw
        );
    }

    /// A typed profile's probe config is the one it already ran: the probe only
    /// differs for a custom profile.
    #[test]
    fn probe_config_of_a_typed_profile_is_the_runtime_config() {
        let s = AdvancedSettings::default();
        let p = sample();
        assert_eq!(
            build_xray_probe_config(&p, &s, &[]).unwrap().config,
            build_xray_config(&p, &s, &[], &[]).unwrap()
        );

        let mut via = sample();
        via.meta_mut().via = Some("entry".into());
        let all = vec![
            via.clone(),
            chained("ss://YWVzLTEyOC1nY206cHc@entry.ex:8388", "entry", None),
        ];
        let probe = build_xray_probe_config(&via, &s, &all).unwrap();
        assert_eq!(probe.target.describe(), "outbound proxy");
        // Its chain hangs off the entry outbound, as it does at runtime.
        assert_eq!(
            probe.config,
            build_xray_config(&via, &s, &[], &all).unwrap()
        );
    }

    #[test]
    fn kasumi_rules_win_over_provider_rules() {
        let p = custom("provider", &provider_raw());
        let s = AdvancedSettings {
            routing_mode: crate::state::RoutingMode::Rules,
            ..Default::default()
        };
        let rule = RoutingRule {
            domain: Some(vec!["b.example".into()]),
            ..source_rule("block")
        };
        let cfg = build_xray_config(&p, &s, &[rule], &[]).unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        let ours = rules
            .iter()
            .position(|r| r["outboundTag"] == "block")
            .unwrap();
        let theirs = rules
            .iter()
            .position(|r| r.get("domain") == Some(&json!(["m.example"])))
            .unwrap();
        assert!(ours < theirs);
    }

    #[test]
    fn provider_tags_never_shadow_kasumi_outbounds() {
        let mut main = provider_vless("main", "main.example");
        main["streamSettings"]["sockopt"] = json!({ "dialerProxy": "block" });
        let raw = json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [
                main,
                // A server tagged like Kasumi's blackhole, and one like a profile id.
                provider_vless("block", "entry.example"),
                provider_vless("c", "other.example"),
            ],
            "routing": {
                "balancers": [{ "tag": "lb", "selector": ["m", "c"] }],
                "rules": [
                    { "type": "field", "ip": ["1.1.1.1"], "outboundTag": "block" },
                    { "type": "field", "ip": ["8.8.8.8"], "balancerTag": "lb" },
                ],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(
            &p,
            &AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&p),
        )
        .unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let main_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main.example")
            .unwrap();
        let block_server = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "entry.example")
            .unwrap();
        // The provider's block server has a namespaced tag, NOT literal "block"
        assert!(
            block_server["tag"]
                .as_str()
                .unwrap()
                .starts_with("ks-provider:")
        );
        assert_ne!(block_server["tag"], "block");
        assert_eq!(
            main_ob["streamSettings"]["sockopt"]["dialerProxy"],
            block_server["tag"]
        );
        // Kasumi's actual blackhole outbound is present at the end
        assert_eq!(obs.last().unwrap()["tag"], "block");
        assert_eq!(obs.last().unwrap()["protocol"], "blackhole");

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        let rule_1_1_1_1 = rules
            .iter()
            .find(|r| r.get("ip") == Some(&json!(["1.1.1.1"])))
            .unwrap();
        assert_eq!(rule_1_1_1_1["outboundTag"], block_server["tag"]);
    }

    #[test]
    fn provider_chain_dials_through_the_profile_via() {
        let mut main = provider_vless("main", "main.example");
        main["streamSettings"]["sockopt"] = json!({ "dialerProxy": "relay" });
        let raw = json!({ "outbounds": [main, provider_vless("relay", "relay.example")] });
        let mut p = custom("provider", &raw);
        p.meta_mut().via = Some("entry".into());
        let all = vec![
            p.clone(),
            chained("ss://YWVzLTEyOC1nY206cHc@entry.ex:8388", "entry", None),
        ];
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &all).unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let main_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main.example")
            .unwrap();
        let relay_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "relay.example")
            .unwrap();
        assert_eq!(
            main_ob["streamSettings"]["sockopt"]["dialerProxy"],
            relay_ob["tag"]
        );
        assert_eq!(
            relay_ob["streamSettings"]["sockopt"]["dialerProxy"],
            "entry"
        );
    }

    #[test]
    fn provider_dial_loop_is_an_error() {
        let mut a = provider_vless("a", "a.example");
        a["streamSettings"]["sockopt"] = json!({ "dialerProxy": "b" });
        let mut b = provider_vless("b", "b.example");
        b["streamSettings"]["sockopt"] = json!({ "dialerProxy": "a" });
        let mut p = custom("provider", &json!({ "outbounds": [a, b] }));
        p.meta_mut().via = Some("entry".into());
        let all = vec![
            p.clone(),
            chained("ss://YWVzLTEyOC1nY206cHc@entry.ex:8388", "entry", None),
        ];
        let err = build_xray_config(&p, &AdvancedSettings::default(), &[], &all).unwrap_err();
        assert!(err.contains("loop") || err.contains("cycle"), "{err}");
    }

    #[test]
    fn user_custom_still_verbatim() {
        let raw = provider_raw();
        let cfg = build_xray_config(
            &custom("user", &raw),
            &AdvancedSettings::default(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(cfg, raw);
    }

    /// `provider_raw` with `tls` as the `backup` outbound's tlsSettings.
    fn raw_with_tls(tls: Value) -> Value {
        let mut raw = provider_raw();
        raw["outbounds"][2]["streamSettings"]["tlsSettings"] = tls;
        raw
    }

    #[test]
    fn custom_unpinned_allow_insecure_is_refused() {
        use crate::contract::CoreConflict;
        let raw = raw_with_tls(json!({ "serverName": "b.example", "allowInsecure": true }));
        for origin in ["user", "provider"] {
            let p = custom(origin, &raw);
            assert_eq!(core_conflict(&p), Some(CoreConflict::CustomAllowInsecure));
            let err = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap_err();
            assert_eq!(
                err,
                CoreConflict::CustomAllowInsecure.to_string(),
                "{origin}"
            );
        }
        let checked = raw_with_tls(json!({ "serverName": "b.example", "allowInsecure": false }));
        assert_eq!(core_conflict(&custom("user", &checked)), None);
    }

    #[test]
    fn custom_pinned_allow_insecure_runs_on_the_pin() {
        let raw = raw_with_tls(json!({
            "serverName": "b.example", "allowInsecure": true, "pinnedPeerCertSha256": "aabb",
        }));
        for origin in ["user", "provider"] {
            let p = custom(origin, &raw);
            assert_eq!(core_conflict(&p), None, "{origin}");
            let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
            let backup = cfg["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["settings"]["vnext"][0]["address"] == "backup.example")
                .unwrap();
            assert_eq!(
                backup["streamSettings"]["tlsSettings"],
                json!({ "serverName": "b.example", "pinnedPeerCertSha256": "aabb" }),
                "{origin}"
            );
        }
    }

    #[test]
    fn hand_edited_provider_raw_is_resanitised() {
        // A state file edited after import still never runs provider listeners.
        let mut raw = provider_raw();
        raw["inbounds"] = json!([{ "tag": "in", "protocol": "dokodemo-door", "port": 9 }]);
        raw["outbounds"][1]["streamSettings"]["sockopt"] = json!({ "interface": "wlan0" });
        let cfg = build_xray_config(
            &custom("provider", &raw),
            &AdvancedSettings::default(),
            &[],
            &[],
        )
        .unwrap();
        let text = cfg.to_string();
        assert!(
            !text.contains("dokodemo-door") && !text.contains("wlan0"),
            "{text}"
        );

        let bad = custom(
            "provider",
            &json!({ "outbounds": [{ "protocol": "freedom" }] }),
        );
        let err = build_xray_config(&bad, &AdvancedSettings::default(), &[], &[]).unwrap_err();
        assert!(err.contains("no proxy outbound"), "{err}");
    }

    #[test]
    fn plain_shadowsocks_outbound_has_no_tls_stream() {
        let p =
            crate::share::parse_share_link("ss://YWVzLTI1Ni1nY206cHc=@ss.example:8388#plain", None)
                .unwrap();
        let out = build_outbound(&p, &AdvancedSettings::default()).unwrap();
        assert_eq!(out["protocol"], "shadowsocks");
        assert_eq!(out["streamSettings"]["security"], "none", "{out}");
        assert!(out["streamSettings"].get("tlsSettings").is_none(), "{out}");
    }

    #[test]
    fn hysteria2_outbound_names_the_hysteria_stream_network() {
        let p = crate::share::parse_share_link("hysteria2://pw@h.x:443?sni=h.x", None).unwrap();
        let out = build_outbound(&p, &AdvancedSettings::default()).unwrap();
        assert_eq!(out["protocol"], "hysteria");
        assert_eq!(out["streamSettings"]["network"], "hysteria", "{out}");
        assert_eq!(
            out["streamSettings"]["hysteriaSettings"]["version"], 2,
            "{out}"
        );
    }

    #[test]
    fn kcp_sending_window_below_the_mtu_is_left_to_the_core_default() {
        let mut p = crate::share::parse_share_link(
            "vless://11111111-1111-1111-1111-111111111111@v.example:4000?type=kcp&security=none",
            None,
        )
        .unwrap();
        {
            let Profile::Vless(v) = &mut p else {
                panic!("expected a VLESS profile");
            };
            let Transport::Kcp(k) = &mut v.transport else {
                panic!("expected a KCP transport");
            };
            k.mtu = 1350;
            k.max_sending_window = 128;
        }
        let out = build_outbound(&p, &AdvancedSettings::default()).unwrap();
        assert!(
            out["streamSettings"]["kcpSettings"]
                .get("maxSendingWindow")
                .is_none(),
            "{out}"
        );

        {
            let Profile::Vless(v) = &mut p else {
                unreachable!();
            };
            let Transport::Kcp(k) = &mut v.transport else {
                unreachable!();
            };
            k.max_sending_window = 2 * 1024 * 1024;
        }
        let out = build_outbound(&p, &AdvancedSettings::default()).unwrap();
        assert_eq!(
            out["streamSettings"]["kcpSettings"]["maxSendingWindow"],
            2 * 1024 * 1024,
            "{out}"
        );
    }

    #[test]
    fn provider_internal_graph_keeps_fallback_cascade_and_burst_observatory() {
        let loopback = |tag: &str, in_tag: &str| {
            json!({
                "tag": tag, "protocol": "loopback",
                "settings": { "inboundTag": in_tag }
            })
        };
        let raw = json!({
            "outbounds": [
                provider_vless("srv-1", "srv1.example"),
                provider_vless("srv-2", "srv2.example"),
                loopback("lb-fb", "v-fallback"),
                { "tag": "direct", "protocol": "freedom" },
            ],
            "routing": {
                "balancers": [
                    { "tag": "balancer-all", "selector": ["srv-2"] },
                    { "tag": "balancer-sticky", "selector": ["srv-1"], "fallbackTag": "lb-fb" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["v-fallback"], "balancerTag": "balancer-all" },
                    { "type": "field", "domain": ["blocked.example"], "outboundTag": "direct" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "balancer-sticky" },
                ],
            },
            "burstObservatory": {
                "pingConfig": { "destination": "https://example.com/check", "interval": "1m" },
                "subjectSelector": ["srv-1", "srv-2"],
            }
        });

        let p = custom("provider", &raw);
        let settings = AdvancedSettings::default();

        // 1. Runtime build
        let cfg = build_xray_config(&p, &settings, &[], &[]).unwrap();
        assert!(cfg.get("burstObservatory").is_some());
        let obs = cfg["outbounds"].as_array().unwrap();
        let srv1_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "srv1.example")
            .unwrap();
        let srv2_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "srv2.example")
            .unwrap();
        assert_eq!(
            cfg["burstObservatory"]["subjectSelector"],
            json!([srv1_ob["tag"], srv2_ob["tag"]])
        );
        let balancers = cfg["routing"]["balancers"].as_array().unwrap();
        let lb_all = balancers
            .iter()
            .find(|b| b["selector"] == json!([srv2_ob["tag"]]))
            .unwrap();
        let lb_sticky = balancers
            .iter()
            .find(|b| b["selector"] == json!([srv1_ob["tag"]]))
            .unwrap();

        let rules = cfg["routing"]["rules"].as_array().unwrap();

        // Prefix rules: force-in, proxy-select -> balancer-sticky, v-fallback -> balancer-all, dns-rule
        assert_eq!(rules[0]["inboundTag"], json!(["force-in"]));
        assert_eq!(rules[1]["inboundTag"], json!([PROXY_SELECT]));
        assert_eq!(rules[1]["balancerTag"], lb_sticky["tag"]);
        assert_eq!(rules[2]["balancerTag"], lb_all["tag"]);
        assert!(rules[2]["inboundTag"][0].as_str().unwrap().contains(":v:"));

        // Entry rules sit before catch-all to proxy
        let n = rules.len();
        let direct_ob = obs
            .iter()
            .find(|o| o["protocol"] == "freedom" && o["tag"] != "direct")
            .unwrap();
        assert_eq!(rules[n - 3]["domain"], json!(["blocked.example"]));
        assert_eq!(rules[n - 3]["outboundTag"], direct_ob["tag"]);
        assert_eq!(rules[n - 2]["balancerTag"], lb_sticky["tag"]);
        assert_eq!(rules[n - 1]["outboundTag"], "proxy");

        // 2. Probe build
        let probe = build_xray_probe_config(&p, &settings, &[]).unwrap();
        assert!(probe.target.describe().starts_with("balancer ks-provider:"));
        assert!(probe.config.get("burstObservatory").is_some());
        let probe_rules = probe.config["routing"]["rules"].as_array().unwrap();
        // Probe retains internal fallback graph (v-fallback) but excludes external entry domain rule
        assert!(probe_rules.iter().any(|r| {
            r.get("inboundTag")
                .is_some_and(|t| t.to_string().contains(":v:"))
        }));
        assert!(
            !probe_rules
                .iter()
                .any(|r| r.get("domain") == Some(&json!(["blocked.example"])))
        );
    }

    #[test]
    fn simultaneous_standard_and_burst_observatory_rejected() {
        let raw = json!({
            "outbounds": [provider_vless("srv", "srv.example")],
            "observatory": { "probeUrl": "https://example.com/check", "subjectSelector": ["srv"] },
            "burstObservatory": { "pingConfig": { "destination": "https://example.com/check" }, "subjectSelector": ["srv"] },
        });
        let p = custom("provider", &raw);
        let err = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap_err();
        assert!(
            err.contains("both observatory and burstObservatory") || err.contains("simultaneous"),
            "{err}"
        );
    }

    #[test]
    fn inactive_stored_profiles_do_not_block_active_observed_profile() {
        let raw1 = json!({
            "outbounds": [provider_vless("srv-1", "srv1.example")],
            "burstObservatory": { "pingConfig": { "destination": "https://example.com/check" }, "subjectSelector": ["srv-1"] },
        });
        let raw2 = json!({
            "outbounds": [provider_vless("srv-2", "srv2.example")],
            "observatory": { "probeUrl": "https://example.com/check", "subjectSelector": ["srv-2"] },
        });
        let mut p1 = custom("provider", &raw1);
        p1.meta_mut().id = "p-1".into();
        let mut p2 = custom("provider", &raw2);
        p2.meta_mut().id = "p-2".into();
        let all = vec![p1.clone(), p2.clone()];
        // Finding 8: inactive stored profile p2 must not block active profile p1
        assert!(build_xray_config(&p1, &AdvancedSettings::default(), &[], &all).is_ok());
    }

    #[test]
    fn observer_selectors_do_not_capture_other_outbounds() {
        let raw = json!({
            "outbounds": [
                provider_vless("main", "main.example"),
                { "tag": "proxy-direct", "protocol": "freedom" },
            ],
            "routing": {
                "rules": [
                    { "type": "field", "network": "tcp,udp", "outboundTag": "main" },
                ],
            },
            "observatory": {
                "probeUrl": "https://example.com/check",
                "subjectSelector": ["main"],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let main_tag = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main.example")
            .unwrap()["tag"]
            .as_str()
            .unwrap();
        // Finding 1: selector rewritten to prefix-free opaque tag of main, never capturing proxy-direct
        assert_eq!(cfg["observatory"]["subjectSelector"], json!([main_tag]));
        assert!(!main_tag.starts_with("proxy"));
    }

    #[test]
    fn provider_virtual_proxy_select_does_not_hijack_client_alias() {
        let loopback = |tag: &str, in_tag: &str| {
            json!({
                "tag": tag, "protocol": "loopback",
                "settings": { "inboundTag": in_tag }
            })
        };
        let raw = json!({
            "outbounds": [
                provider_vless("srv-a", "a.example"),
                provider_vless("srv-b", "b.example"),
                loopback("lb-fb", "proxy-select"),
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb-main", "selector": ["srv-a"], "fallbackTag": "lb-fb" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["proxy-select"], "outboundTag": "srv-b" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "lb-main" },
                ],
            },
            "observatory": {
                "probeUrl": "https://example.com/check",
                "subjectSelector": ["srv-a"],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        let balancers = cfg["routing"]["balancers"].as_array().unwrap();
        let lb_main_tag = balancers[0]["tag"].as_str().unwrap();
        // Finding 2: Kasumi's generated alias loopback uses literal PROXY_SELECT
        assert_eq!(cfg["outbounds"][0]["settings"]["inboundTag"], PROXY_SELECT);
        // Generated alias rule dispatches literal PROXY_SELECT to the default balancer lb-main
        let alias_rule = rules
            .iter()
            .find(|r| r.get("inboundTag") == Some(&json!([PROXY_SELECT])))
            .unwrap();
        assert_eq!(alias_rule["balancerTag"], lb_main_tag);
    }

    #[test]
    fn internal_rules_preserve_tcp_and_udp_dispatch() {
        let loopback = json!({
            "tag": "lb-fb", "protocol": "loopback",
            "settings": { "inboundTag": "v" }
        });
        let raw = json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [
                provider_vless("srv-tcp", "tcp.example"),
                provider_vless("srv-udp", "udp.example"),
                loopback,
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["srv-tcp"], "fallbackTag": "lb-fb" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["v"], "network": "tcp", "outboundTag": "srv-tcp" },
                    { "type": "field", "inboundTag": ["v"], "network": "udp", "outboundTag": "srv-udp" },
                    { "type": "field", "inboundTag": ["in"], "network": "tcp,udp", "balancerTag": "lb" },
                ],
            },
            "observatory": {
                "probeUrl": "https://example.com/check",
                "subjectSelector": ["srv-tcp"],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // Finding 3: Both TCP and UDP rules for virtual inbound context v are preserved
        let v_rules: Vec<&Value> = rules
            .iter()
            .filter(|r| {
                r.get("inboundTag")
                    .is_some_and(|t| t.to_string().contains(":v:"))
            })
            .collect();
        assert!(
            v_rules
                .iter()
                .any(|r| r.get("network") == Some(&json!("tcp")))
        );
        assert!(
            v_rules
                .iter()
                .any(|r| r.get("network") == Some(&json!("udp")))
        );
    }

    #[test]
    fn ingress_conditions_map_to_controlled_entry_tags() {
        let raw = json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [provider_vless("srv", "srv.example")],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["in"], "outboundTag": "srv" },
                ],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // Finding 4: Ingress tag 'in' is mapped to Kasumi's client inbounds socks-in, http-in
        let entry_rule = rules
            .iter()
            .find(|r| {
                r.get("inboundTag") == Some(&json!(["socks-in", "http-in"]))
                    && r.get("port").is_none()
                    && r.get("network").is_none()
            })
            .unwrap();
        assert!(
            entry_rule["outboundTag"]
                .as_str()
                .unwrap()
                .starts_with("ks-provider:")
        );
    }

    #[test]
    fn internal_fallback_uses_original_first_outbound() {
        let loopback = json!({
            "tag": "lb", "protocol": "loopback",
            "settings": { "inboundTag": "v" }
        });
        let raw = json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [
                provider_vless("decoy", "decoy.example"),
                provider_vless("main", "main.example"),
                loopback,
            ],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["in"], "network": "tcp,udp", "outboundTag": "main" },
                    { "type": "field", "inboundTag": ["v"], "domain": ["only.example"], "outboundTag": "main" },
                ],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let decoy_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "decoy.example")
            .unwrap();
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // Finding 6: Unmatched virtual traffic falls back to the original first outbound (decoy), not main
        let fallback_rule = rules
            .iter()
            .find(|r| {
                r.get("inboundTag")
                    .is_some_and(|t| t.to_string().contains(":v:"))
                    && r.get("network") == Some(&json!("tcp,udp"))
            })
            .unwrap();
        assert_eq!(fallback_rule["outboundTag"], decoy_ob["tag"]);
    }

    #[test]
    fn transport_headers_are_not_retargeted_as_dialer_proxy() {
        let mut main = provider_vless("main", "main.example");
        main["streamSettings"]["sockopt"] = json!({ "dialerProxy": "relay" });
        main["streamSettings"]["network"] = "ws".into();
        main["streamSettings"]["wsSettings"] = json!({
            "path": "/ws",
            "headers": {
                "dialerProxy": "node-original",
                "CertificateFile": "literal-header"
            }
        });
        let raw = json!({
            "outbounds": [
                main,
                provider_vless("relay", "relay.example"),
                provider_vless("node-original", "node.example"),
            ]
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let main_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "main.example")
            .unwrap();
        let relay_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "relay.example")
            .unwrap();
        // Actual sockopt.dialerProxy is rewritten to relay's namespaced tag
        assert_eq!(
            main_ob["streamSettings"]["sockopt"]["dialerProxy"],
            relay_ob["tag"]
        );
        // wsSettings.headers stays byte-identical and is not corrupted
        assert_eq!(
            main_ob["streamSettings"]["wsSettings"]["headers"],
            json!({
                "dialerProxy": "node-original",
                "CertificateFile": "literal-header"
            })
        );
    }

    #[test]
    fn first_outbound_loopback_preserves_internal_graph_and_alias() {
        let loopback = json!({
            "tag": "lb-entry", "protocol": "loopback",
            "settings": { "inboundTag": "v" }
        });
        let raw = json!({
            "inbounds": [{ "tag": "in", "protocol": "socks" }],
            "outbounds": [
                loopback,
                provider_vless("conditional", "cond.example"),
                provider_vless("fallback", "fall.example"),
            ],
            "routing": {
                "rules": [
                    { "type": "field", "inboundTag": ["v"], "domain": ["special.example"], "outboundTag": "conditional" },
                    { "type": "field", "inboundTag": ["v"], "network": "tcp,udp", "outboundTag": "fallback" },
                ],
            },
        });
        let p = custom("provider", &raw);
        let cfg = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        let obs = cfg["outbounds"].as_array().unwrap();
        let loopback_ob = obs
            .iter()
            .find(|o| o["protocol"] == "loopback" && o["tag"] != "proxy")
            .unwrap();
        let cond_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "cond.example")
            .unwrap();
        let fall_ob = obs
            .iter()
            .find(|o| o["settings"]["vnext"][0]["address"] == "fall.example")
            .unwrap();

        let rules = cfg["routing"]["rules"].as_array().unwrap();
        // proxy-select dispatches to the namespaced loopback entry
        let proxy_select_rule = rules
            .iter()
            .find(|r| r.get("inboundTag") == Some(&json!([PROXY_SELECT])))
            .unwrap();
        assert_eq!(proxy_select_rule["outboundTag"], loopback_ob["tag"]);

        // Internal rules preserve both conditional and fallback
        let v_rules: Vec<&Value> = rules
            .iter()
            .filter(|r| {
                r.get("inboundTag")
                    .is_some_and(|t| t.to_string().contains(":v:"))
            })
            .collect();
        assert_eq!(v_rules.len(), 2);
        assert_eq!(v_rules[0]["domain"], json!(["special.example"]));
        assert_eq!(v_rules[0]["outboundTag"], cond_ob["tag"]);
        assert_eq!(v_rules[1]["outboundTag"], fall_ob["tag"]);
    }

    #[test]
    fn provider_graph_cycle_detection() {
        let loopback = |tag: &str, in_tag: &str| {
            json!({
                "tag": tag, "protocol": "loopback",
                "settings": { "inboundTag": in_tag }
            })
        };
        // A cycle: lb-1 -> loopback -> rule -> lb-1
        let cyclic = json!({
            "outbounds": [
                provider_vless("srv", "srv.example"),
                loopback("lb-fb", "v-cycle"),
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb-1", "selector": ["srv"], "fallbackTag": "lb-fb" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["v-cycle"], "balancerTag": "lb-1" },
                ],
            },
            "observatory": { "probeUrl": "https://example.com/check", "subjectSelector": ["srv"] },
        });
        let p = custom("provider", &cyclic);
        let err = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap_err();
        assert!(err.contains("cycle") || err.contains("loop"), "{err}");

        // An acyclic diamond graph passes
        let diamond = json!({
            "outbounds": [
                provider_vless("srv-common", "c.example"),
                loopback("fb-1", "v-1"),
                loopback("fb-2", "v-2"),
            ],
            "routing": {
                "balancers": [
                    { "tag": "top", "selector": ["srv-common"], "fallbackTag": "fb-1" },
                    { "tag": "branch", "selector": ["srv-common"], "fallbackTag": "fb-2" },
                    { "tag": "bottom", "selector": ["srv-common"] },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["v-1"], "balancerTag": "branch" },
                    { "type": "field", "inboundTag": ["v-2"], "balancerTag": "bottom" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "top" },
                ],
            },
            "observatory": { "probeUrl": "https://example.com/check", "subjectSelector": ["srv-common"] },
        });
        let p_ok = custom("provider", &diamond);
        assert!(build_xray_config(&p_ok, &AdvancedSettings::default(), &[], &[]).is_ok());
    }

    #[test]
    fn chaining_via_on_expanded_graph_rejected() {
        let loopback = json!({
            "tag": "lb-fb", "protocol": "loopback",
            "settings": { "inboundTag": "v-fb" }
        });
        let raw = json!({
            "outbounds": [
                provider_vless("srv", "srv.example"),
                loopback,
            ],
            "routing": {
                "balancers": [
                    { "tag": "lb", "selector": ["srv"], "fallbackTag": "lb-fb" },
                ],
                "rules": [
                    { "type": "field", "inboundTag": ["v-fb"], "outboundTag": "srv" },
                    { "type": "field", "network": "tcp,udp", "balancerTag": "lb" },
                ],
            },
            "observatory": { "probeUrl": "https://example.com/check", "subjectSelector": ["srv"] },
        });
        let mut p = custom("provider", &raw);
        p.meta_mut().via = Some("hop".into());
        let err = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap_err();
        assert!(
            err.contains("chaining (.via) on expanded loopback/fallback graphs is not supported"),
            "{err}"
        );
    }

    #[test]
    fn observatory_subject_selector_service_target_rejected() {
        let raw = json!({
            "outbounds": [
                provider_vless("srv", "srv.example"),
                { "tag": "direct", "protocol": "freedom" },
            ],
            "observatory": {
                "probeUrl": "https://example.com/check",
                "subjectSelector": ["direct"],
            },
        });
        let p = custom("provider", &raw);
        let err = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap_err();
        assert!(
            err.contains("observatory selector matches service or loopback outbound")
                || err.contains("proxy outbounds"),
            "{err}"
        );
    }
}
