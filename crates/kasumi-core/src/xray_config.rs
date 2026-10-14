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
    drop_pinned_allow_insecure, is_service_outbound, sanitize_provider_xray,
};
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
    json!({
        "tag": "proxy", "protocol": "hysteria",
        "settings": { "version": 2, "address": h.endpoint.address, "port": h.endpoint.port },
        "streamSettings": {
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
            if k.max_sending_window != 0 {
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
pub(crate) fn xray_rule_has_condition(rule: &Map<String, Value>) -> bool {
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
    provider_rules: &[Value],
) -> Value {
    let domain_strategy = wire(&s.domain_strategy);
    // Bypass-geo rule for the always-on `force-in` inbound — pushed first so traffic
    // arriving there reaches `proxy` ahead of the geo/user rules.
    let force_rule = json!({ "type": "field", "inboundTag": ["force-in"], "network": "tcp,udp", "outboundTag": "proxy" });
    let dns_rule = json!({ "type": "field", "inboundTag": ["socks-in", "http-in"], "port": 53, "outboundTag": dns_outbound_tag });
    let final_rule = json!({ "type": "field", "inboundTag": ["socks-in", "http-in"], "network": "tcp,udp", "outboundTag": "proxy" });

    if s.routing_mode == crate::state::RoutingMode::Rules && !routing_rules.is_empty() {
        let mut rules: Vec<Value> = vec![force_rule, dns_rule];
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
        rules.extend_from_slice(provider_rules);
        rules.push(final_rule);
        return json!({ "domainStrategy": domain_strategy, "rules": rules });
    }

    if s.routing_mode == crate::state::RoutingMode::Custom
        && let Some(cr) = s.custom_routing.as_deref().filter(|x| !x.trim().is_empty())
        && let Some(Value::Array(parsed)) = parse_json_safe(cr)
    {
        let mut rules: Vec<Value> = vec![force_rule, dns_rule];
        rules.extend(
            parsed
                .into_iter()
                .filter(|r| r.as_object().is_none_or(xray_rule_has_condition)),
        );
        rules.extend_from_slice(provider_rules);
        rules.push(final_rule);
        return json!({ "domainStrategy": domain_strategy, "rules": rules });
    }

    let mut rules: Vec<Value> = vec![force_rule, dns_rule];
    if s.fake_dns {
        rules.push(json!({ "type": "field", "ip": [FAKEIP_INET4_RANGE], "outboundTag": "proxy" }));
    }
    rules.extend_from_slice(provider_rules);
    rules.push(final_rule);
    json!({ "domainStrategy": domain_strategy, "rules": rules })
}

/// Build the full Xray config object from a profile + settings.
pub fn build_xray_config(
    p: &Profile,
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
) -> Result<Value, String> {
    if let Profile::Custom(_) = p
        && let Some(c) = core_conflict(p)
    {
        return Err(c.to_string());
    }
    let provider = match p {
        Profile::Custom(c) if c.origin == CustomOrigin::User => {
            return match parse_json_safe(&c.raw) {
                Some(mut v @ Value::Object(_)) => {
                    // Runs as written, but for the key xray refuses that a pin makes moot.
                    drop_pinned_allow_insecure(&mut v, "", &mut Vec::new());
                    Ok(v)
                }
                _ => Err("custom profile contains invalid JSON".to_string()),
            };
        }
        // Sanitised on every build, not only at import: stored state can be edited.
        Profile::Custom(c) => provider_outbounds(c, profiles)?,
        _ => ActiveOutbounds {
            outbounds: vec![build_outbound(p, s).ok_or_else(|| match core_conflict(p) {
                Some(c) => c.to_string(),
                None => format!("{:?} requires sing-box", p.protocol()),
            })?],
            rules: Vec::new(),
            balancers: Vec::new(),
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
        balancers,
    } = provider;
    let mut targets = po.outbounds.clone();
    let mut hops: Vec<Value> = Vec::new();
    let mut emitted: HashSet<String> = targets
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    let entry = direct_dialer(&head)?;
    attach_chain(p, &mut head[entry], s, profiles, &mut hops, &mut emitted)?;
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
        &provider_rules,
    );
    if !balancers.is_empty() {
        routing["balancers"] = balancers.into();
    }
    Ok(json!({
        "log": { "loglevel": log_level },
        "dns": build_dns(s),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": routing,
    }))
}

/// The active profile's outbounds, `proxy` first, and for a provider config the
/// routing between them.
struct ActiveOutbounds {
    outbounds: Vec<Value>,
    rules: Vec<Value>,
    balancers: Vec<Value>,
}

/// Fit a provider config's sanitised outbounds into Kasumi's skeleton. Its first
/// outbound that reaches a server becomes `proxy`, which Kasumi's own rules route
/// to. A freedom `direct` or blackhole `block` gives way to Kasumi's identical
/// one; any other tag that is, or prefixes, one of Kasumi's or a profile id (which
/// tags chain hops and rule targets) is renamed so it can't shadow Kasumi's outbounds.
fn provider_outbounds(c: &Custom, profiles: &[Profile]) -> Result<ActiveOutbounds, String> {
    let raw = parse_json_safe(&c.raw).ok_or("custom profile contains invalid JSON")?;
    let sanitized =
        sanitize_provider_xray(&raw).map_err(|e| format!("provider config rejected: {e}"))?;
    let proxy_idx = sanitized
        .outbounds
        .iter()
        .position(|o| !is_service_outbound(o))
        .ok_or("provider config rejected: no proxy outbound")?;

    // Selectors match by prefix, so a tag that merely starts one of Kasumi's
    // would pull it into a provider balancer.
    let reserved = |t: &str| {
        SPECIAL_OUTBOUND_TAGS
            .iter()
            .chain(&[DNS_OUT])
            .any(|k| k.starts_with(t))
            || profiles.iter().any(|p| p.meta().id.starts_with(t))
    };
    let mut taken: HashSet<String> = sanitized
        .outbounds
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    let mut renames: BTreeMap<String, String> = BTreeMap::new();
    let mut outbounds = Vec::new();
    for (i, mut ob) in sanitized.outbounds.into_iter().enumerate() {
        let tag = ob["tag"].as_str().map(str::to_string);
        if i == proxy_idx {
            if let Some(t) = tag.filter(|t| t != "proxy") {
                renames.insert(t, "proxy".into());
            }
            ob["tag"] = "proxy".into();
            outbounds.insert(0, ob);
            continue;
        }
        // Without a tag nothing but the default route reaches it, and that is `proxy`.
        let Some(tag) = tag else { continue };
        let equivalent = match tag.as_str() {
            "direct" => ob["protocol"] == "freedom",
            "block" => ob["protocol"] == "blackhole",
            _ => false,
        };
        if equivalent {
            continue;
        }
        if reserved(&tag) {
            let fresh = (1..)
                .map(|n| {
                    format!(
                        "{tag}-provider{}",
                        if n == 1 { String::new() } else { n.to_string() }
                    )
                })
                .find(|t| !taken.contains(t) && !reserved(t))
                .expect("an unused tag exists");
            taken.insert(fresh.clone());
            ob["tag"] = fresh.as_str().into();
            renames.insert(tag, fresh);
        }
        outbounds.push(ob);
    }

    let routing = sanitized.routing.unwrap_or(Value::Null);
    let mut rules: Vec<Value> = routing["rules"].as_array().cloned().unwrap_or_default();
    let mut balancers: Vec<Value> = routing["balancers"].as_array().cloned().unwrap_or_default();
    // One lookup per reference: a tag freed by one rename may be another's target.
    for ob in &mut outbounds {
        retarget_dialers(ob, &renames);
        retarget(
            ob.get_mut("proxySettings").and_then(|p| p.get_mut("tag")),
            &renames,
        );
    }
    for rule in &mut rules {
        retarget(rule.get_mut("outboundTag"), &renames);
    }
    for b in &mut balancers {
        retarget(b.get_mut("fallbackTag"), &renames);
        if let Some(sel) = b.get_mut("selector").and_then(Value::as_array_mut) {
            sel.iter_mut().for_each(|m| retarget(Some(m), &renames));
        }
    }
    Ok(ActiveOutbounds {
        outbounds,
        rules,
        balancers,
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

/// Index of the outbound in `head` that connects to its server itself: `proxy`,
/// or the last of the outbounds it dials through. A profile's own `via` chain
/// attaches there, in front of the provider's.
fn direct_dialer(head: &[Value]) -> Result<usize, String> {
    let mut at = 0;
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
        // The first server outbound is what Kasumi's rules call `proxy`; the
        // provider's freedom `direct` gives way to Kasumi's.
        assert_eq!(tags(&cfg), ["proxy", "backup", "direct", "block"]);
        assert_eq!(
            cfg["outbounds"][0]["settings"]["vnext"][0]["address"],
            "main.example"
        );
        let text = cfg.to_string();
        assert!(
            !text.contains("/data/adb") && !text.contains("\"mark\""),
            "{text}"
        );

        // Provider rules sit after Kasumi's, before the catch-all to `proxy`.
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        let n = rules.len();
        assert_eq!(
            rules[n - 1],
            typed["routing"]["rules"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .clone()
        );
        assert_eq!(rules[n - 4]["outboundTag"], "direct");
        assert!(rules[n - 4].get("inboundTag").is_none());
        assert_eq!(rules[n - 3]["outboundTag"], "backup");
        assert_eq!(rules[n - 2]["outboundTag"], "proxy");
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
            .position(|r| r["outboundTag"] == "backup")
            .unwrap();
        assert!(ours < theirs);
    }

    #[test]
    fn provider_tags_never_shadow_kasumi_outbounds() {
        let mut main = provider_vless("main", "main.example");
        main["streamSettings"]["sockopt"] = json!({ "dialerProxy": "block" });
        let raw = json!({
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
        assert_eq!(
            tags(&cfg),
            ["proxy", "block-provider", "c-provider", "direct", "block"]
        );
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
            "block-provider"
        );
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert!(
            rules
                .iter()
                .any(|r| r["ip"][0] == "1.1.1.1" && r["outboundTag"] == "block-provider")
        );
        // The balancer keeps exactly its members, under their new tags.
        assert_eq!(
            cfg["routing"]["balancers"],
            json!([{ "tag": "lb", "selector": ["proxy", "c-provider"] }])
        );
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
        let by_tag = |t: &str| obs.iter().find(|o| o["tag"] == t).unwrap();
        assert_eq!(
            by_tag("proxy")["streamSettings"]["sockopt"]["dialerProxy"],
            "relay"
        );
        assert_eq!(
            by_tag("relay")["streamSettings"]["sockopt"]["dialerProxy"],
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
        assert!(err.contains("loop"), "{err}");
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
        raw["inbounds"] = json!([{ "tag": "x", "protocol": "dokodemo-door", "port": 9 }]);
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
}
