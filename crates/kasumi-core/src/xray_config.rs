//! Build a complete Xray `config.json` from a Profile + AdvancedSettings.
//! Builds a `serde_json::Value` directly; pinned against committed reference
//! fixtures (compared as Value, so key order is irrelevant).

use serde_json::{json, Map, Value};

use crate::config_shared::{build_ws_path, parse_pem_chain, split_list};
use crate::enums::{Fingerprint, HeaderType, Security};
use crate::mixins::Transport;
use crate::profile::Profile;
use crate::state::{
    AdvancedSettings, RoutingRule, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT,
    DEFAULT_REMOTE_DNS, FAKEIP_INET4_RANGE,
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
            let mut server = json!({ "address": t.endpoint.address, "port": t.endpoint.port, "password": t.password });
            if t.flow != crate::enums::Flow::Empty {
                server["flow"] = wire(&t.flow).into();
            }
            json!({ "tag": "proxy", "protocol": "trojan", "settings": { "servers": [server] } })
        }
        Profile::Shadowsocks(ss) => json!({
            "tag": "proxy", "protocol": "shadowsocks",
            "settings": { "servers": [{ "address": ss.endpoint.address, "port": ss.endpoint.port, "method": wire(&ss.method), "password": ss.password, "uot": true }]},
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
    let address: Vec<String> = if w.local_address.is_empty() {
        vec!["172.16.0.2/32".to_string()]
    } else {
        w.local_address
            .split(',')
            .map(|x| x.trim().to_string())
            .collect()
    };
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
        "endpoint": format!("{}:{}", w.endpoint.address, w.endpoint.port),
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
    if tls.allow_insecure {
        m.insert("allowInsecure".into(), true.into());
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
                json!({ "Host": tc.host.split(',').collect::<Vec<_>>() })
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

fn build_rule_object(rule: &RoutingRule, resolve: &dyn Fn(&str) -> String) -> Value {
    let mut m = Map::new();
    m.insert("type".into(), "field".into());
    if let Some(d) = &rule.domain {
        if !d.is_empty() {
            m.insert("domain".into(), json!(d));
        }
    }
    if let Some(ip) = &rule.ip {
        if !ip.is_empty() {
            m.insert("ip".into(), json!(ip));
        }
    }
    if let Some(port) = &rule.port {
        if !port.is_empty() {
            m.insert("port".into(), port.clone().into());
        }
    }
    if let Some(net) = &rule.network {
        m.insert("network".into(), wire(net).into());
    }
    if let Some(proto) = &rule.protocol {
        if !proto.is_empty() {
            m.insert("protocol".into(), json!(proto));
        }
    }
    m.insert("outboundTag".into(), resolve(&rule.outbound_tag).into());
    Value::Object(m)
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

fn build_routing(
    s: &AdvancedSettings,
    dns_outbound_tag: &str,
    routing_rules: &[RoutingRule],
    resolve: &dyn Fn(&str) -> String,
) -> Value {
    let domain_strategy = wire(&s.domain_strategy);
    let force_rule = json!({ "type": "field", "inboundTag": ["force-in"], "network": "tcp,udp", "outboundTag": "proxy" });
    let has_force = s
        .app_filter
        .values()
        .any(|m| *m == crate::state::AppFilterMode::ForceProxy);
    let dns_rule = json!({ "type": "field", "inboundTag": ["socks-in", "http-in"], "port": 53, "outboundTag": dns_outbound_tag });
    let final_rule = json!({ "type": "field", "inboundTag": ["socks-in", "http-in"], "network": "tcp,udp", "outboundTag": "proxy" });

    if s.routing_mode == crate::state::RoutingMode::Rules && !routing_rules.is_empty() {
        let mut rules: Vec<Value> = Vec::new();
        if has_force {
            rules.push(force_rule);
        }
        rules.push(dns_rule);
        for r in routing_rules.iter().filter(|r| r.enabled) {
            rules.push(build_rule_object(r, resolve));
        }
        rules.push(final_rule);
        return json!({ "domainStrategy": domain_strategy, "rules": rules });
    }

    if s.routing_mode == crate::state::RoutingMode::Custom {
        if let Some(cr) = s.custom_routing.as_deref().filter(|x| !x.trim().is_empty()) {
            if let Some(Value::Array(parsed)) = parse_json_safe(cr) {
                let mut rules: Vec<Value> = Vec::new();
                if has_force {
                    rules.push(force_rule);
                }
                rules.push(dns_rule);
                rules.extend(parsed);
                rules.push(final_rule);
                return json!({ "domainStrategy": domain_strategy, "rules": rules });
            }
        }
    }

    let mut rules: Vec<Value> = Vec::new();
    if has_force {
        rules.push(force_rule);
    }
    rules.push(dns_rule);
    if s.fake_dns {
        rules.push(json!({ "type": "field", "ip": [FAKEIP_INET4_RANGE], "outboundTag": "proxy" }));
    }
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
    if let Profile::Custom(c) = p {
        return match parse_json_safe(&c.raw) {
            Some(v @ Value::Object(_)) => Ok(v),
            _ => Err("custom profile contains invalid JSON".to_string()),
        };
    }

    let outbound =
        build_outbound(p, s).ok_or_else(|| format!("{:?} requires sing-box", p.protocol()))?;
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
    let force_port = socks_port + 2;
    let has_force = s
        .app_filter
        .values()
        .any(|m| *m == crate::state::AppFilterMode::ForceProxy);
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
    if has_force {
        inbounds.push(json!({
            "tag": "force-in", "port": force_port, "listen": listen, "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
        }));
    }

    let mut outbounds = vec![outbound];
    outbounds.extend(po.outbounds.iter().cloned());
    outbounds.push(json!({ "protocol": "freedom", "tag": "direct" }));
    outbounds.push(json!({ "protocol": "blackhole", "tag": "block" }));

    Ok(json!({
        "log": { "loglevel": log_level },
        "dns": build_dns(s),
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": build_routing(s, dns_outbound_tag, routing_rules, &resolve),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = include_str!("../tests/fixtures/xray_config.json");

    #[test]
    fn build_matches_reference() {
        let cases: Vec<Value> = serde_json::from_str(FIXTURES).unwrap();
        assert_eq!(cases.len(), 38);
        for c in &cases {
            let label = c["label"].as_str().unwrap();
            let uri = c["uri"].as_str().unwrap();
            let settings: AdvancedSettings = serde_json::from_value(c["settings"].clone()).unwrap();
            let rules: Vec<RoutingRule> =
                serde_json::from_value(c["routingRules"].clone()).unwrap();
            // Cases exercising editor-only fields carry a flat profile (a URI can't
            // express them); upgrade it through the migration. Otherwise parse the URI.
            let profile = if c.get("profile").is_some_and(|p| !p.is_null()) {
                let mut flat = c["profile"].clone();
                crate::migrate::migrate_profile(&mut flat);
                serde_json::from_value(flat)
                    .unwrap_or_else(|e| panic!("migrate profile for {label}: {e}"))
            } else {
                crate::share::parse_share_link(uri, None)
                    .unwrap_or_else(|| panic!("parse failed for {label}: {uri}"))
            };
            let built =
                build_xray_config(&profile, &settings, &rules, std::slice::from_ref(&profile))
                    .unwrap_or_else(|e| panic!("build failed for {label}: {e}"));
            assert_eq!(built, c["config"], "config mismatch for {label}");
        }
    }

    #[test]
    fn socks_auth_gates_the_local_inbounds() {
        let p =
            crate::share::parse_share_link("vless://u@e.x:443?type=tcp&security=tls&sni=s", None)
                .unwrap();
        let mut s = AdvancedSettings::default();
        s.socks_username = Some("alice".into());
        s.socks_password = Some("s3cret".into());
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
}
