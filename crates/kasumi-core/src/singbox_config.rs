//! Build a complete sing-box config from a Profile + AdvancedSettings. Builds a
//! `serde_json::Value` directly. The emitted config is validated against the real
//! core on PR by `core-compat.yml` (`tests/core_validation.rs`); targeted invariants
//! (e.g. inbound/route shape) are covered by the unit tests below.

use serde_json::{Map, Value, json};

use crate::config_shared::{parse_pem_chain, split_csv, split_list};
use crate::enums::{Fingerprint, HeaderType, Security};
use crate::mixins::Transport;
use crate::profile::Profile;
use crate::state::{
    AdvancedSettings, AppFilterMode, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT,
    DEFAULT_REMOTE_DNS, DomainStrategy, FAKEIP_INET4_RANGE, RoutingMode, RoutingRule,
    force_socks_port,
};

/// iproute2 table + rule-priority indices that native sing-box `auto_route`
/// installs on Linux. The main tun uses sing-tun's defaults (`DefaultIPRoute2TableIndex`
/// = 2022, `DefaultIPRoute2RuleIndex` = 9000); the force tun is shifted onto its own
/// table + rule so two `auto_route` tuns don't collide (see `build_singbox_tun_inbounds`).
/// Desktop teardown of orphaned routing keys off exactly these — keep them in sync.
pub const SINGBOX_MAIN_TABLE: u32 = 2022;
pub const SINGBOX_MAIN_RULE_PRIO: u32 = 9000;
pub const SINGBOX_FORCE_TABLE: u32 = 2023;
pub const SINGBOX_FORCE_RULE_PRIO: u32 = 9010;

fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Insertion-ordered tag set — sing-box `rule_set` order is significant, so
/// tags must keep first-seen order (a plain sorted/hashed set would reorder them).
type Tags = Vec<String>;
fn tag_insert(v: &mut Tags, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}
fn tag_extend(v: &mut Tags, other: &Tags) {
    for t in other {
        tag_insert(v, t.clone());
    }
}

/// Format a JS `Number → String` the way `${n}s`/interval strings expect
/// (integers without a trailing `.0`).
fn num_str(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn push_str(target: &mut Value, key: &str, value: String) {
    let arr = target
        .as_object_mut()
        .unwrap()
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()));
    arr.as_array_mut().unwrap().push(Value::String(value));
}

fn push_num(target: &mut Value, key: &str, value: i64) {
    let arr = target
        .as_object_mut()
        .unwrap()
        .entry(key)
        .or_insert_with(|| Value::Array(Vec::new()));
    arr.as_array_mut().unwrap().push(Value::from(value));
}

fn has_match_fields(rule: &Value, keys: &[&str]) -> bool {
    let Some(o) = rule.as_object() else {
        return false;
    };
    keys.iter().any(|k| o.contains_key(*k))
}

// ---------- TLS ----------

/// Accepts either a raw base64 ECHConfigList (share-link form) or a value that
/// already carries the PEM armor.
fn ech_config_pem(ech: &str) -> Vec<String> {
    let trimmed = ech.trim();
    if trimmed.contains("-----BEGIN ECH CONFIGS-----") {
        return trimmed.lines().map(str::to_string).collect();
    }
    let base64: String = trimmed.split_whitespace().collect();
    let mut lines = vec!["-----BEGIN ECH CONFIGS-----".to_string()];
    lines.extend(
        base64
            .as_bytes()
            .chunks(64)
            .map(|c| String::from_utf8(c.to_vec()).unwrap_or_default()),
    );
    lines.push("-----END ECH CONFIGS-----".to_string());
    lines
}

fn build_singbox_tls(p: &Profile, force: bool, s: &AdvancedSettings) -> Option<Value> {
    let tls = p.tls()?;
    let active = force || tls.security == Security::Tls || tls.security == Security::Reality;
    if !active {
        return None;
    }
    let host = p
        .transport()
        .map(|t| t.host().to_string())
        .unwrap_or_default();
    let authority = p
        .transport()
        .map(|t| t.authority().to_string())
        .unwrap_or_default();
    let pin_sha256 = match p {
        Profile::Hysteria2(h) => h.pin_sha256.clone(),
        _ => String::new(),
    };
    let pin = if !pin_sha256.is_empty() {
        pin_sha256
    } else {
        tls.pcs.clone()
    };
    let certs = parse_pem_chain(&tls.cert);
    let address = p.endpoint().map(|e| e.address.clone()).unwrap_or_default();
    let server_name = if !tls.sni.is_empty() {
        tls.sni.clone()
    } else if !authority.is_empty() {
        authority
    } else if !host.is_empty() {
        host
    } else {
        address
    };

    let mut t = json!({
        "enabled": true,
        "server_name": server_name,
        "insecure": tls.allow_insecure,
    });
    if tls.disable_sni {
        t["disable_sni"] = true.into();
    }
    if !tls.tls_min_version.is_empty() {
        t["min_version"] = tls.tls_min_version.clone().into();
    }
    if !tls.tls_max_version.is_empty() {
        t["max_version"] = tls.tls_max_version.clone().into();
    }
    if !tls.tls_cipher_suites.is_empty() {
        t["cipher_suites"] = tls.tls_cipher_suites.clone().into();
    }
    if !tls.tls_curve_preferences.is_empty() {
        t["curve_preferences"] = tls.tls_curve_preferences.clone().into();
    }
    if let Some(certs) = &certs
        && !certs.is_empty()
    {
        t["certificate"] = json!(certs);
    }
    if s.fragment {
        t["record_fragment"] = true.into();
    }
    if !tls.alpn.is_empty() {
        t["alpn"] = tls.alpn.clone().into();
    }
    if !pin.is_empty() {
        t["certificate_public_key_sha256"] = json!([pin]);
    }
    if !tls.ech.is_empty() {
        // sing-box joins `config` with "\n" and runs `pem.Decode`, demanding a
        // `ECH CONFIGS` PEM block (common/tls/ech.go). Share links carry the raw
        // base64 ECHConfigList (what xray's `echConfigList` wants), so wrap it in
        // a PEM block here unless it already is one.
        t["ech"] = json!({ "enabled": true, "config": ech_config_pem(&tls.ech) });
    }
    // Some outbounds reject a uTLS config: hysteria2/tuic drive their own QUIC TLS
    // stack (sing-box errors `unsupported usage for uTLS` on every dial), and the
    // naive outbound uses a chromium-style TLS (`uTLS is not supported on naive
    // outbound` at init). Skip uTLS for those.
    let no_utls = matches!(
        p,
        Profile::Hysteria2(_) | Profile::Tuic(_) | Profile::Naive(_)
    );
    if tls.fingerprint != Fingerprint::Empty && !no_utls {
        t["utls"] = json!({ "enabled": true, "fingerprint": wire(&tls.fingerprint) });
    }
    if tls.security == Security::Reality {
        t["reality"] =
            json!({ "enabled": true, "public_key": tls.public_key, "short_id": tls.short_id });
        t["insecure"] = false.into();
    }
    Some(t)
}

// ---------- transport ----------

fn build_singbox_transport(p: &Profile) -> Option<Value> {
    let t = p.transport()?;
    match t {
        Transport::Ws(w) => {
            let mut v = json!({ "type": "ws" });
            if !w.path.is_empty() {
                v["path"] = w.path.clone().into();
            }
            // The ws `Host` header: an explicit profile host wins, otherwise fall
            // back to the server domain *without* the port. Left unset, sing-box
            // sends the server address with its port (`domain:443`), which
            // host-routing gateways (edge platforms) reject with HTTP 400 — xray
            // sends the bare domain, which is why the same profile works there.
            let host = if !w.host.is_empty() {
                w.host.clone()
            } else {
                p.endpoint().map(|e| e.address.clone()).unwrap_or_default()
            };
            let mut headers = Map::new();
            if !host.is_empty() {
                headers.insert("Host".into(), host.into());
            }
            for (k, val) in &w.headers {
                headers.insert(k.clone(), val.clone().into());
            }
            if !headers.is_empty() {
                v["headers"] = Value::Object(headers);
            }
            if w.early_data > 0 {
                v["max_early_data"] = w.early_data.into();
                v["early_data_header_name"] = if w.early_data_header.is_empty() {
                    "Sec-WebSocket-Protocol".into()
                } else {
                    w.early_data_header.clone().into()
                };
            } else if !w.early_data_header.is_empty() {
                v["early_data_header_name"] = w.early_data_header.clone().into();
            }
            Some(v)
        }
        Transport::Grpc(g) => {
            let mut v = json!({ "type": "grpc", "service_name": g.service_name.clone() });
            if g.idle_timeout != 0 {
                v["idle_timeout"] = format!("{}s", g.idle_timeout).into();
            }
            if g.ping_timeout != 0 {
                v["ping_timeout"] = format!("{}s", g.ping_timeout).into();
            }
            if g.permit_without_stream {
                v["permit_without_stream"] = true.into();
            }
            Some(v)
        }
        Transport::H2(h) => {
            let mut v = json!({ "type": "http" });
            if let Some(hosts) = split_csv(&h.host) {
                v["host"] = hosts.into();
            }
            if !h.path.is_empty() {
                v["path"] = h.path.clone().into();
            }
            if h.idle_timeout != 0 {
                v["idle_timeout"] = format!("{}s", h.idle_timeout).into();
            }
            if h.ping_timeout != 0 {
                v["ping_timeout"] = format!("{}s", h.ping_timeout).into();
            }
            Some(v)
        }
        Transport::Httpupgrade(h) => {
            let mut v = json!({ "type": "httpupgrade" });
            if !h.path.is_empty() {
                v["path"] = h.path.clone().into();
            }
            if !h.host.is_empty() {
                v["host"] = h.host.clone().into();
            }
            Some(v)
        }
        Transport::Quic(_) => Some(json!({ "type": "quic" })),
        Transport::Tcp(tc) => {
            if tc.header_type != HeaderType::Http {
                return None;
            }
            let mut v = json!({ "type": "http" });
            if let Some(hosts) = split_csv(&tc.host) {
                v["host"] = hosts.into();
            }
            if !tc.path.is_empty() {
                v["path"] = tc.path.clone().into();
            }
            Some(v)
        }
        // xhttp/kcp aren't sing-box transports.
        Transport::Xhttp(_) | Transport::Kcp(_) => None,
    }
}

fn build_singbox_mux(p: &Profile, s: &AdvancedSettings) -> Option<Value> {
    if !p.mux_enabled() {
        return None;
    }
    Some(json!({ "enabled": true, "protocol": "h2mux", "max_connections": s.mux_concurrency }))
}

fn build_server_ports(ports: &str) -> Vec<String> {
    split_csv(ports)
        .unwrap_or_default()
        .into_iter()
        .map(|x| {
            let port = x.replace('-', ":");
            if port.contains(':') {
                port
            } else {
                format!("{port}:{port}")
            }
        })
        .collect()
}

// ---------- outbound per protocol ----------

/// Build the sing-box outbound (or wireguard endpoint) object for a profile.
pub fn build_singbox_outbound(p: &Profile, s: &AdvancedSettings) -> Value {
    let mut base = json!({ "tag": "proxy", "type": wire_protocol(p) });
    if let Some(ep) = p.endpoint() {
        base["server"] = ep.address.clone().into();
        base["server_port"] = ep.port.into();
    }

    let apply_tls = |base: &mut Value, force: bool| {
        if let Some(tls) = build_singbox_tls(p, force, s) {
            base["tls"] = tls;
        }
    };
    let apply_transport = |base: &mut Value| {
        if let Some(tr) = build_singbox_transport(p) {
            base["transport"] = tr;
        }
    };
    let apply_mux = |base: &mut Value| {
        if let Some(mux) = build_singbox_mux(p, s) {
            base["multiplex"] = mux;
        }
    };

    match p {
        Profile::Vmess(v) => {
            base["uuid"] = v.uuid.clone().into();
            base["alter_id"] = v.alter_id.into();
            base["security"] = wire(&v.encryption).into();
            if v.packet_encoding != crate::enums::PacketEncoding::Empty {
                base["packet_encoding"] = wire(&v.packet_encoding).into();
            }
            if v.vmess_global_padding {
                base["global_padding"] = true.into();
            }
            if v.vmess_authenticated_length {
                base["authenticated_length"] = true.into();
            }
            apply_mux(&mut base);
            apply_transport(&mut base);
            apply_tls(&mut base, false);
        }
        Profile::Vless(v) => {
            base["uuid"] = v.uuid.clone().into();
            base["packet_encoding"] = if v.packet_encoding == crate::enums::PacketEncoding::Empty {
                "xudp".into()
            } else {
                wire(&v.packet_encoding).into()
            };
            if v.flow != crate::enums::Flow::Empty {
                base["flow"] = wire(&v.flow).into();
            } else {
                apply_mux(&mut base);
            }
            apply_transport(&mut base);
            apply_tls(&mut base, false);
        }
        Profile::Trojan(v) => {
            base["password"] = v.password.clone().into();
            apply_mux(&mut base);
            apply_transport(&mut base);
            apply_tls(&mut base, false);
        }
        Profile::Shadowsocks(v) => {
            base["method"] = wire(&v.method).into();
            base["password"] = v.password.clone().into();
            match &v.transport {
                Transport::Tcp(tc) if tc.header_type == HeaderType::Http => {
                    base["plugin"] = "obfs-local".into();
                    base["plugin_opts"] = format!("obfs=http;obfs-host={};", tc.host).into();
                }
                other => {
                    let mut args = String::new();
                    match other {
                        Transport::Ws(w) => {
                            args.push_str("mode=websocket;");
                            args.push_str(&format!("host={};", w.host));
                            let path = w
                                .path
                                .replace('\\', "\\\\")
                                .replace('=', "\\=")
                                .replace(',', "\\,");
                            args.push_str(&format!("path={path};"));
                        }
                        Transport::Quic(_) => args.push_str("mode=quic;"),
                        _ => {}
                    }
                    if v.tls.security == Security::Tls {
                        args.push_str("tls;");
                    }
                    if !args.is_empty() {
                        base["plugin"] = "v2ray-plugin".into();
                        let opts = format!("{args}mux=0;");
                        base["plugin_opts"] = opts.trim_end_matches(';').to_string().into();
                    }
                }
            }
            apply_mux(&mut base);
        }
        Profile::Socks(v) => {
            base["version"] = "5".into();
            if !v.username.is_empty() && !v.password.is_empty() {
                base["username"] = v.username.clone().into();
                base["password"] = v.password.clone().into();
            }
        }
        Profile::Http(v) => {
            if !v.username.is_empty() && !v.password.is_empty() {
                base["username"] = v.username.clone().into();
                base["password"] = v.password.clone().into();
            }
            apply_tls(&mut base, false);
        }
        Profile::Wireguard(v) => {
            let reserved: Vec<i64> = v.reserved.iter().map(|&b| b as i64).collect();
            let mut peer = json!({
                "address": v.endpoint.address,
                "port": v.endpoint.port,
                "public_key": v.peer_public_key,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            });
            if !v.pre_shared_key.is_empty() {
                peer["pre_shared_key"] = v.pre_shared_key.clone().into();
            }
            if v.persistent_keepalive != 0 {
                peer["persistent_keepalive_interval"] = v.persistent_keepalive.into();
            }
            if !reserved.is_empty() {
                peer["reserved"] = reserved.into();
            }
            let mut wg = json!({
                "type": "wireguard",
                "tag": "proxy",
                "address": split_csv(&v.local_address).unwrap_or_else(|| vec![v.local_address.clone()]),
                "private_key": v.secret_key,
                "mtu": if v.mtu != 0 { v.mtu } else { 1408 },
                "peers": [peer],
            });
            if v.workers != 0 {
                wg["workers"] = v.workers.into();
            }
            return wg;
        }
        Profile::Hysteria2(v) => {
            base["password"] = v.password.clone().into();
            if v.obfs_type == crate::enums::Hysteria2Obfs::Salamander && !v.obfs_password.is_empty()
            {
                base["obfs"] = json!({ "type": "salamander", "password": v.obfs_password });
            }
            if v.up_mbps > 0 {
                base["up_mbps"] = v.up_mbps.into();
            }
            if v.down_mbps > 0 {
                base["down_mbps"] = v.down_mbps.into();
            }
            if !v.ports.trim().is_empty() && v.ports.contains([':', '-', ',']) {
                base.as_object_mut().unwrap().remove("server_port");
                base["server_ports"] = json!(build_server_ports(&v.ports));
                let hop = v.hop_interval.parse::<f64>().ok();
                base["hop_interval"] = match hop {
                    Some(h) if h.is_finite() && h >= 5.0 => format!("{}s", num_str(h)),
                    _ => "30s".to_string(),
                }
                .into();
            }
            apply_tls(&mut base, true);
        }
        Profile::Tuic(v) => {
            base["uuid"] = v.uuid.clone().into();
            base["password"] = v.password.clone().into();
            base["congestion_control"] = wire(&v.congestion_control).into();
            if !v.udp_relay_mode.is_empty() {
                base["udp_relay_mode"] = v.udp_relay_mode.clone().into();
            }
            if v.zero_rtt {
                base["zero_rtt_handshake"] = true.into();
            }
            if v.udp_over_stream {
                base["udp_over_stream"] = true.into();
            }
            if !v.heartbeat.is_empty() {
                base["heartbeat"] = v.heartbeat.clone().into();
            }
            apply_tls(&mut base, true);
        }
        Profile::Anytls(v) => {
            base["password"] = v.password.clone().into();
            if !v.idle_session_check_interval.is_empty() {
                base["idle_session_check_interval"] = v.idle_session_check_interval.clone().into();
            }
            if !v.idle_session_timeout.is_empty() {
                base["idle_session_timeout"] = v.idle_session_timeout.clone().into();
            }
            if v.min_idle_session != 0 {
                base["min_idle_session"] = v.min_idle_session.into();
            }
            apply_tls(&mut base, true);
        }
        Profile::Naive(v) => {
            if !v.username.is_empty() {
                base["username"] = v.username.clone().into();
            }
            base["password"] = v.password.clone().into();
            if v.insecure_concurrency > 0 {
                base["insecure_concurrency"] = v.insecure_concurrency.into();
            }
            if v.naive_quic {
                base["quic"] = true.into();
            }
            base["quic_congestion_control"] = wire(&v.congestion_control).into();
            apply_tls(&mut base, true);
        }
        Profile::Shadowtls(v) => {
            base["version"] = v.version.into();
            if !v.password.is_empty() {
                base["password"] = v.password.clone().into();
            }
            apply_tls(&mut base, true);
        }
        Profile::Custom(_) => {
            // Caller guards against this; return an empty marker instead of panicking.
            return Value::Null;
        }
    }
    base
}

fn wire_protocol(p: &Profile) -> String {
    wire(&p.protocol())
}

// ---------- DNS ----------

fn parse_hosts(v: &str) -> Option<Value> {
    if v.trim().is_empty() {
        return None;
    }
    if let Ok(Value::Object(o)) = serde_json::from_str::<Value>(v.trim()) {
        return Some(Value::Object(o));
    }
    let mut out = Map::new();
    for line in v.split('\n') {
        let mut parts = line.splitn(2, '=');
        let host = parts.next().unwrap_or("").trim();
        let ip = parts.next().unwrap_or("").trim();
        if host.is_empty() || ip.is_empty() {
            continue;
        }
        match out.get_mut(host) {
            Some(Value::Array(a)) => a.push(ip.to_string().into()),
            Some(slot) => {
                let prev = slot.clone();
                *slot = json!([prev, ip]);
            }
            None => {
                out.insert(host.to_string(), ip.to_string().into());
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

fn build_singbox_dns_rule_for_domains(
    domains: &[String],
    server: &str,
    rule_set_tags: &mut Tags,
) -> Option<Value> {
    let mut rule = json!({ "server": server });
    for d in domains {
        parse_singbox_domain(d, &mut rule, rule_set_tags);
    }
    if has_match_fields(
        &rule,
        &[
            "rule_set",
            "domain",
            "domain_suffix",
            "domain_keyword",
            "domain_regex",
        ],
    ) {
        Some(rule)
    } else {
        None
    }
}

/// Split `host`, `host:port`, or `[v6]:port` into the bare host and an optional port.
fn split_dns_host_port(s: &str) -> (String, Option<u16>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal: `[addr]` or `[addr]:port`.
        if let Some((addr, after)) = rest.split_once(']') {
            let port = after.strip_prefix(':').and_then(|p| p.parse().ok());
            return (addr.to_string(), port);
        }
    }
    // A single colon means `host:port`; more than one is a bracketless IPv6 literal.
    if s.matches(':').count() == 1
        && let Some((h, p)) = s.split_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return (h.to_string(), Some(port));
    }
    (s.to_string(), None)
}

/// Translate a DNS address into a sing-box DNS server object, honouring an optional
/// URL scheme so a single text field accepts every transport sing-box supports:
/// plain IPv4/UDP (`1.1.1.1`), DoT (`tls://…`), DoH (`https://1.1.1.1/dns-query`),
/// DoQ (`quic://…`), DoH3 (`h3://…`), `tcp://…`, and `local`/`localhost`. A bare
/// address stays plain UDP, so existing settings keep working. The `+local` xray
/// suffix collapses to the base transport. Conventions mirror v2rayN / xray-core.
fn build_singbox_dns_server(tag: &str, addr: &str) -> Value {
    let addr = addr.trim();
    if addr.eq_ignore_ascii_case("local") || addr.eq_ignore_ascii_case("localhost") {
        return json!({ "type": "local", "tag": tag });
    }

    let (scheme, rest) = match addr.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase().replace("+local", ""), r),
        None => (String::new(), addr),
    };
    let dns_type = if scheme.is_empty() {
        "udp"
    } else {
        scheme.as_str()
    };

    // Only DoH/DoH3 carry a request path; for the rest the whole remainder is host[:port].
    let (hostport, path) = if matches!(dns_type, "https" | "h3") {
        match rest.split_once('/') {
            Some((hp, p)) => (hp, Some(format!("/{p}"))),
            None => (rest, None),
        }
    } else {
        (rest, None)
    };

    let (host, port) = split_dns_host_port(hostport);
    let mut server = json!({ "type": dns_type, "tag": tag, "server": host });
    if let Some(port) = port {
        server["server_port"] = port.into();
    }
    if let Some(path) = path.filter(|p| p != "/") {
        server["path"] = path.into();
    }
    // sing-box refuses a DNS server whose address is a domain unless it is told how
    // to resolve that domain. Bootstrap such servers through `local` (which is an
    // IP in the default setup); the `local` server itself must not point at itself.
    let is_domain = server["server"]
        .as_str()
        .is_some_and(|h| h.parse::<std::net::IpAddr>().is_err());
    if is_domain && tag != "local" {
        server["domain_resolver"] = json!({ "server": "local" });
    }
    server
}

fn build_singbox_dns(
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    extra_rule_set_tags: &mut Tags,
) -> Value {
    let remote = split_list(s.remote_dns.as_deref().unwrap_or(""), &DEFAULT_REMOTE_DNS)[0].clone();
    let domestic = split_list(s.domestic_dns.as_deref().unwrap_or(""), &["223.5.5.5"])[0].clone();
    let hosts = parse_hosts(s.dns_hosts.as_deref().unwrap_or(""));

    let mut remote_server = build_singbox_dns_server("remote", &remote);
    if s.dns_via_proxy {
        remote_server["detour"] = "proxy".into();
    }
    let mut servers = vec![remote_server, build_singbox_dns_server("local", &domestic)];
    let mut rules: Vec<Value> = Vec::new();
    let mut dns_rule_set_tags = Tags::new();

    if let Some(hosts) = hosts {
        servers.push(json!({ "type": "hosts", "tag": "hosts", "predefined": hosts }));
        rules.push(json!({ "ip_accept_any": true, "server": "hosts" }));
    }
    if s.fake_dns {
        servers.push(json!({ "type": "fakeip", "tag": "fakeip", "inet4_range": FAKEIP_INET4_RANGE, "inet6_range": "fc00::/18" }));
        rules.push(json!({ "query_type": ["A", "AAAA"], "server": "fakeip" }));
    }
    if s.routing_mode == RoutingMode::Rules {
        for r in routing_rules {
            if !r.enabled {
                continue;
            }
            let Some(domain) = &r.domain else { continue };
            if domain.is_empty() {
                continue;
            }
            let server = match r.outbound_tag.as_str() {
                "direct" => "local",
                "proxy" => "remote",
                _ => continue,
            };
            if let Some(dr) =
                build_singbox_dns_rule_for_domains(domain, server, &mut dns_rule_set_tags)
            {
                rules.push(dr);
            }
        }
    }
    rules.push(json!({ "ip_is_private": true, "server": "local" }));

    let mut dns = json!({
        "servers": servers,
        "final": "remote",
        "strategy": if s.ipv6_enabled.unwrap_or(false) { "prefer_ipv4" } else { "ipv4_only" },
    });
    if !rules.is_empty() {
        dns.as_object_mut()
            .unwrap()
            .insert("rules".into(), Value::Array(rules));
    }
    tag_extend(extra_rule_set_tags, &dns_rule_set_tags);
    dns
}

// ---------- structured routing ----------

fn build_base_singbox_rule(rule: &RoutingRule, resolve: &dyn Fn(&str) -> String) -> Value {
    let mut out = if rule.outbound_tag == "block" {
        json!({ "action": "reject" })
    } else {
        let tag = if rule.outbound_tag.is_empty() {
            "proxy"
        } else {
            &rule.outbound_tag
        };
        json!({ "outbound": resolve(tag) })
    };
    if let Some(port) = rule.port.as_deref().filter(|p| !p.trim().is_empty()) {
        for item in split_csv(port).unwrap_or_default() {
            if item.contains('-') {
                push_str(&mut out, "port_range", item.replace('-', ":"));
            } else if let Ok(n) = item.parse::<i64>() {
                push_num(&mut out, "port", n);
            }
        }
    }
    if let Some(net) = &rule.network {
        out["network"] = json!(split_csv(&wire(net)).unwrap_or_default());
    }
    if let Some(proto) = &rule.protocol
        && !proto.is_empty()
    {
        out["protocol"] = json!(proto);
    }
    out
}

fn parse_singbox_domain(value: &str, rule: &mut Value, rule_set_tags: &mut Tags) -> bool {
    let domain = value.trim();
    if domain.is_empty()
        || domain.starts_with('#')
        || domain.starts_with("ext:")
        || domain.starts_with("ext-domain:")
    {
        return false;
    }
    if let Some(rest) = domain.strip_prefix("geosite:") {
        let tag = format!("geosite-{}", rest.to_lowercase());
        push_str(rule, "rule_set", tag.clone());
        tag_insert(rule_set_tags, tag);
        return true;
    }
    if let Some(rest) = domain.strip_prefix("regexp:") {
        push_str(rule, "domain_regex", rest.replace("\\,", ","));
        return true;
    }
    if let Some(rest) = domain.strip_prefix("domain:") {
        push_str(rule, "domain_suffix", rest.to_string());
        return true;
    }
    if let Some(rest) = domain.strip_prefix("full:") {
        push_str(rule, "domain", rest.to_string());
        return true;
    }
    if let Some(rest) = domain.strip_prefix("keyword:") {
        push_str(rule, "domain_keyword", rest.to_string());
        return true;
    }
    if let Some(rest) = domain.strip_prefix("dotless:") {
        push_str(rule, "domain_keyword", rest.to_string());
        return true;
    }
    push_str(rule, "domain_keyword", domain.to_string());
    true
}

fn parse_singbox_ip(value: &str, rule: &mut Value, rule_set_tags: &mut Tags) -> bool {
    let ip = value.trim();
    if ip.is_empty() || ip.starts_with("ext:") || ip.starts_with("ext-ip:") {
        return false;
    }
    if ip == "geoip:private" {
        rule["ip_is_private"] = true.into();
        return true;
    }
    if ip == "geoip:!private" {
        rule["ip_is_private"] = false.into();
        return true;
    }
    if let Some(rest) = ip.strip_prefix("geoip:!") {
        let tag = format!("geoip-{}", rest.to_lowercase());
        push_str(rule, "rule_set", tag.clone());
        rule["invert"] = true.into();
        tag_insert(rule_set_tags, tag);
        return true;
    }
    if let Some(rest) = ip.strip_prefix("geoip:") {
        let tag = format!("geoip-{}", rest.to_lowercase());
        push_str(rule, "rule_set", tag.clone());
        tag_insert(rule_set_tags, tag);
        return true;
    }
    push_str(rule, "ip_cidr", ip.to_string());
    true
}

fn build_rule_set_objects(rule_set_tags: &Tags, srs_dir: &str) -> Option<Vec<Value>> {
    if rule_set_tags.is_empty() {
        return None;
    }
    Some(
        rule_set_tags
            .iter()
            .map(|tag| {
                json!({
                    "type": "local", "format": "binary", "tag": tag,
                    "path": if srs_dir.is_empty() { format!("{tag}.srs") } else { format!("{srs_dir}/{tag}.srs") },
                })
            })
            .collect(),
    )
}

struct StructuredRules {
    rules: Vec<Value>,
    ip_rules: Vec<Value>,
    rule_set_tags: Tags,
}

fn build_structured_singbox_rules(
    routing_rules: &[RoutingRule],
    resolve: &dyn Fn(&str) -> String,
) -> StructuredRules {
    let mut rules = Vec::new();
    let mut ip_rules = Vec::new();
    let mut rule_set_tags = Tags::new();

    for item in routing_rules {
        if !item.enabled {
            continue;
        }
        let base = build_base_singbox_rule(item, resolve);
        let mut emitted = false;

        if let Some(domain) = &item.domain
            && !domain.is_empty()
        {
            let mut domain_rule = base.clone();
            for d in domain {
                parse_singbox_domain(d, &mut domain_rule, &mut rule_set_tags);
            }
            if has_match_fields(
                &domain_rule,
                &[
                    "rule_set",
                    "domain",
                    "domain_suffix",
                    "domain_keyword",
                    "domain_regex",
                ],
            ) {
                rules.push(domain_rule);
                emitted = true;
            }
        }
        if let Some(ip) = &item.ip
            && !ip.is_empty()
        {
            let mut ip_rule = base.clone();
            for addr in ip {
                parse_singbox_ip(addr, &mut ip_rule, &mut rule_set_tags);
            }
            if has_match_fields(&ip_rule, &["rule_set", "ip_cidr", "ip_is_private"]) {
                rules.push(ip_rule.clone());
                ip_rules.push(ip_rule);
                emitted = true;
            }
        }
        if !emitted && has_match_fields(&base, &["port", "port_range", "network", "protocol"]) {
            rules.push(base);
        }
    }

    StructuredRules {
        rules,
        ip_rules,
        rule_set_tags,
    }
}

fn build_singbox_resolve_rule(s: &AdvancedSettings) -> Value {
    json!({ "action": "resolve", "strategy": wire(&s.domain_strategy4_singbox) })
}

// ---------- tun inbounds ----------

fn uid_of(key: &str) -> Option<i64> {
    key.split(':').nth(1).and_then(|x| x.parse::<i64>().ok())
}

fn build_singbox_tun_inbounds(s: &AdvancedSettings) -> Vec<Value> {
    let force_uids: Vec<i64> = s
        .app_filter
        .iter()
        .filter(|(_, m)| **m == AppFilterMode::ForceProxy)
        .filter_map(|(k, _)| uid_of(k))
        .collect();
    let bypass_uids: Vec<i64> = s
        .app_filter
        .iter()
        .filter(|(_, m)| **m == AppFilterMode::Bypass)
        .filter_map(|(k, _)| uid_of(k))
        .collect();

    let stack = wire(&s.singbox_stack);
    let v6 = s.ipv6_enabled.unwrap_or(false);
    let main_addr = if v6 {
        json!(["198.18.0.1/15", "fdfe:dcba:9876::1/64"])
    } else {
        json!(["198.18.0.1/15"])
    };
    let mut exclude_uid = vec![0i64];
    exclude_uid.extend(bypass_uids.iter().copied());
    exclude_uid.extend(force_uids.iter().copied());

    let main_tun = json!({
        "type": "tun", "tag": "tun-in",
        "address": main_addr, "mtu": s.tun_mtu, "auto_route": true,
        "stack": stack, "strict_route": s.strict_route,
        "exclude_uid": exclude_uid,
    });
    let mut inbounds = vec![main_tun];
    if !force_uids.is_empty() {
        let force_addr = if v6 {
            json!(["198.19.0.1/16", "fdfe:dcba:9877::1/64"])
        } else {
            json!(["198.19.0.1/16"])
        };
        inbounds.push(json!({
            "type": "tun", "tag": "tun-force",
            "address": force_addr, "mtu": s.tun_mtu, "auto_route": true,
            // Both tuns auto_route, so the force tun MUST own a separate iproute2
            // table + rule range — otherwise it tries to add the default route to
            // tun-in's table (2022) and sing-box FATALs with "add route 0: file
            // exists". The kernel filters packets into each tun by uid, then each
            // tun's default route lives in its own table.
            "iproute2_table_index": SINGBOX_FORCE_TABLE, "iproute2_rule_index": SINGBOX_FORCE_RULE_PRIO,
            "stack": stack, "strict_route": s.strict_route,
            "include_uid": force_uids,
        }));
    }
    inbounds
}

// ---------- route ----------

fn build_singbox_route(
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    extra_rule_set_tags: &Tags,
    resolve: &dyn Fn(&str) -> String,
    srs_dir: &str,
) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_set_tags: Tags = Tags::new();
    let ds = s.domain_strategy;
    let private_rule = json!({ "ip_is_private": true, "outbound": "direct" });
    let mut retry_ip_rules: Vec<Value> = vec![private_rule.clone()];

    if s.routing_mode == RoutingMode::Rules {
        let structured = build_structured_singbox_rules(routing_rules, resolve);
        if ds == DomainStrategy::IpOnDemand {
            rules.push(build_singbox_resolve_rule(s));
        }
        rules.push(private_rule.clone());
        rules.extend(structured.rules.iter().cloned());
        retry_ip_rules = std::iter::once(private_rule.clone())
            .chain(structured.ip_rules.iter().cloned())
            .collect();
        tag_extend(&mut rule_set_tags, &structured.rule_set_tags);
    } else {
        if ds == DomainStrategy::IpOnDemand {
            rules.push(build_singbox_resolve_rule(s));
        }
        rules.push(private_rule);
    }

    if ds == DomainStrategy::IpIfNonMatch {
        rules.push(build_singbox_resolve_rule(s));
        rules.extend(retry_ip_rules.iter().cloned());
    }

    // Always-on bypass-geo rule for the `force-in` inbound (app's own fetches); the
    // per-app force path adds the tun-force rule the same way when enabled. Both sit
    // ahead of the geo/user rules.
    rules.insert(0, json!({ "inbound": ["force-in"], "outbound": "proxy" }));
    let has_force = s
        .app_filter
        .values()
        .any(|m| *m == AppFilterMode::ForceProxy);
    if has_force {
        rules.insert(0, json!({ "inbound": ["tun-force"], "outbound": "proxy" }));
    }
    if s.domain_sniffing {
        rules.insert(0, json!({ "protocol": ["dns"], "action": "hijack-dns" }));
        rules.insert(0, json!({ "action": "sniff" }));
    }

    tag_extend(&mut rule_set_tags, extra_rule_set_tags);

    let mut route = json!({
        "rules": rules,
        "final": "proxy",
        "auto_detect_interface": true,
        "default_domain_resolver": { "server": "local" },
    });
    if let Some(rs) = build_rule_set_objects(&rule_set_tags, srs_dir)
        && !rs.is_empty()
    {
        route["rule_set"] = json!(rs);
    }
    route
}

// ---------- full config ----------

const SPECIAL_OUTBOUND_TAGS: [&str; 3] = ["proxy", "direct", "block"];

struct ProfileTargets {
    outbounds: Vec<Value>,
    endpoints: Vec<Value>,
    resolved: std::collections::HashMap<String, String>,
}

fn build_singbox_profile_targets(
    active: &Profile,
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
) -> ProfileTargets {
    let mut resolved = std::collections::HashMap::new();
    let mut outbounds = Vec::new();
    let mut endpoints = Vec::new();
    if s.routing_mode == RoutingMode::Rules {
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
                Some(profile) if !matches!(profile, Profile::Custom(_)) => {
                    let mut target = build_singbox_outbound(profile, s);
                    if let Some(o) = target.as_object_mut() {
                        o.insert("tag".into(), id.clone().into());
                    }
                    if matches!(profile, Profile::Wireguard(_)) {
                        endpoints.push(target);
                    } else {
                        outbounds.push(target);
                    }
                    resolved.insert(id.clone(), id);
                }
                _ => {
                    resolved.insert(id, "proxy".to_string());
                }
            }
        }
    }
    ProfileTargets {
        outbounds,
        endpoints,
        resolved,
    }
}

/// Build-time inputs the neutral builder can't infer.
#[derive(Default, Clone, Copy)]
pub struct SingboxBuildOpts<'a> {
    pub no_tun: bool,
    pub srs_dir: &'a str,
}

pub fn build_singbox_config(
    p: &Profile,
    s: &AdvancedSettings,
    routing_rules: &[RoutingRule],
    profiles: &[Profile],
    opts: SingboxBuildOpts,
) -> Result<Value, String> {
    if matches!(p, Profile::Custom(_)) {
        return Err("custom profiles run on Xray, not sing-box".to_string());
    }
    let socks_port = s.local_socks_port.unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
    let proxy = build_singbox_outbound(p, s);
    let is_endpoint = matches!(p, Profile::Wireguard(_));
    let targets = build_singbox_profile_targets(p, s, routing_rules, profiles);
    let mut shared_rule_set_tags = Tags::new();
    let dns = build_singbox_dns(s, routing_rules, &mut shared_rule_set_tags);

    let resolve = |tag: &str| -> String {
        if SPECIAL_OUTBOUND_TAGS.contains(&tag) {
            tag.to_string()
        } else {
            targets
                .resolved
                .get(tag)
                .cloned()
                .unwrap_or_else(|| "proxy".into())
        }
    };

    let listen = if s.allow_non_localhost {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    // Optional auth on the user-facing mixed inbound (Settings →
    // socksUsername/socksPassword, both required). sing-box takes a `users` list.
    let socks_auth = s
        .socks_username
        .as_deref()
        .filter(|u| !u.is_empty())
        .zip(s.socks_password.as_deref().filter(|p| !p.is_empty()));
    let mut socks_in = json!({
        "type": "mixed", "tag": "socks-in", "listen": listen, "listen_port": socks_port,
    });
    if let Some((u, p)) = socks_auth {
        socks_in["users"] = json!([{ "username": u, "password": p }]);
    }
    // Always-on bypass-geo inbound (see route's `force-in` rule); localhost-only and
    // noauth regardless of `allow_non_localhost` — internal use for the app's fetches.
    // `http_port` is only passed so the force port matches `proxy_status` (which can't
    // know the active engine); sing-box itself has no separate http inbound.
    let http_port = s.local_http_port.unwrap_or(DEFAULT_LOCAL_HTTP_PORT);
    let force_in = json!({
        "type": "mixed", "tag": "force-in",
        "listen": "127.0.0.1", "listen_port": force_socks_port(socks_port, http_port),
    });
    let mut inbounds = vec![socks_in, force_in];
    if !opts.no_tun {
        inbounds.extend(build_singbox_tun_inbounds(s));
    }

    let direct = json!({ "type": "direct", "tag": "direct" });
    let mut outbounds: Vec<Value> = Vec::new();
    if !is_endpoint {
        outbounds.push(proxy.clone());
    }
    outbounds.extend(targets.outbounds.iter().cloned());
    outbounds.push(direct);

    let route = build_singbox_route(
        s,
        routing_rules,
        &shared_rule_set_tags,
        &resolve,
        opts.srs_dir,
    );

    let log_level = s
        .log_level
        .map(|l| wire(&l))
        .unwrap_or_else(|| "warning".into());
    let mut cfg = json!({
        "log": { "level": log_level, "timestamp": true },
        "dns": dns,
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": route,
    });

    let mut endpoints: Vec<Value> = Vec::new();
    if is_endpoint {
        endpoints.push(proxy);
    }
    endpoints.extend(targets.endpoints);
    if !endpoints.is_empty() {
        cfg.as_object_mut()
            .unwrap()
            .insert("endpoints".into(), Value::Array(endpoints));
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_in_inbound_is_always_present_and_localhost_only() {
        let p = crate::share::parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex", None).unwrap();
        let cfg = build_singbox_config(
            &p,
            &AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&p),
            SingboxBuildOpts::default(),
        )
        .unwrap();
        let force = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == "force-in")
            .expect("force-in inbound present");
        // Internal bypass-geo port: localhost-only mixed inbound.
        assert_eq!(force["type"], "mixed");
        assert_eq!(force["listen"], "127.0.0.1");
        // Its route rule sends force-in straight to proxy, ahead of the first
        // direct rule (the always-present private-IP bypass / any geo rule).
        let rules = cfg["route"]["rules"].as_array().unwrap();
        let force_idx = rules
            .iter()
            .position(|r| r["inbound"][0] == "force-in" && r["outbound"] == "proxy")
            .expect("force-in → proxy route rule present");
        let direct_idx = rules
            .iter()
            .position(|r| r["outbound"] == "direct")
            .unwrap();
        assert!(
            force_idx < direct_idx,
            "force-in rule must precede direct rules"
        );
    }

    #[test]
    fn ech_raw_base64_is_wrapped_in_a_pem_block() {
        let cfg = ech_config_pem("AEX+DQBB...base64...");
        assert_eq!(cfg.first().unwrap(), "-----BEGIN ECH CONFIGS-----");
        assert_eq!(cfg.last().unwrap(), "-----END ECH CONFIGS-----");
        // Joined the way sing-box does (\n) it must round-trip through pem.Decode.
        let joined = cfg.join("\n");
        let body = joined
            .strip_prefix("-----BEGIN ECH CONFIGS-----\n")
            .and_then(|s| s.strip_suffix("\n-----END ECH CONFIGS-----"))
            .unwrap();
        assert_eq!(body.replace('\n', ""), "AEX+DQBB...base64...");
    }

    #[test]
    fn ech_existing_pem_is_split_into_lines_unchanged() {
        let pem = "-----BEGIN ECH CONFIGS-----\nAAAA\nBBBB\n-----END ECH CONFIGS-----";
        let cfg = ech_config_pem(pem);
        assert_eq!(
            cfg,
            vec![
                "-----BEGIN ECH CONFIGS-----",
                "AAAA",
                "BBBB",
                "-----END ECH CONFIGS-----",
            ]
        );
    }

    #[test]
    fn socks_auth_adds_users_to_the_mixed_inbound() {
        let p = crate::share::parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex", None).unwrap();
        let s = AdvancedSettings {
            socks_username: Some("alice".into()),
            socks_password: Some("s3cret".into()),
            ..Default::default()
        };
        let cfg = build_singbox_config(
            &p,
            &s,
            &[],
            std::slice::from_ref(&p),
            SingboxBuildOpts::default(),
        )
        .unwrap();
        let socks = cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["tag"] == "socks-in")
            .unwrap();
        assert_eq!(socks["users"][0]["username"], "alice");
        assert_eq!(socks["users"][0]["password"], "s3cret");

        // No creds → no users list (open inbound).
        let cfg = build_singbox_config(
            &p,
            &AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&p),
            SingboxBuildOpts::default(),
        )
        .unwrap();
        let socks = &cfg["inbounds"].as_array().unwrap()[0];
        assert!(socks.get("users").is_none());
    }

    #[test]
    fn naive_outbound_omits_utls() {
        let build = |uri: &str| {
            let p = crate::share::parse_share_link(uri, None).unwrap();
            build_singbox_config(
                &p,
                &AdvancedSettings::default(),
                &[],
                std::slice::from_ref(&p),
                SingboxBuildOpts::default(),
            )
            .unwrap()
        };
        let proxy = |cfg: &Value| {
            cfg["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == "proxy")
                .cloned()
                .unwrap()
        };

        // sing-box rejects uTLS on the naive outbound (`uTLS is not supported on
        // naive outbound`), so the builder must omit it even though the profile
        // carries a default fingerprint.
        let naive = proxy(&build("naive+https://user:pw@n.ex:443?sni=s.ex&fp=chrome"));
        assert_eq!(naive["type"], "naive");
        assert!(
            naive["tls"]["utls"].is_null(),
            "naive tls must not carry utls"
        );

        // A protocol that does accept uTLS still gets it (guard against an over-broad skip).
        let anytls = proxy(&build("anytls://pw@a.ex:443?sni=s.ex&fp=chrome"));
        assert_eq!(anytls["tls"]["utls"]["enabled"], true);
    }

    #[test]
    fn dns_address_scheme_is_detected() {
        // Bare address stays plain UDP (back-compat with stored settings).
        assert_eq!(
            build_singbox_dns_server("remote", "1.1.1.1"),
            json!({ "type": "udp", "tag": "remote", "server": "1.1.1.1" })
        );
        // DoH: scheme + host + path, default port omitted.
        assert_eq!(
            build_singbox_dns_server("remote", "https://1.1.1.1/dns-query"),
            json!({ "type": "https", "tag": "remote", "server": "1.1.1.1", "path": "/dns-query" })
        );
        // DoT with explicit port and a hostname: the domain address gets a bootstrap
        // resolver so sing-box can resolve it (it refuses a bare domain server).
        assert_eq!(
            build_singbox_dns_server("remote", "tls://dns.google:853"),
            json!({
                "type": "tls", "tag": "remote", "server": "dns.google",
                "server_port": 853, "domain_resolver": { "server": "local" }
            })
        );
        // DoQ / DoH3 schemes pass through; `+local` collapses to the base transport.
        assert_eq!(
            build_singbox_dns_server("remote", "quic://9.9.9.9")["type"],
            "quic"
        );
        assert_eq!(
            build_singbox_dns_server("remote", "h3://1.1.1.1/dns-query")["type"],
            "h3"
        );
        assert_eq!(
            build_singbox_dns_server("local", "https+local://77.88.8.8/dns-query")["type"],
            "https"
        );
        // local / localhost map to the system resolver with no server address.
        assert_eq!(
            build_singbox_dns_server("local", "local"),
            json!({ "type": "local", "tag": "local" })
        );
        // IPv6 literal with brackets keeps the address and parses the port.
        assert_eq!(
            build_singbox_dns_server("local", "[2606:4700:4700::1111]:53"),
            json!({ "type": "udp", "tag": "local", "server": "2606:4700:4700::1111", "server_port": 53 })
        );
    }

    #[test]
    fn dns_via_proxy_detours_remote_server_with_scheme() {
        let s = AdvancedSettings {
            remote_dns: Some("https://1.1.1.1/dns-query".into()),
            dns_via_proxy: true,
            ..Default::default()
        };
        let dns = build_singbox_dns(&s, &[], &mut Tags::new());
        let remote = dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["tag"] == "remote")
            .unwrap();
        assert_eq!(remote["type"], "https");
        assert_eq!(remote["detour"], "proxy");
    }

    #[test]
    fn ws_host_header_defaults_to_server_domain_without_port() {
        let proxy = |uri: &str| {
            let p = crate::share::parse_share_link(uri, None).unwrap();
            let cfg = build_singbox_config(
                &p,
                &AdvancedSettings::default(),
                &[],
                std::slice::from_ref(&p),
                SingboxBuildOpts::default(),
            )
            .unwrap();
            cfg["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["tag"] == "proxy")
                .cloned()
                .unwrap()
        };

        // No ws host in the profile → the Host header must be the bare server domain,
        // never "<domain>:443" (which host-routing gateways 400 on; the bug this guards).
        let o = proxy(
            "vless://11111111-1111-1111-1111-111111111111@gw.example.com:443?type=ws&path=%2Fvmess&security=tls&sni=gw.example.com",
        );
        assert_eq!(o["transport"]["type"], "ws");
        assert_eq!(o["transport"]["headers"]["Host"], "gw.example.com");

        // An explicit ws host still wins.
        let o = proxy(
            "vless://11111111-1111-1111-1111-111111111111@gw.example.com:443?type=ws&path=%2Fvmess&host=front.example.com&security=tls&sni=gw.example.com",
        );
        assert_eq!(o["transport"]["headers"]["Host"], "front.example.com");
    }
}
