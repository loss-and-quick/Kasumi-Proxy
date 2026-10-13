//! Binding the core's own egress outbounds to a physical uplink interface.
//!
//! Invariant across every platform: every outbound that opens a socket to the
//! network (each server it proxies through, and `direct`) must leave via the
//! physical uplink and never re-enter the tun, or it loops (tun → tun-engine →
//! core SOCKS → outbound → tun → …). How that's achieved depends on the tun mode,
//! not the engine:
//!   - **bridged** (xray/sing-box behind an external tun engine like tun2socks/hev,
//!     with a split-default pulling traffic into the tun): bind the egress outbounds
//!     to the uplink at the socket layer — this helper. Engine- and
//!     tun-engine-agnostic; the escape is on the core's socket, so swapping the tun
//!     engine changes nothing here.
//!   - **self-managed** (sing-box `auto_route`): the core owns the tun and escapes
//!     via the egress fwmark (`route.default_mark` + the desktop's escape ip-rule;
//!     see `SINGBOX_ESCAPE_MARK`) and its own `auto_detect_interface` — do *not*
//!     call this there, an explicit `bind_interface` would defeat the
//!     auto-detection and pin a stale interface.
//!   - **Android**: a per-uid policy-routing model excludes root from marking, so the
//!     core (run as root) escapes without an explicit bind. It doesn't call this
//!     today, but the helper is shared so it can if a future need arises.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::enums::CoreEngine;

/// Outbound kinds that open no socket to the network: they drop traffic, hand it
/// back to routing, or pick another outbound. An xray `dns` outbound is not one of
/// them: it forwards xray's own DNS queries, and non-IP queries under
/// `nonIPQuery: "skip"`, to the target or its `address`/`port` override through
/// its own dialer.
/// https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/dns/dns.go#L116-L131
/// https://github.com/XTLS/Xray-core/blob/v26.3.27/proxy/dns/dns.go#L193-L231
const XRAY_LOCAL_PROTOCOLS: [&str; 2] = ["blackhole", "loopback"];
const SINGBOX_LOCAL_TYPES: [&str; 3] = ["block", "selector", "urltest"];

/// Bind every outbound that dials the network itself to `iface`, so the core's
/// traffic to its servers *and* its direct (geo-`direct`) traffic egress the
/// physical uplink and escape an active tun — no per-connection OS routing involved.
/// That covers the active server, per-rule profile targets, the first hop of a
/// chain, a provider config's balancer members and relays, and freedom/`direct`.
/// xray exposes this as `streamSettings.sockopt.interface` (→ `SO_BINDTODEVICE` /
/// `IP_UNICAST_IF`); sing-box as a top-level `bind_interface`. sing-box's wireguard
/// outbound lives under `endpoints`, so both arrays are scanned.
///
/// Left unbound: outbounds that open no socket, ones whose servers are all on
/// loopback (they never reach the tun, and a device bind would cut them off), and
/// ones that dial through another outbound (xray `dialerProxy` / `proxySettings`,
/// sing-box `detour`) — their socket is that outbound's, which is bound itself.
///
/// `source` pins the egress *source address* alongside the device. On a multi-homed
/// host (several NICs on one subnet) `SO_BINDTODEVICE` alone lets the kernel pick a
/// different NIC's source address, so the reply lands on the other interface and is
/// dropped — the dial then times out and the bind silently fails to escape the tun.
/// Pinning the source to the uplink's own address (xray `sendThrough`, sing-box
/// `inet4_bind_address`) makes the escape deterministic. `None` keeps the device-only
/// behaviour (single-homed hosts, or where the source can't be resolved).
pub fn bind_uplink_outbounds(
    engine: CoreEngine,
    cfg: &mut Value,
    iface: &str,
    source: Option<&str>,
) {
    for key in ["outbounds", "endpoints"] {
        let Some(arr) = cfg.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        for ob in arr.iter_mut().filter_map(Value::as_object_mut) {
            match engine {
                CoreEngine::Xray => bind_xray_outbound(ob, iface, source),
                CoreEngine::SingBox => bind_singbox_outbound(ob, iface, source),
            }
        }
    }
}

fn bind_xray_outbound(ob: &mut Map<String, Value>, iface: &str, source: Option<&str>) {
    let protocol = ob.get("protocol").and_then(Value::as_str).unwrap_or("");
    if protocol.is_empty() || XRAY_LOCAL_PROTOCOLS.contains(&protocol) {
        return;
    }
    if dials_only_loopback(&xray_servers(ob)) {
        return;
    }
    let relayed = ob
        .get("proxySettings")
        .and_then(|p| p.get("tag"))
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty());
    if !relayed {
        ob.entry("streamSettings").or_insert_with(|| json!({}));
    }
    let Some(stream) = ob.get_mut("streamSettings").and_then(Value::as_object_mut) else {
        return;
    };
    // An XHTTP download leg dials its own server with its own sockopt: xray
    // inherits the outer one only under `penetrate`.
    // https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/splithttp/dialer.go#L403-L409
    if let Some(xhttp) = stream.get_mut("xhttpSettings") {
        for in_extra in [false, true] {
            let parent = if in_extra {
                xhttp.get_mut("extra")
            } else {
                Some(&mut *xhttp)
            };
            if let Some(leg) = parent
                .and_then(|p| p.get_mut("downloadSettings"))
                .and_then(Value::as_object_mut)
                && !leg
                    .get("address")
                    .and_then(Value::as_str)
                    .is_some_and(is_loopback_host)
            {
                bind_xray_sockopt(leg, iface);
            }
        }
    }
    if relayed || !bind_xray_sockopt(stream, iface) {
        return;
    }
    if let Some(src) = source {
        ob.insert("sendThrough".into(), src.into());
    }
}

/// Set `sockopt.interface` on one xray stream config unless its socket comes from
/// another outbound (`dialerProxy`). Returns whether it was bound.
fn bind_xray_sockopt(stream: &mut Map<String, Value>, iface: &str) -> bool {
    let Some(sock) = stream
        .entry("sockopt")
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return false;
    };
    if sock
        .get("dialerProxy")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty())
    {
        return false;
    }
    sock.insert("interface".into(), iface.into());
    true
}

fn bind_singbox_outbound(ob: &mut Map<String, Value>, iface: &str, source: Option<&str>) {
    let kind = ob.get("type").and_then(Value::as_str).unwrap_or("");
    if kind.is_empty() || SINGBOX_LOCAL_TYPES.contains(&kind) {
        return;
    }
    if ob
        .get("detour")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty())
    {
        return;
    }
    let servers = ob
        .get("server")
        .and_then(Value::as_str)
        .into_iter()
        .chain(peer_field(ob, "address"))
        .collect::<Vec<_>>();
    if dials_only_loopback(&servers) {
        return;
    }
    ob.insert("bind_interface".into(), iface.into());
    if let Some(src) = source {
        ob.insert("inet4_bind_address".into(), src.into());
    }
}

/// Server addresses an xray outbound dials: `vnext` / `servers` entries, the
/// hysteria `address` and wireguard peer endpoints.
fn xray_servers(ob: &Map<String, Value>) -> Vec<&str> {
    let Some(settings) = ob.get("settings").and_then(Value::as_object) else {
        return Vec::new();
    };
    ["vnext", "servers"]
        .into_iter()
        .filter_map(|k| settings.get(k).and_then(Value::as_array))
        .flatten()
        .filter_map(|s| s.get("address").and_then(Value::as_str))
        .chain(settings.get("address").and_then(Value::as_str))
        .chain(peer_field(settings, "endpoint"))
        .collect()
}

fn peer_field<'a>(m: &'a Map<String, Value>, key: &'a str) -> impl Iterator<Item = &'a str> {
    m.get("peers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(move |p| p.get(key).and_then(Value::as_str))
}

fn dials_only_loopback(servers: &[&str]) -> bool {
    !servers.is_empty() && servers.iter().all(|s| is_loopback_host(s))
}

/// `host`, `host:port`, `[v6]:port` or a bare v6 literal on loopback.
fn is_loopback_host(addr: &str) -> bool {
    let host = if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if addr.matches(':').count() == 1 {
        addr.split(':').next().unwrap_or(addr)
    } else {
        addr
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Let xray reach its proxy servers without the system resolver, so DNS can be sent
/// through the tun. An xray outbound dials a domain server through Go's resolver,
/// whose sockets are not bound to the uplink: with DNS captured by the tun that
/// query would come back into xray, which needs the very server it is resolving to
/// forward it. Each domain server gets the addresses resolved before bring-up
/// (`resolved`) as an xray `dns.hosts` entry, and its outbound resolves through
/// xray's own DNS (`sockopt.domainStrategy`), which answers from `hosts` first. The
/// address itself stays a domain, so SNI and Host headers are unchanged. Only IPv4
/// addresses are pinned when the server has any — they route on every host. A
/// user's own `hosts` entry for the same name wins.
pub fn pin_xray_server_hosts(cfg: &mut Value, resolved: &BTreeMap<String, Vec<String>>) {
    let mut pins: BTreeMap<String, (Vec<String>, &str)> = BTreeMap::new();
    let Some(outbounds) = cfg.get_mut("outbounds").and_then(Value::as_array_mut) else {
        return;
    };
    for ob in outbounds {
        let mut strategy = None;
        for key in ["vnext", "servers"] {
            let hosts = ob
                .get("settings")
                .and_then(|s| s.get(key))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|s| s.get("address").and_then(Value::as_str));
            for host in hosts {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                let Some(ips) = resolved.get(host).filter(|ips| !ips.is_empty()) else {
                    continue;
                };
                let v4: Vec<String> = ips.iter().filter(|ip| !ip.contains(':')).cloned().collect();
                let pin = if v4.is_empty() {
                    (ips.clone(), "UseIPv6")
                } else {
                    (v4, "UseIPv4")
                };
                // One outbound has one server in practice; a mixed-family set falls
                // back to the generic strategy.
                strategy = match strategy {
                    None => Some(pin.1),
                    Some(s) if s == pin.1 => Some(s),
                    Some(_) => Some("UseIP"),
                };
                pins.insert(host.to_string(), pin);
            }
        }
        let Some(strategy) = strategy else {
            continue;
        };
        let Some(map) = ob.as_object_mut() else {
            continue;
        };
        let stream = map.entry("streamSettings").or_insert_with(|| json!({}));
        if let Some(sock) = stream
            .as_object_mut()
            .map(|s| s.entry("sockopt").or_insert_with(|| json!({})))
            .and_then(Value::as_object_mut)
        {
            sock.entry("domainStrategy")
                .or_insert_with(|| strategy.into());
        }
    }
    if pins.is_empty() {
        return;
    }
    let Some(root) = cfg.as_object_mut() else {
        return;
    };
    let dns = root.entry("dns").or_insert_with(|| json!({}));
    let Some(hosts) = dns
        .as_object_mut()
        .map(|d| d.entry("hosts").or_insert_with(|| json!({})))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    for (host, (ips, _)) in pins {
        hosts.entry(host).or_insert_with(|| json!(ips));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use crate::singbox_config::{SingboxBuildOpts, build_singbox_config};
    use crate::state::{AdvancedSettings, RoutingMode, RoutingRule};
    use crate::xray_config::build_xray_config;

    #[test]
    fn pins_domain_servers_into_xray_hosts() {
        let mut x = json!({
            "dns": { "servers": ["1.1.1.1"], "hosts": { "mine.example": "10.0.0.1" } },
            "outbounds": [
                { "tag": "proxy", "protocol": "vless",
                  "settings": { "vnext": [{ "address": "srv.example", "port": 443 }] },
                  "streamSettings": { "security": "tls" } },
                { "tag": "hop", "protocol": "trojan",
                  "settings": { "servers": [{ "address": "v6.example" }] } },
                { "tag": "lit", "protocol": "vless",
                  "settings": { "vnext": [{ "address": "203.0.113.9" }] } },
                { "tag": "user", "protocol": "vless",
                  "settings": { "vnext": [{ "address": "mine.example" }] } },
                { "tag": "direct", "protocol": "freedom" },
            ],
        });
        let resolved = BTreeMap::from([
            (
                "srv.example".to_string(),
                vec!["2001:db8::1".to_string(), "198.51.100.7".to_string()],
            ),
            ("v6.example".to_string(), vec!["2001:db8::2".to_string()]),
            ("mine.example".to_string(), vec!["198.51.100.8".to_string()]),
        ]);
        pin_xray_server_hosts(&mut x, &resolved);

        let ob = &x["outbounds"];
        assert_eq!(x["dns"]["hosts"]["srv.example"], json!(["198.51.100.7"]));
        assert_eq!(
            ob[0]["streamSettings"]["sockopt"]["domainStrategy"],
            "UseIPv4"
        );
        // Existing stream settings are kept.
        assert_eq!(ob[0]["streamSettings"]["security"], "tls");
        // The address stays a domain (SNI / Host unchanged).
        assert_eq!(ob[0]["settings"]["vnext"][0]["address"], "srv.example");

        assert_eq!(x["dns"]["hosts"]["v6.example"], json!(["2001:db8::2"]));
        assert_eq!(
            ob[1]["streamSettings"]["sockopt"]["domainStrategy"],
            "UseIPv6"
        );

        // A literal address needs nothing; a user's hosts entry wins.
        assert!(ob[2].get("streamSettings").is_none());
        assert_eq!(x["dns"]["hosts"]["mine.example"], "10.0.0.1");
        assert!(ob[4].get("streamSettings").is_none());
        assert_eq!(x["dns"]["servers"], json!(["1.1.1.1"]));
    }

    fn by_tag<'a>(cfg: &'a Value, key: &str, tag: &str) -> &'a Value {
        cfg[key]
            .as_array()
            .and_then(|a| a.iter().find(|o| o["tag"] == tag))
            .unwrap_or_else(|| panic!("no {key} tagged {tag}: {cfg}"))
    }

    fn xray_bound(cfg: &Value, tag: &str) -> bool {
        by_tag(cfg, "outbounds", tag)["streamSettings"]["sockopt"]["interface"] == "eno1"
    }

    fn singbox_bound(cfg: &Value, key: &str, tag: &str) -> bool {
        by_tag(cfg, key, tag)["bind_interface"] == "eno1"
    }

    fn profile(uri: &str, id: &str, via: Option<&str>) -> Profile {
        let mut p = crate::share::parse_share_link(uri, None).unwrap();
        p.meta_mut().id = id.into();
        p.meta_mut().via = via.map(str::to_string);
        p
    }

    fn rule_to(outbound: &str, domain: &str) -> RoutingRule {
        serde_json::from_value(json!({
            "id": domain, "remarks": domain, "enabled": true,
            "outboundTag": outbound, "domain": [domain],
        }))
        .unwrap()
    }

    fn singbox(p: &Profile, s: &AdvancedSettings, rules: &[RoutingRule], all: &[Profile]) -> Value {
        let opts = SingboxBuildOpts {
            no_tun: true,
            srs_dir: "",
        };
        build_singbox_config(p, s, rules, all, opts).unwrap()
    }

    #[test]
    fn binds_every_outbound_that_dials_the_network() {
        let mut x = json!({ "outbounds": [
            { "tag": "proxy", "protocol": "socks",
              "settings": { "servers": [{ "address": "s.example", "port": 1080 }] } },
            { "tag": "hy", "protocol": "hysteria", "settings": { "address": "h.example" },
              "streamSettings": { "security": "tls", "sockopt": {} } },
            { "tag": "wg", "protocol": "wireguard",
              "settings": { "address": ["10.0.0.2/32"], "peers": [{ "endpoint": "[2001:db8::1]:51820" }] } },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "fragment", "protocol": "freedom", "settings": { "fragment": {} } },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "dns-out", "protocol": "dns", "settings": { "nonIPQuery": "skip" } },
            { "tag": "dns-fwd", "protocol": "dns",
              "settings": { "address": "1.1.1.1", "port": 53 } },
            { "tag": "dns-local", "protocol": "dns",
              "settings": { "address": "127.0.0.53", "port": 53 } },
            { "tag": "back", "protocol": "loopback", "settings": { "inboundTag": "socks-in" } },
            { "tag": "local", "protocol": "socks",
              "settings": { "servers": [{ "address": "127.0.0.1", "port": 1080 }] } },
            { "tag": "local-wg", "protocol": "wireguard",
              "settings": { "peers": [{ "endpoint": "[::1]:51820" }] } },
            { "tag": "relayed", "protocol": "vless", "proxySettings": { "tag": "proxy" },
              "settings": { "vnext": [{ "address": "r.example", "port": 443 }] } },
            { "tag": "dialed", "protocol": "vless",
              "settings": { "vnext": [{ "address": "d.example", "port": 443 }] },
              "streamSettings": { "sockopt": { "dialerProxy": "proxy" } } },
        ] });
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", Some("192.168.1.5"));
        for tag in [
            "proxy", "hy", "wg", "direct", "fragment", "dns-out", "dns-fwd",
        ] {
            assert!(xray_bound(&x, tag), "{tag} unbound");
            assert_eq!(by_tag(&x, "outbounds", tag)["sendThrough"], "192.168.1.5");
        }
        // Drop, loopback and relayed outbounds keep their shape.
        for tag in ["block", "back", "dns-local", "local", "local-wg", "relayed"] {
            let ob = by_tag(&x, "outbounds", tag);
            assert!(ob.get("streamSettings").is_none(), "{tag} touched: {ob}");
            assert!(ob.get("sendThrough").is_none(), "{tag} touched: {ob}");
        }
        assert_eq!(
            by_tag(&x, "outbounds", "dialed")["streamSettings"]["sockopt"],
            json!({ "dialerProxy": "proxy" })
        );
        assert!(
            by_tag(&x, "outbounds", "dialed")
                .get("sendThrough")
                .is_none()
        );

        let mut s = json!({
            "outbounds": [
                { "tag": "proxy", "type": "vless", "server": "p.example" },
                { "tag": "other", "type": "trojan", "server": "o.example" },
                { "tag": "direct", "type": "direct" },
                { "tag": "block", "type": "block" },
                { "tag": "pick", "type": "selector", "outbounds": ["proxy", "other"] },
                { "tag": "auto", "type": "urltest", "outbounds": ["proxy", "other"] },
                { "tag": "local", "type": "socks", "server": "localhost" },
                { "tag": "hop", "type": "vless", "server": "h.example", "detour": "other" },
            ],
            "endpoints": [
                { "tag": "wg", "type": "wireguard", "peers": [{ "address": "w.example" }] },
                { "tag": "wg-hop", "type": "wireguard", "detour": "other",
                  "peers": [{ "address": "w2.example" }] },
            ],
        });
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "eno1", Some("192.168.1.2"));
        for tag in ["proxy", "other", "direct"] {
            assert!(singbox_bound(&s, "outbounds", tag), "{tag} unbound");
            assert_eq!(
                by_tag(&s, "outbounds", tag)["inet4_bind_address"],
                "192.168.1.2"
            );
        }
        assert!(singbox_bound(&s, "endpoints", "wg"));
        for tag in ["block", "pick", "auto", "local", "hop"] {
            let ob = by_tag(&s, "outbounds", tag);
            assert!(ob.get("bind_interface").is_none(), "{tag} bound");
            assert!(ob.get("inet4_bind_address").is_none(), "{tag} bound");
        }
        assert!(
            by_tag(&s, "endpoints", "wg-hop")
                .get("bind_interface")
                .is_none()
        );
    }

    /// A provider Xray config: a three-server balancer, a relay that one exit
    /// dials through (`dialerProxy`), another exit riding it (`proxySettings`),
    /// and a freedom outbound of its own.
    #[test]
    fn provider_balancer_members_and_relays_are_bound() {
        let server = |tag: &str, host: &str| {
            json!({
                "tag": tag, "protocol": "vless",
                "settings": { "vnext": [{ "address": host, "port": 443,
                    "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
                "streamSettings": { "network": "tcp", "security": "tls" },
            })
        };
        let mut via_dialer = server("exit-a", "a.example");
        via_dialer["streamSettings"]["sockopt"] = json!({ "dialerProxy": "relay" });
        let mut via_proxy = server("exit-b", "b.example");
        via_proxy["proxySettings"] = json!({ "tag": "relay" });
        let raw = json!({
            "outbounds": [
                server("de-1", "de1.example"),
                server("de-2", "de2.example"),
                server("de-3", "de3.example"),
                server("relay", "relay.example"),
                via_dialer,
                via_proxy,
                { "tag": "fragment", "protocol": "freedom",
                  "settings": { "fragment": { "packets": "tlshello", "length": "100-200", "interval": "10-20" } } },
                { "tag": "block", "protocol": "blackhole" },
            ],
            "routing": {
                "balancers": [{ "tag": "de", "selector": ["de-"], "strategy": { "type": "roundRobin" } }],
                "rules": [
                    { "type": "field", "domain": ["de.example"], "balancerTag": "de" },
                    { "type": "field", "domain": ["a.example"], "outboundTag": "exit-a" },
                    { "type": "field", "domain": ["b.example"], "outboundTag": "exit-b" },
                    { "type": "field", "domain": ["f.example"], "outboundTag": "fragment" },
                ],
            },
        });
        let p: Profile = serde_json::from_value(json!({
            "protocol": "custom",
            "meta": { "id": "c", "remarks": "C", "groupId": "g-main" },
            "raw": raw.to_string(),
            "origin": "provider",
        }))
        .unwrap();
        let mut x = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", None);

        // `de-1` became `proxy`; the balancer still picks among all three.
        assert_eq!(
            x["routing"]["balancers"][0]["selector"],
            json!(["proxy", "de-2", "de-3"])
        );
        for tag in ["proxy", "de-2", "de-3", "relay", "fragment", "direct"] {
            assert!(xray_bound(&x, tag), "{tag} unbound");
        }
        for tag in ["exit-a", "exit-b"] {
            assert!(
                by_tag(&x, "outbounds", tag)["streamSettings"]["sockopt"]
                    .get("interface")
                    .is_none(),
                "{tag} bound"
            );
        }
        assert!(
            by_tag(&x, "outbounds", "block")
                .get("streamSettings")
                .is_none()
        );
    }

    #[test]
    fn per_rule_profile_targets_are_bound() {
        let all = [
            profile(
                "vless://u@main.ex:443?security=tls&sni=main.ex",
                "main",
                None,
            ),
            profile(
                "trojan://pw@other.ex:443?security=tls&sni=other.ex",
                "other",
                None,
            ),
            profile(
                "wireguard://cHJpdg==@wg.ex:51820?publickey=cHVi",
                "wg",
                None,
            ),
            profile("socks://127.0.0.1:1080", "local", None),
        ];
        let s = AdvancedSettings {
            routing_mode: RoutingMode::Rules,
            ..AdvancedSettings::default()
        };
        let rules = [
            rule_to("other", "o.example"),
            rule_to("wg", "w.example"),
            rule_to("local", "l.example"),
        ];

        let mut x = build_xray_config(&all[0], &s, &rules, &all).unwrap();
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", None);
        for tag in ["proxy", "other", "wg"] {
            assert!(xray_bound(&x, tag), "xray {tag} unbound");
        }
        assert!(!xray_bound(&x, "local"));

        let mut sb = singbox(&all[0], &s, &rules, &all);
        bind_uplink_outbounds(CoreEngine::SingBox, &mut sb, "eno1", None);
        for tag in ["proxy", "other"] {
            assert!(
                singbox_bound(&sb, "outbounds", tag),
                "sing-box {tag} unbound"
            );
        }
        assert!(singbox_bound(&sb, "endpoints", "wg"));
        assert!(!singbox_bound(&sb, "outbounds", "local"));
    }

    /// Only the hop that dials its server itself is bound: the others' sockets
    /// come from the next hop, and a bind on them would be dead config at best.
    #[test]
    fn chain_binds_only_the_first_hop() {
        let all = [
            profile(
                "vless://u@exit.ex:443?type=ws&security=tls&sni=exit.ex",
                "exit",
                Some("mid"),
            ),
            profile(
                "trojan://pw@mid.ex:443?security=tls&sni=mid.ex",
                "mid",
                Some("entry"),
            ),
            profile("ss://YWVzLTEyOC1nY206cHc@entry.ex:8388", "entry", None),
        ];
        let s = AdvancedSettings::default();

        let mut x = build_xray_config(&all[0], &s, &[], &all).unwrap();
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", Some("192.168.1.5"));
        assert!(xray_bound(&x, "entry"));
        assert_eq!(
            by_tag(&x, "outbounds", "entry")["sendThrough"],
            "192.168.1.5"
        );
        for tag in ["proxy", "mid"] {
            assert!(!xray_bound(&x, tag), "xray {tag} bound");
            assert!(by_tag(&x, "outbounds", tag).get("sendThrough").is_none());
        }

        // sing-box, with a wireguard hop that lives under `endpoints`.
        let mut sb_all = all.clone();
        sb_all[1] = profile(
            "wireguard://cHJpdg==@mid.ex:51820?publickey=cHVi",
            "mid",
            Some("entry"),
        );
        let mut sb = singbox(&sb_all[0], &s, &[], &sb_all);
        bind_uplink_outbounds(CoreEngine::SingBox, &mut sb, "eno1", None);
        assert!(singbox_bound(&sb, "outbounds", "entry"));
        assert!(!singbox_bound(&sb, "outbounds", "proxy"));
        assert!(!singbox_bound(&sb, "endpoints", "mid"));
    }

    #[test]
    fn xhttp_download_leg_is_bound_on_its_own_sockopt() {
        let mut x = json!({ "outbounds": [
            { "tag": "proxy", "protocol": "vless",
              "settings": { "vnext": [{ "address": "up.example", "port": 443 }] },
              "streamSettings": { "network": "xhttp", "xhttpSettings": {
                  "downloadSettings": { "address": "down.example", "port": 443, "network": "xhttp" },
                  "extra": { "downloadSettings": { "address": "down2.example", "port": 443,
                      "sockopt": { "tcpNoDelay": true } } },
              } } },
            { "tag": "chained", "protocol": "vless",
              "settings": { "vnext": [{ "address": "up.example", "port": 443 }] },
              "streamSettings": { "sockopt": { "dialerProxy": "proxy" }, "xhttpSettings": {
                  "downloadSettings": { "address": "down.example", "port": 443 },
                  "extra": { "downloadSettings": { "address": "down.example", "port": 443,
                      "sockopt": { "dialerProxy": "proxy" } } },
              } } },
        ] });
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", None);
        let xhttp =
            |tag: &str| by_tag(&x, "outbounds", tag)["streamSettings"]["xhttpSettings"].clone();
        let proxy = xhttp("proxy");
        assert_eq!(proxy["downloadSettings"]["sockopt"]["interface"], "eno1");
        assert_eq!(
            proxy["extra"]["downloadSettings"]["sockopt"],
            json!({ "tcpNoDelay": true, "interface": "eno1" })
        );
        // The download leg doesn't inherit the upload leg's dialerProxy.
        let chained = xhttp("chained");
        assert_eq!(chained["downloadSettings"]["sockopt"]["interface"], "eno1");
        assert!(
            chained["extra"]["downloadSettings"]["sockopt"]
                .get("interface")
                .is_none()
        );
        assert!(!xray_bound(&x, "chained"));
    }

    /// The `dns` outbound the desktop adds for DNS sent through the tun dials
    /// whatever xray forwards rather than answers, so it is bound like `direct`.
    #[test]
    fn hijacked_dns_outbound_is_bound() {
        let p = profile(
            "vless://u@main.ex:443?security=tls&sni=main.ex",
            "main",
            None,
        );
        let mut x = build_xray_config(&p, &AdvancedSettings::default(), &[], &[]).unwrap();
        crate::xray_config::hijack_inbound_dns(&mut x);
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", Some("192.168.1.5"));
        let dns = x["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["protocol"] == "dns")
            .expect("hijack adds a dns outbound");
        assert_eq!(dns["streamSettings"]["sockopt"]["interface"], "eno1");
        assert_eq!(dns["sendThrough"], "192.168.1.5");
    }

    #[test]
    fn source_is_optional() {
        // No source → device-only binding (single-homed hosts keep the old shape).
        let mut x = json!({ "outbounds": [{ "tag": "proxy", "protocol": "vless" }] });
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", None);
        assert_eq!(
            x["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert!(x["outbounds"][0].get("sendThrough").is_none());

        let mut s = json!({ "outbounds": [{ "tag": "proxy", "type": "vless" }] });
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "eno1", None);
        assert_eq!(s["outbounds"][0]["bind_interface"], "eno1");
        assert!(s["outbounds"][0].get("inet4_bind_address").is_none());
    }
}
