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
//!
//! One exception holds in every mode: an outbound that dials a *local relay* (a
//! provider's companion app listening on loopback, e.g. a WireGuard profile whose
//! peer is `127.0.0.1:9000`) must keep loopback reachability. A socket pinned to a
//! physical device cannot send to `127.0.0.1` at all, so such an object is left
//! unbound here and exempted from the core's own interface detection by
//! [`preserve_loopback_singbox_egress`].

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

/// The uplink's own source addresses, per family, for [`bind_uplink_outbounds`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UplinkSource {
    pub v4: Option<String>,
    pub v6: Option<String>,
}

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
/// Pinning the source to the uplink's own address makes the escape deterministic.
/// sing-box takes one per family (`inet4_bind_address` / `inet6_bind_address`) and
/// uses the one matching each dial. xray has a single `sendThrough` for every dial,
/// so it gets the IPv4 source only: an IPv6 one would break every IPv4 dial, and
/// xray's IPv6 traffic keeps the device-only bind. A family without a source keeps
/// the device-only behaviour (single-homed hosts, or where it can't be resolved).
/// <https://sing-box.sagernet.org/configuration/shared/dial/>
/// <https://xtls.github.io/en/config/outbound.html#outboundobject>
pub fn bind_uplink_outbounds(
    engine: CoreEngine,
    cfg: &mut Value,
    iface: &str,
    source: &UplinkSource,
) {
    escape_outbounds(engine, cfg, &Escape::Bind { iface, source });
}

/// Mark the same outbounds [`bind_uplink_outbounds`] binds with `mark` instead, for
/// a host whose policy routing sends that mark past the tun to the main table. The
/// main table then picks the uplink for every dial, so a change of uplink needs
/// nothing rebuilt. xray takes it per outbound as `streamSettings.sockopt.mark`
/// (`SO_MARK`). sing-box takes it once as `route.default_mark`, which also covers
/// its DNS servers' own dials.
/// <https://xtls.github.io/en/config/transport.html#sockoptobject>
/// <https://sing-box.sagernet.org/configuration/route/#default_mark>
pub fn mark_egress_outbounds(engine: CoreEngine, cfg: &mut Value, mark: u32) {
    match engine {
        CoreEngine::Xray => escape_outbounds(engine, cfg, &Escape::Mark(mark)),
        CoreEngine::SingBox => {
            let Some(root) = cfg.as_object_mut() else {
                return;
            };
            if let Some(route) = root
                .entry("route")
                .or_insert_with(|| json!({}))
                .as_object_mut()
            {
                route.insert("default_mark".into(), mark.into());
            }
        }
    }
}

/// How an outbound's socket leaves the tun.
enum Escape<'a> {
    /// Bound to the uplink's device and source address.
    Bind {
        iface: &'a str,
        source: &'a UplinkSource,
    },
    /// Carries a mark that policy routing sends past the tun.
    Mark(u32),
}

fn escape_outbounds(engine: CoreEngine, cfg: &mut Value, escape: &Escape) {
    for key in ["outbounds", "endpoints"] {
        let Some(arr) = cfg.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        for ob in arr.iter_mut().filter_map(Value::as_object_mut) {
            match (engine, escape) {
                (CoreEngine::Xray, _) => escape_xray_outbound(ob, escape),
                (CoreEngine::SingBox, Escape::Bind { iface, source }) => {
                    bind_singbox_outbound(ob, iface, source)
                }
                // sing-box marks every dial at once (see `mark_egress_outbounds`).
                (CoreEngine::SingBox, Escape::Mark(_)) => {}
            }
        }
    }
}

fn escape_xray_outbound(ob: &mut Map<String, Value>, escape: &Escape) {
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
                escape_xray_sockopt(leg, escape);
            }
        }
    }
    if relayed || !escape_xray_sockopt(stream, escape) {
        return;
    }
    if let Escape::Bind { source, .. } = escape
        && let Some(v4) = &source.v4
    {
        ob.insert("sendThrough".into(), v4.as_str().into());
    }
}

/// Set `sockopt.interface` or `sockopt.mark` on one xray stream config unless its
/// socket comes from another outbound (`dialerProxy`). Returns whether it was set.
fn escape_xray_sockopt(stream: &mut Map<String, Value>, escape: &Escape) -> bool {
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
    match escape {
        Escape::Bind { iface, .. } => sock.insert("interface".into(), (*iface).into()),
        Escape::Mark(mark) => sock.insert("mark".into(), (*mark).into()),
    };
    true
}

fn bind_singbox_outbound(ob: &mut Map<String, Value>, iface: &str, source: &UplinkSource) {
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
    let servers = singbox_servers(ob);
    if dials_only_loopback(&servers) {
        return;
    }
    ob.insert("bind_interface".into(), iface.into());
    if let Some(v4) = &source.v4 {
        ob.insert("inet4_bind_address".into(), v4.as_str().into());
    }
    if let Some(v6) = &source.v6 {
        ob.insert("inet6_bind_address".into(), v6.as_str().into());
    }
}

/// Keep a local-relay object reachable under `route.auto_detect_interface`.
///
/// In the self-managed tun mode sing-box binds every dial to the default uplink
/// device, and a device-bound socket cannot reach `127.0.0.1`. A WireGuard profile
/// whose peer is an on-device relay (a provider hands out `wireguard://…@127.0.0.1:9000`
/// so its companion app carries the packets) therefore never completes a handshake,
/// and everything routed to it times out while the rest of the config looks healthy.
///
/// A bind address on the object makes sing-box skip the auto-detected device bind for
/// that object alone (its `disableDefaultBind`), so the object keeps loopback
/// reachability while every other dial stays on the uplink. Only loopback-*only*
/// objects are exempted: a peer list that also names a remote server still needs the
/// uplink, and a chained object dials through another outbound's socket.
pub fn preserve_loopback_singbox_egress(cfg: &mut Value) {
    for key in ["outbounds", "endpoints"] {
        let Some(arr) = cfg.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        for ob in arr.iter_mut().filter_map(Value::as_object_mut) {
            preserve_singbox_loopback(ob);
        }
    }
}

fn preserve_singbox_loopback(ob: &mut Map<String, Value>) {
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
    let servers = singbox_servers(ob);
    if !dials_only_loopback(&servers) {
        return;
    }
    let mut v4 = false;
    let mut v6 = false;
    for family in servers.iter().filter_map(|s| loopback_family(s)) {
        v4 |= family != LoopbackFamily::V6;
        v6 |= family != LoopbackFamily::V4;
    }
    if v4 {
        ob.insert("inet4_bind_address".into(), "127.0.0.1".into());
    }
    if v6 {
        ob.insert("inet6_bind_address".into(), "::1".into());
    }
}

/// Server addresses a sing-box outbound or endpoint dials itself: `server`, and the
/// wireguard peers' `address` (endpoints keep their peers under `peers`).
fn singbox_servers(ob: &Map<String, Value>) -> Vec<&str> {
    ob.get("server")
        .and_then(Value::as_str)
        .into_iter()
        .chain(peer_field(ob, "address"))
        .collect()
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
    loopback_family(addr).is_some()
}

/// Which loopback family an address names, for choosing the bind addresses that keep
/// an object off the uplink device. `localhost` may resolve either way.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LoopbackFamily {
    V4,
    V6,
    Both,
}

fn loopback_family(addr: &str) -> Option<LoopbackFamily> {
    let host = host_of(addr);
    if host.eq_ignore_ascii_case("localhost") {
        return Some(LoopbackFamily::Both);
    }
    match host.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) if v4.is_loopback() => Some(LoopbackFamily::V4),
        std::net::IpAddr::V6(v6) if v6.is_loopback() => Some(LoopbackFamily::V6),
        _ => None,
    }
}

/// The host part of `host`, `host:port`, `[v6]:port` or a bare v6 literal.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else if addr.matches(':').count() == 1 {
        addr.split(':').next().unwrap_or(addr)
    } else {
        addr
    }
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
            force_tun: false,
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &v4("192.168.1.5"));
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
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "eno1", &v4("192.168.1.2"));
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

    #[test]
    fn marks_the_outbounds_a_bind_would_bind() {
        let mut x = json!({ "outbounds": [
            { "tag": "proxy", "protocol": "vless",
              "settings": { "vnext": [{ "address": "p.example", "port": 443 }] },
              "streamSettings": { "network": "xhttp", "xhttpSettings": { "downloadSettings": {
                  "address": "d.example", "port": 443 } } } },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "dns-out", "protocol": "dns" },
            { "tag": "block", "protocol": "blackhole" },
            { "tag": "local", "protocol": "socks",
              "settings": { "servers": [{ "address": "127.0.0.1", "port": 1080 }] } },
            { "tag": "relayed", "protocol": "vless", "proxySettings": { "tag": "proxy" },
              "settings": { "vnext": [{ "address": "r.example", "port": 443 }] } },
            { "tag": "dialed", "protocol": "vless",
              "settings": { "vnext": [{ "address": "d.example", "port": 443 }] },
              "streamSettings": { "sockopt": { "dialerProxy": "proxy" } } },
        ] });
        mark_egress_outbounds(CoreEngine::Xray, &mut x, 0x4b53);
        for tag in ["proxy", "direct", "dns-out"] {
            let ob = by_tag(&x, "outbounds", tag);
            assert_eq!(
                ob["streamSettings"]["sockopt"],
                json!({ "mark": 0x4b53 }),
                "{tag}"
            );
            // Nothing names the uplink: the main table picks it per dial.
            assert!(ob.get("sendThrough").is_none(), "{tag}");
        }
        assert_eq!(
            by_tag(&x, "outbounds", "proxy")["streamSettings"]["xhttpSettings"]["downloadSettings"]
                ["sockopt"],
            json!({ "mark": 0x4b53 })
        );
        for tag in ["block", "local", "relayed"] {
            let ob = by_tag(&x, "outbounds", tag);
            assert!(ob.get("streamSettings").is_none(), "{tag} touched: {ob}");
        }
        assert_eq!(
            by_tag(&x, "outbounds", "dialed")["streamSettings"]["sockopt"],
            json!({ "dialerProxy": "proxy" })
        );

        let mut s = json!({
            "outbounds": [{ "tag": "proxy", "type": "vless", "server": "p.example" }],
            "route": { "final": "proxy" },
        });
        mark_egress_outbounds(CoreEngine::SingBox, &mut s, 0x4b53);
        assert_eq!(
            s["route"],
            json!({ "final": "proxy", "default_mark": 0x4b53 })
        );
        assert!(
            by_tag(&s, "outbounds", "proxy")
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &UplinkSource::default());

        let selector: Vec<String> = x["routing"]["balancers"][0]["selector"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member.as_str().unwrap().to_string())
            .collect();
        // The balancer picks among all three namespaced members.
        assert!(selector.iter().all(|tag| tag.starts_with("ks-provider:")));
        assert_eq!(selector.len(), 3);
        let namespace = selector
            .first()
            .and_then(|tag| tag.rsplit_once(":o:").map(|(prefix, _)| prefix.to_string()))
            .unwrap_or_default();
        let bound_extra = [
            format!("{namespace}:o:00000003:"),
            format!("{namespace}:o:00000006:"),
            "direct".to_string(),
        ];
        for tag in selector.iter().chain(&bound_extra) {
            assert!(xray_bound(&x, tag), "{tag} unbound");
        }
        for ordinal in ["00000004", "00000005"] {
            let tag = format!("{namespace}:o:{ordinal}:");
            assert!(
                by_tag(&x, "outbounds", &tag)["streamSettings"]["sockopt"]
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &UplinkSource::default());
        for tag in ["proxy", "other", "wg"] {
            assert!(xray_bound(&x, tag), "xray {tag} unbound");
        }
        assert!(!xray_bound(&x, "local"));

        let mut sb = singbox(&all[0], &s, &rules, &all);
        bind_uplink_outbounds(
            CoreEngine::SingBox,
            &mut sb,
            "eno1",
            &UplinkSource::default(),
        );
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &v4("192.168.1.5"));
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
        bind_uplink_outbounds(
            CoreEngine::SingBox,
            &mut sb,
            "eno1",
            &UplinkSource::default(),
        );
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &UplinkSource::default());
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &v4("192.168.1.5"));
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
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &UplinkSource::default());
        assert_eq!(
            x["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert!(x["outbounds"][0].get("sendThrough").is_none());

        let mut s = json!({ "outbounds": [{ "tag": "proxy", "type": "vless" }] });
        bind_uplink_outbounds(
            CoreEngine::SingBox,
            &mut s,
            "eno1",
            &UplinkSource::default(),
        );
        assert_eq!(s["outbounds"][0]["bind_interface"], "eno1");
        assert!(s["outbounds"][0].get("inet4_bind_address").is_none());
    }

    fn v4(addr: &str) -> UplinkSource {
        UplinkSource {
            v4: Some(addr.into()),
            v6: None,
        }
    }

    fn dual() -> UplinkSource {
        UplinkSource {
            v4: Some("192.168.1.5".into()),
            v6: Some("2001:db8::5".into()),
        }
    }

    /// The full config the backend would launch for a vless profile on `engine`.
    fn built(engine: CoreEngine) -> Value {
        let mut p = profile(
            "vless://11111111-1111-1111-1111-111111111111@e.x:443?type=tcp&security=tls&sni=s",
            "vless",
            None,
        );
        p.meta_mut().core_type = Some(engine);
        let cfg = crate::core_config::build_core_config(
            &p,
            &crate::state::AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&p),
            "",
            crate::data_path_plan::TEST_HOST,
        )
        .unwrap();
        assert_eq!(cfg.engine(), engine);
        cfg.config
    }

    #[test]
    fn singbox_pins_each_family_on_the_built_config() {
        let mut s = built(CoreEngine::SingBox);
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "eno1", &dual());
        for tag in ["proxy", "direct"] {
            let ob = by_tag(&s, "outbounds", tag);
            assert_eq!(ob["bind_interface"], "eno1");
            assert_eq!(ob["inet4_bind_address"], "192.168.1.5");
            assert_eq!(ob["inet6_bind_address"], "2001:db8::5");
        }
    }

    // xray has one `sendThrough` for every dial: an IPv6 source would break its
    // IPv4 dials, so only the IPv4 source is pinned and IPv6 stays device-only.
    #[test]
    fn xray_pins_only_the_ipv4_source_on_the_built_config() {
        let mut x = built(CoreEngine::Xray);
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", &dual());
        for tag in ["proxy", "direct"] {
            assert!(xray_bound(&x, tag));
            assert_eq!(by_tag(&x, "outbounds", tag)["sendThrough"], "192.168.1.5");
        }
        assert!(!x.to_string().contains("2001:db8::5"));

        let mut v6_only = built(CoreEngine::Xray);
        let source = UplinkSource {
            v4: None,
            v6: Some("2001:db8::5".into()),
        };
        bind_uplink_outbounds(CoreEngine::Xray, &mut v6_only, "eno1", &source);
        assert!(xray_bound(&v6_only, "proxy"));
        assert!(!v6_only.to_string().contains("sendThrough"));
    }

    #[test]
    fn loopback_relay_objects_keep_their_reachability() {
        let mut s = json!({
            "outbounds": [
                { "tag": "proxy", "type": "vless", "server": "p.example" },
                { "tag": "direct", "type": "direct" },
                { "tag": "block", "type": "block" },
                { "tag": "pick", "type": "selector", "outbounds": ["proxy"] },
                { "tag": "local", "type": "socks", "server": "127.0.0.1" },
                { "tag": "local6", "type": "socks", "server": "[::1]" },
                { "tag": "name", "type": "http", "server": "localhost" },
                { "tag": "mixed", "type": "wireguard",
                  "peers": [{ "address": "127.0.0.1" }, { "address": "w.example" }] },
                { "tag": "hop", "type": "socks", "server": "127.0.0.1",
                  "detour": "proxy" },
            ],
            "endpoints": [
                { "tag": "relay", "type": "wireguard", "peers": [{ "address": "127.0.0.1" }] },
                { "tag": "remote", "type": "wireguard", "peers": [{ "address": "w.example" }] },
            ],
        });
        preserve_loopback_singbox_egress(&mut s);
        // Loopback-only: exempted from the auto-detected device bind, per family.
        assert_eq!(
            by_tag(&s, "outbounds", "local")["inet4_bind_address"],
            "127.0.0.1"
        );
        assert_eq!(
            by_tag(&s, "outbounds", "local6")["inet6_bind_address"],
            "::1"
        );
        for key in ["inet4_bind_address", "inet6_bind_address"] {
            let expected = if key == "inet4_bind_address" {
                "127.0.0.1"
            } else {
                "::1"
            };
            // `localhost` may resolve either way, so it gets both families.
            assert_eq!(by_tag(&s, "outbounds", "name")[key], expected);
        }
        let relay = by_tag(&s, "endpoints", "relay");
        assert_eq!(relay["inet4_bind_address"], "127.0.0.1");
        assert!(relay.get("inet6_bind_address").is_none());
        // Everything else is left for `auto_detect_interface` to bind.
        for (key, tag) in [
            ("outbounds", "proxy"),
            ("outbounds", "direct"),
            ("outbounds", "block"),
            ("outbounds", "pick"),
            ("outbounds", "mixed"),
            ("outbounds", "hop"),
            ("endpoints", "remote"),
        ] {
            let ob = by_tag(&s, key, tag);
            assert!(ob.get("bind_interface").is_none(), "{tag} bound");
            assert!(ob.get("inet4_bind_address").is_none(), "{tag} bound");
            assert!(ob.get("inet6_bind_address").is_none(), "{tag} bound");
        }

        // Idempotent, and the uplink bind still skips the exempted objects.
        let once = s.clone();
        preserve_loopback_singbox_egress(&mut s);
        assert_eq!(s, once);
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "eno1", &v4("192.168.1.2"));
        assert!(singbox_bound(&s, "outbounds", "proxy"));
        assert!(singbox_bound(&s, "endpoints", "remote"));
        let relay = by_tag(&s, "endpoints", "relay");
        assert!(relay.get("bind_interface").is_none());
        assert_eq!(relay["inet4_bind_address"], "127.0.0.1");
    }

    #[test]
    fn a_loopback_wireguard_profile_is_exempted_on_the_built_config() {
        let mut p = profile(
            "wireguard://cHJpdg==@127.0.0.1:9000?publickey=cHVi&address=10.13.13.2/32",
            "relay",
            None,
        );
        p.meta_mut().core_type = Some(CoreEngine::SingBox);
        let cfg = crate::core_config::build_core_config(
            &p,
            &crate::state::AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&p),
            "",
            crate::data_path_plan::TEST_HOST,
        )
        .unwrap();
        assert_eq!(cfg.engine(), CoreEngine::SingBox);
        // The end-to-end tun escape stays on for every other dial.
        assert_eq!(cfg.config["route"]["auto_detect_interface"], true);
        let relay = &cfg.config["endpoints"][0];
        assert_eq!(relay["type"], "wireguard");
        assert_eq!(relay["inet4_bind_address"], "127.0.0.1");
        assert!(relay.get("bind_interface").is_none());
    }
}
