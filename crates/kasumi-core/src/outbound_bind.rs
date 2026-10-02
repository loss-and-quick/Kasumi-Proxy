//! Binding the core's own egress outbounds to a physical uplink interface.
//!
//! Invariant across every platform: a core's own egress outbounds (`proxy` +
//! `direct`) must leave via the physical uplink and never re-enter the tun, or they
//! loop (tun → tun-engine → core SOCKS → outbound → tun → …). How that's achieved
//! depends on the tun mode, not the engine:
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

use serde_json::{Value, json};

use crate::enums::CoreEngine;

/// The core's own egress outbounds, by tag. Service outbounds (`block`, `dns`) carry
/// no traffic to the network and are left untouched.
const EGRESS_TAGS: [&str; 2] = ["proxy", "direct"];

/// Bind every egress (`proxy`/`direct`) outbound's upstream socket to `iface` so the
/// core's traffic to the server *and* its direct (geo-`direct`) traffic egress the
/// physical uplink and escape an active tun — no per-connection OS routing involved.
/// xray exposes this as `streamSettings.sockopt.interface` (→ `SO_BINDTODEVICE` /
/// `IP_UNICAST_IF`); sing-box as a top-level `bind_interface`. sing-box's wireguard
/// outbound lives under `endpoints`, so both arrays are scanned.
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
        for ob in arr {
            let tag = ob.get("tag").and_then(Value::as_str);
            if !tag.is_some_and(|t| EGRESS_TAGS.contains(&t)) {
                continue;
            }
            let Some(map) = ob.as_object_mut() else {
                continue;
            };
            match engine {
                CoreEngine::Xray => {
                    {
                        let stream = map.entry("streamSettings").or_insert_with(|| json!({}));
                        if let Some(sock) = stream
                            .as_object_mut()
                            .map(|s| s.entry("sockopt").or_insert_with(|| json!({})))
                            .and_then(Value::as_object_mut)
                        {
                            sock.insert("interface".into(), iface.into());
                        }
                    }
                    if let Some(src) = source {
                        map.insert("sendThrough".into(), src.into());
                    }
                }
                CoreEngine::SingBox => {
                    map.insert("bind_interface".into(), iface.into());
                    if let Some(src) = source {
                        map.insert("inet4_bind_address".into(), src.into());
                    }
                }
            }
        }
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

    #[test]
    fn binds_egress_outbounds_only() {
        // xray: sets streamSettings.sockopt.interface on both the proxy and direct
        // outbounds, creating the streamSettings/sockopt objects when absent, and
        // leaves service outbounds (block/dns) untouched.
        let mut x = json!({ "outbounds": [
            { "tag": "proxy", "protocol": "socks" },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" },
        ] });
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1", Some("192.168.1.5"));
        assert_eq!(
            x["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert_eq!(x["outbounds"][0]["sendThrough"], "192.168.1.5");
        assert_eq!(
            x["outbounds"][1]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert_eq!(x["outbounds"][1]["sendThrough"], "192.168.1.5");
        assert!(x["outbounds"][2].get("streamSettings").is_none());
        assert!(x["outbounds"][2].get("sendThrough").is_none());

        // sing-box: top-level bind_interface on the proxy + direct outbounds and the
        // wireguard proxy endpoint, leaving service outbounds untouched.
        let mut s = json!({
            "outbounds": [
                { "tag": "proxy", "type": "vless" },
                { "tag": "direct", "type": "direct" },
                { "tag": "dns", "type": "dns" },
            ],
            "endpoints": [{ "tag": "proxy", "type": "wireguard" }],
        });
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "wlan0", Some("192.168.1.2"));
        assert_eq!(s["outbounds"][0]["bind_interface"], "wlan0");
        assert_eq!(s["outbounds"][0]["inet4_bind_address"], "192.168.1.2");
        assert_eq!(s["outbounds"][1]["bind_interface"], "wlan0");
        assert_eq!(s["outbounds"][1]["inet4_bind_address"], "192.168.1.2");
        assert!(s["outbounds"][2].get("bind_interface").is_none());
        assert_eq!(s["endpoints"][0]["bind_interface"], "wlan0");
        assert_eq!(s["endpoints"][0]["inet4_bind_address"], "192.168.1.2");
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
