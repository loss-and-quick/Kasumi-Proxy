//! DNS/address helpers shared by the desktop data-path (`singbox` + `routing`), so
//! the proxy-server bypass resolution lives in one place — including the parsing
//! of proxy-server hosts out of a built xray config, reused by both the Linux and
//! Windows routing back-ends.

use std::collections::HashSet;

use serde_json::{json, Value};

use kasumi_core::enums::CoreEngine;

/// Bind every `proxy`-tagged outbound's upstream socket to `iface` (`SO_BINDTODEVICE`)
/// so a helper-spawned test core's traffic to the server egresses the physical uplink
/// and escapes an active tun — no per-test OS routing involved. xray exposes this as
/// `streamSettings.sockopt.interface`; sing-box as a top-level `bind_interface` (its
/// wireguard outbound lives under `endpoints`, so both arrays are scanned).
pub fn bind_proxy_outbound(engine: CoreEngine, cfg: &mut Value, iface: &str) {
    for key in ["outbounds", "endpoints"] {
        let Some(arr) = cfg.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        for ob in arr {
            if ob.get("tag").and_then(Value::as_str) != Some("proxy") {
                continue;
            }
            let Some(map) = ob.as_object_mut() else {
                continue;
            };
            match engine {
                CoreEngine::Xray => {
                    let stream = map.entry("streamSettings").or_insert_with(|| json!({}));
                    if let Some(sock) = stream
                        .as_object_mut()
                        .map(|s| s.entry("sockopt").or_insert_with(|| json!({})))
                        .and_then(Value::as_object_mut)
                    {
                        sock.insert("interface".into(), iface.into());
                    }
                }
                CoreEngine::SingBox => {
                    map.insert("bind_interface".into(), iface.into());
                }
            }
        }
    }
}

/// Resolve a host (domain or literal IP) to its IPs, or `[]` on failure.
pub async fn resolve_ips(host: &str) -> Vec<String> {
    match tokio::net::lookup_host((host, 0u16)).await {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Add a non-loopback string host to the set.
fn add_host(hosts: &mut HashSet<String>, h: Option<&Value>) {
    if let Some(s) = h.and_then(Value::as_str) {
        if !s.is_empty() && s != "127.0.0.1" {
            hosts.insert(s.to_string());
        }
    }
}

/// `host:port` (or `[v6]:port`) → bare host.
fn strip_endpoint_host(ep: &str) -> String {
    let no_port = match ep.rfind(':') {
        Some(i) => &ep[..i],
        None => ep,
    };
    no_port
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string()
}

/// Proxy-server hosts from a built xray config (all protocol shapes).
fn collect_xray_servers(cfg: &Value) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for ob in cfg
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(s) = ob.get("settings") else {
            continue;
        };
        for v in s
            .get("vnext")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            add_host(&mut hosts, v.get("address"));
        }
        for sv in s
            .get("servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            add_host(&mut hosts, sv.get("address"));
        }
        // wireguard peers: "host:port"
        for p in s
            .get("peers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(ep) = p.get("endpoint").and_then(Value::as_str) {
                let host = strip_endpoint_host(ep);
                if !host.is_empty() && host != "127.0.0.1" {
                    hosts.insert(host);
                }
            }
        }
    }
    hosts
}

/// Resolve every proxy-server host in the xray config to bypass CIDRs, plus the
/// `extra_hosts` the OS routing back-end supplies (its DNS resolvers, so name
/// resolution keeps working while the tun is up).
pub async fn resolve_bypass_cidrs(xray_cfg_text: &str, extra_hosts: &[String]) -> Vec<String> {
    let cfg: Value = serde_json::from_str(xray_cfg_text).unwrap_or(Value::Null);
    let mut out = HashSet::new();
    for host in collect_xray_servers(&cfg) {
        for ip in resolve_ips(&host).await {
            out.insert(cidr(&ip));
        }
    }
    for host in extra_hosts {
        out.insert(cidr(host));
    }
    out.into_iter().collect()
}

/// Host-route CIDR for a single address (`/32` v4, `/128` v6).
pub fn cidr(ip: &str) -> String {
    if ip.contains(':') {
        format!("{ip}/128")
    } else {
        format!("{ip}/32")
    }
}

/// Whether a string is a bare IPv4/IPv6 literal (not a domain).
pub fn is_literal_ip(addr: &str) -> bool {
    addr.contains(':')
        || (!addr.is_empty() && addr.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_picks_family() {
        assert_eq!(cidr("1.2.3.4"), "1.2.3.4/32");
        assert_eq!(cidr("2001:db8::1"), "2001:db8::1/128");
    }

    #[test]
    fn binds_only_the_proxy_outbound() {
        // xray: sets streamSettings.sockopt.interface on the proxy outbound only,
        // creating the streamSettings/sockopt objects when absent.
        let mut x = json!({ "outbounds": [
            { "tag": "proxy", "protocol": "socks" },
            { "tag": "direct", "protocol": "freedom" },
        ] });
        bind_proxy_outbound(CoreEngine::Xray, &mut x, "eno1");
        assert_eq!(
            x["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert!(x["outbounds"][1].get("streamSettings").is_none());

        // sing-box: top-level bind_interface on the proxy outbound and the
        // wireguard proxy endpoint, leaving siblings untouched.
        let mut s = json!({
            "outbounds": [
                { "tag": "proxy", "type": "vless" },
                { "tag": "direct", "type": "direct" },
            ],
            "endpoints": [{ "tag": "proxy", "type": "wireguard" }],
        });
        bind_proxy_outbound(CoreEngine::SingBox, &mut s, "wlan0");
        assert_eq!(s["outbounds"][0]["bind_interface"], "wlan0");
        assert!(s["outbounds"][1].get("bind_interface").is_none());
        assert_eq!(s["endpoints"][0]["bind_interface"], "wlan0");
    }

    #[test]
    fn literal_ip_detection() {
        assert!(is_literal_ip("8.8.8.8"));
        assert!(is_literal_ip("::1"));
        assert!(!is_literal_ip("dns.google"));
        assert!(!is_literal_ip(""));
    }

    #[tokio::test]
    async fn resolve_localhost_yields_loopback() {
        let ips = resolve_ips("localhost").await;
        assert!(ips.iter().any(|ip| ip == "127.0.0.1" || ip == "::1"));
    }

    #[test]
    fn strips_endpoint_host() {
        assert_eq!(strip_endpoint_host("1.2.3.4:51820"), "1.2.3.4");
        assert_eq!(strip_endpoint_host("[2001:db8::1]:51820"), "2001:db8::1");
        assert_eq!(
            strip_endpoint_host("vpn.example.com:443"),
            "vpn.example.com"
        );
    }

    #[test]
    fn collects_servers_across_protocol_shapes() {
        let cfg = serde_json::json!({
            "outbounds": [
                { "settings": { "vnext": [{ "address": "a.example" }] } },
                { "settings": { "servers": [{ "address": "b.example" }, { "address": "127.0.0.1" }] } },
                { "settings": { "peers": [{ "endpoint": "c.example:51820" }] } },
            ]
        });
        let hosts = collect_xray_servers(&cfg);
        assert!(hosts.contains("a.example"));
        assert!(hosts.contains("b.example"));
        assert!(hosts.contains("c.example"));
        // Loopback is never bypass-routed.
        assert!(!hosts.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn resolve_bypass_cidrs_for_literal_servers_and_extra_hosts() {
        // Literal IPs resolve to themselves (no DNS), so the aggregation is
        // deterministic: every server host and every extra host becomes a CIDR.
        let cfg = serde_json::json!({
            "outbounds": [
                { "settings": { "vnext": [{ "address": "1.2.3.4" }] } },
                { "settings": { "peers": [{ "endpoint": "[2001:db8::1]:51820" }] } },
            ]
        })
        .to_string();
        let cidrs = resolve_bypass_cidrs(&cfg, &["8.8.8.8".to_string()]).await;
        assert!(cidrs.contains(&"1.2.3.4/32".to_string()));
        assert!(cidrs.contains(&"2001:db8::1/128".to_string()));
        assert!(cidrs.contains(&"8.8.8.8/32".to_string()));
    }
}
