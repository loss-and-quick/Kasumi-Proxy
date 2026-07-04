//! DNS/address helpers shared by the desktop data-path (`singbox` + `routing`), so
//! the proxy-server bypass resolution lives in one place — including the parsing
//! of proxy-server hosts out of a built xray config, reused by both the Linux and
//! Windows routing back-ends.

use std::collections::HashSet;

use serde_json::Value;

/// Resolve a host (domain or literal IP) to its IPs, or `[]` on failure.
pub async fn resolve_ips(host: &str) -> Vec<String> {
    match tokio::net::lookup_host((host, 0u16)).await {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Add a non-loopback string host to the set.
fn add_host(hosts: &mut HashSet<String>, h: Option<&Value>) {
    if let Some(s) = h.and_then(Value::as_str)
        && !is_loopback(s)
    {
        hosts.insert(s.to_string());
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
                if !host.is_empty() && !is_loopback(&host) {
                    hosts.insert(host);
                }
            }
        }
    }
    // xray \`dns.servers\` — the core's own upstream resolvers; must be host-routed
    // off the tun or the core can't resolve its proxy-server host. Plain-string
    // or object-shape; domain servers are skipped (they resolve through the proxy).
    for sv in cfg
        .get("dns")
        .and_then(|d| d.get("servers"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let raw = sv
            .as_str()
            .or_else(|| sv.get("address").and_then(Value::as_str));
        if let Some(addr) = raw
            && !is_loopback(addr)
            && is_literal_ip(addr)
        {
            hosts.insert(addr.to_string());
        }
    }
    hosts
}

/// Proxy-server hosts from a built sing-box config: each outbound's `server`,
/// wireguard endpoint peers, plus literal `dns.servers` IPs. Used when a sing-box
/// core runs socks-only behind an external tun engine (no native tun to carry
/// `route_exclude_address`), so it must reproduce the same bypass set the native
/// path bakes into the config.
fn collect_singbox_servers(cfg: &Value) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for ob in cfg
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        add_host(&mut hosts, ob.get("server"));
    }
    for ep in cfg
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        add_host(&mut hosts, ep.get("server"));
        for peer in ep
            .get("peers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            add_host(&mut hosts, peer.get("address"));
        }
    }
    // sing-box `dns.servers` literal IPs — the core's own upstream resolvers must be
    // host-routed off the tun, else its DNS queries are captured by the split-default
    // and loop back through the helper into the core. Mirrors the native path's
    // `route_exclude_address` (see `singbox::collect_bypass_hosts`); domain DNS
    // servers are skipped (they resolve through the proxy).
    for s in cfg
        .get("dns")
        .and_then(|d| d.get("servers"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(addr) = s.get("server").and_then(Value::as_str)
            && !is_loopback(addr)
            && is_literal_ip(addr)
        {
            hosts.insert(addr.to_string());
        }
    }
    hosts
}

/// Resolve every proxy-server host in the built config to bypass CIDRs, plus the
/// `extra_hosts` the OS routing back-end supplies (its DNS resolvers, so name
/// resolution keeps working while the tun is up). Handles both the xray and the
/// sing-box config shapes (their server keys are disjoint, so the union is safe).
pub async fn resolve_bypass_cidrs(cfg_text: &str, extra_hosts: &[String]) -> Vec<String> {
    let cfg: Value = serde_json::from_str(cfg_text).unwrap_or(Value::Null);
    let mut out = HashSet::new();
    let mut servers = collect_xray_servers(&cfg);
    servers.extend(collect_singbox_servers(&cfg));
    for host in servers {
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

/// Whether \`ip\` is a loopback address that should never be bypass-routed — any
/// \`127.x\` prefix (\`127.0.0.1\`, \`127.0.0.53\`), \`::1\`, or \`0.0.0.0\`.
pub fn is_loopback(ip: &str) -> bool {
    ip.is_empty() || ip.starts_with("127.") || ip == "::1" || ip == "0.0.0.0"
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

    #[test]
    fn collects_singbox_outbound_and_endpoint_servers() {
        let cfg = serde_json::json!({
            "outbounds": [
                { "type": "vless", "server": "sb.example" },
                { "type": "direct" },
                { "type": "socks", "server": "127.0.0.1" },
            ],
            "endpoints": [
                { "type": "wireguard", "peers": [{ "address": "wg.example" }] },
            ],
            "dns": { "servers": [
                { "type": "udp", "server": "8.8.8.8" },
                { "type": "udp", "server": "dns.google" },
                { "type": "udp", "server": "127.0.0.1" },
            ] }
        });
        let hosts = collect_singbox_servers(&cfg);
        assert!(hosts.contains("sb.example"));
        assert!(hosts.contains("wg.example"));
        // Literal DNS server IPs are bypassed (parity with the native tun path);
        // domain and loopback DNS servers are not.
        assert!(hosts.contains("8.8.8.8"));
        assert!(!hosts.contains("dns.google"));
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

    #[tokio::test]
    async fn collects_xray_dns_servers() {
        let cfg = serde_json::json!({
            "dns": { "servers": ["1.1.1.1", "8.8.8.8", {"address": "223.5.5.5"}, "dns.google"] }
        })
        .to_string();
        let cidrs: Vec<String> = resolve_bypass_cidrs(&cfg, &[]).await;
        assert!(cidrs.contains(&"1.1.1.1/32".to_string()));
        assert!(cidrs.contains(&"8.8.8.8/32".to_string()));
        assert!(cidrs.contains(&"223.5.5.5/32".to_string()));
        assert!(!cidrs.iter().any(|c| c.starts_with("dns.google")));
    }
}
