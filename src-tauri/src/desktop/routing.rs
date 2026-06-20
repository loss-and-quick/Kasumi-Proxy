//! Linux desktop routing for the xray data-path. xray exposes a local SOCKS;
//! tun2socks bridges a userspace tun to it. To put all traffic through the tun
//! while keeping xray's own connection to the VPN server (and DNS bring-up) off it:
//!   - host-route the resolved server IPs (+ /etc/resolv.conf nameservers) via the
//!     real uplink gateway, and
//!   - install a split-default (0.0.0.0/1 + 128.0.0.0/1) into the tun, which
//!     overrides the existing `default` without deleting it (classic VPN trick).
//!
//! The exact set of installed routes is persisted so teardown is idempotent.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use kasumi_backend::fs::read_text;
use kasumi_backend::fsjson::{read_json, write_text_atomic};

use super::net::{cidr, resolve_ips};
use super::paths::{IP, TUN_ADDR};
use super::{run_out, silent};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteState {
    tun: String,
    gw: String,
    dev: String,
    /// Bypass host-routes we added (CIDR strings), to delete on teardown.
    bypass: Vec<String>,
}

/// The current default route's gateway + uplink device, or `None`.
pub async fn read_default_route() -> Option<(String, String)> {
    let (code, out) = run_out(&[IP, "route", "show", "default"]).await;
    if code != 0 {
        return None;
    }
    parse_default_route(&out)
}

/// Pull `(gw, dev)` from a `default via <gw> dev <dev> …` line.
fn parse_default_route(out: &str) -> Option<(String, String)> {
    let line = out
        .lines()
        .find(|l| l.trim_start().starts_with("default"))?;
    let toks: Vec<&str> = line.split_whitespace().collect();
    let gw = toks
        .windows(2)
        .find(|w| w[0] == "via")
        .map(|w| w[1].to_string())?;
    let dev = toks
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())?;
    Some((gw, dev))
}

/// Add a non-loopback string host to the set.
fn add_host(hosts: &mut HashSet<String>, h: Option<&Value>) {
    if let Some(s) = h.and_then(Value::as_str) {
        if !s.is_empty() && s != "127.0.0.1" {
            hosts.insert(s.to_string());
        }
    }
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

/// Nameserver IPs from /etc/resolv.conf (so DNS keeps working during bring-up).
async fn read_resolvers() -> Vec<String> {
    let text = read_text("/etc/resolv.conf").await.unwrap_or_default();
    let mut ips = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ip = rest.trim();
            if !ip.is_empty() && ip != "127.0.0.1" && ip != "::1" {
                ips.push(ip.to_string());
            }
        }
    }
    ips
}

/// Resolve every server host in the xray config to bypass CIDRs (+ resolvers).
pub async fn resolve_bypass_cidrs(xray_cfg_text: &str) -> Vec<String> {
    let cfg: Value = serde_json::from_str(xray_cfg_text).unwrap_or(Value::Null);
    let mut out = HashSet::new();
    for host in collect_xray_servers(&cfg) {
        for ip in resolve_ips(&host).await {
            out.insert(cidr(&ip));
        }
    }
    for ip in read_resolvers().await {
        out.insert(cidr(&ip));
    }
    out.into_iter().collect()
}

/// Bring up xray routing: host-route the bypass CIDRs via the uplink, address + up
/// the tun, and split-default into it. Persists the installed set.
pub async fn apply_xray_routing(
    tun: &str,
    bypass: &[String],
    route_state_file: &str,
) -> anyhow::Result<()> {
    let Some((gw, dev)) = read_default_route().await else {
        anyhow::bail!("no default route — cannot set up tun bypass");
    };

    for c in bypass {
        silent(&[IP, "route", "replace", c, "via", &gw, "dev", &dev]).await;
    }

    silent(&[IP, "addr", "add", TUN_ADDR, "dev", tun]).await;
    silent(&[IP, "link", "set", tun, "up"]).await;
    silent(&[IP, "route", "replace", "0.0.0.0/1", "dev", tun]).await;
    silent(&[IP, "route", "replace", "128.0.0.0/1", "dev", tun]).await;

    let state = RouteState {
        tun: tun.to_string(),
        gw,
        dev,
        bypass: bypass.to_vec(),
    };
    let json = serde_json::to_string(&state)?;
    write_text_atomic(route_state_file, &json).await?;
    Ok(())
}

/// Tear down everything `apply_xray_routing` installed. Idempotent.
pub async fn clear_xray_routing(route_state_file: &str) {
    let Some(state) = read_json::<RouteState>(route_state_file).await else {
        return;
    };
    silent(&[IP, "route", "del", "0.0.0.0/1", "dev", &state.tun]).await;
    silent(&[IP, "route", "del", "128.0.0.0/1", "dev", &state.tun]).await;
    for c in &state.bypass {
        silent(&[IP, "route", "del", c]).await;
    }
    kasumi_backend::fs::remove_file(route_state_file).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route() {
        let out = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600";
        assert_eq!(
            parse_default_route(out),
            Some(("192.168.1.1".to_string(), "wlan0".to_string()))
        );
        assert_eq!(parse_default_route("unreachable default"), None);
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
}
