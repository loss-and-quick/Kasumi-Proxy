//! Desktop sing-box config finalisation: tun iface names + the proxy-server bypass.
//! Shared by the Linux and Windows desktop platforms (pure config manipulation).
//!
//! On a desktop tun, `auto_route` + `auto_detect_interface` alone do NOT keep the
//! core's own uplink to the VPN server out of the tunnel — that connection gets
//! captured by the tun and loops, causing timeouts. The fix is `route_exclude_address`
//! on the tun inbound with the resolved server IPs (and literal DNS server IPs),
//! which excludes them at the OS routing level regardless of fwmark.

use std::collections::HashSet;
use std::path::Path;

use serde_json::Value;

use kasumi_backend::fs::{read_text, write_text};
use kasumi_backend::lifecycle::inject_singbox_ifaces;

use crate::desktop::net::{cidr, is_literal_ip, is_loopback, resolve_ips};

/// Outbound server hosts + literal DNS server IPs to keep off the tun.
fn collect_bypass_hosts(cfg: &Value) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for ob in cfg
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(server) = ob.get("server").and_then(Value::as_str) {
            if !server.is_empty() && !is_loopback(server) {
                hosts.insert(server.to_string());
            }
        }
    }
    for s in cfg
        .get("dns")
        .and_then(|d| d.get("servers"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        // Only literal IPs here — domain DNS servers resolve through the proxy.
        if let Some(addr) = s.get("server").and_then(Value::as_str) {
            if is_literal_ip(addr) {
                hosts.insert(addr.to_string());
            }
        }
    }
    hosts
}

/// Inject tun interface names (persisted for traffic counters) and the proxy-server
/// bypass into the on-disk sing-box config. Returns the main tun iface name.
pub async fn prepare_singbox_config(
    cfg_path: &str,
    tun_iface_file: &str,
    tun2_iface_file: &str,
) -> anyhow::Result<String> {
    let (tun, _) = inject_singbox_ifaces(
        Path::new(cfg_path),
        Path::new(tun_iface_file),
        Path::new(tun2_iface_file),
    )
    .await?;

    let raw = read_text(cfg_path).await.unwrap_or_default();
    let mut cfg: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);

    let mut excludes = HashSet::new();
    for host in collect_bypass_hosts(&cfg) {
        for ip in resolve_ips(&host).await {
            excludes.insert(cidr(&ip));
        }
    }
    if !excludes.is_empty() {
        let mut list: Vec<String> = excludes.into_iter().collect();
        list.sort();
        if let Some(inbounds) = cfg.get_mut("inbounds").and_then(Value::as_array_mut) {
            for ib in inbounds {
                if ib.get("type").and_then(Value::as_str) == Some("tun") {
                    ib["route_exclude_address"] = serde_json::to_value(&list)?;
                }
            }
        }
        write_text(cfg_path, &serde_json::to_string_pretty(&cfg)?).await?;
    }
    Ok(tun)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_outbound_servers_and_literal_dns() {
        let cfg = serde_json::json!({
            "outbounds": [
                { "server": "vpn.example" },
                { "server": "127.0.0.1" },
            ],
            "dns": { "servers": [
                { "server": "8.8.8.8" },
                { "server": "dns.google" },
            ] }
        });
        let hosts = collect_bypass_hosts(&cfg);
        assert!(hosts.contains("vpn.example"));
        assert!(hosts.contains("8.8.8.8"));
        // Loopback and domain DNS servers are excluded from the bypass set.
        assert!(!hosts.contains("127.0.0.1"));
        assert!(!hosts.contains("dns.google"));
    }
}
