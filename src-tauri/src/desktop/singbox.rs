//! Desktop sing-box config finalisation: tun iface names + the proxy-server bypass.
//! Shared by the Linux and Windows desktop platforms (pure config manipulation).
//!
//! On a desktop tun, `auto_route` + `auto_detect_interface` alone do NOT keep the
//! core's own uplink to the VPN server out of the tunnel — that connection gets
//! captured by the tun and loops, causing timeouts. The fix is `route_exclude_address`
//! on the tun inbound with the resolved server IPs (and literal DNS server IPs),
//! which excludes them at the OS routing level regardless of fwmark. The config
//! generator bakes the user's own exclusions (`tun_exclude_addresses`, e.g. docker
//! networks) into that list at build time; this post-processor merges the
//! runtime-resolved server IPs in without clobbering them.
//!
//! On Linux the core's `direct` outbound additionally dials arbitrary
//! geo-`direct` hosts whose IPs can't be pre-resolved into that exclude list, so
//! every egress socket is stamped with `route.default_mark` and a fwmark ip-rule
//! installed above the `auto_route` rules diverts it to the main table (see
//! `routing::apply_singbox_escape_rule`). Everything unmarked — any uid, root
//! included — stays captured by the tun.

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
        if let Some(server) = ob.get("server").and_then(Value::as_str)
            && !server.is_empty()
            && !is_loopback(server)
        {
            hosts.insert(server.to_string());
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
        if let Some(addr) = s.get("server").and_then(Value::as_str)
            && is_literal_ip(addr)
        {
            hosts.insert(addr.to_string());
        }
    }
    hosts
}

/// Stamp every egress socket of the core with the escape fwmark (Linux only; the
/// option is rejected by sing-box elsewhere, and Windows needs no mark — its tun
/// escape is route-based). The matching ip-rule is installed by
/// `routing::apply_singbox_escape_rule`.
#[cfg(target_os = "linux")]
fn inject_escape_mark(cfg: &mut Value) -> bool {
    let Some(route) = cfg.get_mut("route").and_then(Value::as_object_mut) else {
        return false;
    };
    route.insert(
        "default_mark".into(),
        kasumi_core::singbox_config::SINGBOX_ESCAPE_MARK.into(),
    );
    true
}

#[cfg(not(target_os = "linux"))]
fn inject_escape_mark(_cfg: &mut Value) -> bool {
    false
}

/// Inject tun interface names (persisted for traffic counters), the proxy-server
/// bypass and the egress fwmark into the on-disk sing-box config. Returns the main
/// tun iface name.
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

    let mut changed = inject_escape_mark(&mut cfg);

    let mut excludes = HashSet::new();
    for host in collect_bypass_hosts(&cfg) {
        for ip in resolve_ips(&host).await {
            excludes.insert(cidr(&ip));
        }
    }
    if !excludes.is_empty()
        && let Some(inbounds) = cfg.get_mut("inbounds").and_then(Value::as_array_mut)
    {
        for ib in inbounds {
            if ib.get("type").and_then(Value::as_str) == Some("tun") {
                // Merge the proxy-server bypass into any user CIDRs the builder
                // already placed on `route_exclude_address` (`tun_exclude_addresses`);
                // never overwrite them, or the OS-level exclusion is lost when the
                // config is rewritten on every reconnect.
                let mut merged: HashSet<String> = ib
                    .get("route_exclude_address")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                merged.extend(excludes.iter().cloned());
                let mut list: Vec<String> = merged.into_iter().collect();
                list.sort();
                ib["route_exclude_address"] = serde_json::to_value(&list)?;
                changed = true;
            }
        }
    }
    if changed {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn escape_mark_lands_in_route_on_linux() {
        let mut cfg = serde_json::json!({ "route": { "auto_detect_interface": true } });
        assert!(inject_escape_mark(&mut cfg));
        assert_eq!(
            cfg["route"]["default_mark"],
            kasumi_core::singbox_config::SINGBOX_ESCAPE_MARK
        );
        // A config without a route section (not ours) is left alone.
        let mut cfg = serde_json::json!({ "inbounds": [] });
        assert!(!inject_escape_mark(&mut cfg));
    }

    // The proxy-server bypass (resolved at runtime) must merge with any
    // user-specified CIDRs already baked into the tun inbound's `route_exclude_address`
    // by the config generator (`tun_exclude_addresses`) — never overwrite them.
    #[tokio::test]
    async fn merges_proxy_bypass_into_existing_route_exclude() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("singbox.json");
        let tun1 = dir.path().join("tun_iface");
        let tun2 = dir.path().join("tun2_iface");
        std::fs::write(&tun1, "").unwrap();
        std::fs::write(&tun2, "").unwrap();

        let cfg = serde_json::json!({
            "inbounds": [
                { "type": "tun", "tag": "tun-in", "route_exclude_address": ["172.17.0.0/16"] },
                { "type": "loopback" },
            ],
            "outbounds": [{ "type": "socks", "server": "1.2.3.4" }],
        });
        std::fs::write(&cfg_path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        prepare_singbox_config(
            cfg_path.to_str().unwrap(),
            tun1.to_str().unwrap(),
            tun2.to_str().unwrap(),
        )
        .await
        .unwrap();

        let raw = read_text(&cfg_path).await.unwrap();
        let out: Value = serde_json::from_str(&raw).unwrap();
        let excluded: Vec<&str> = out["inbounds"][0]["route_exclude_address"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        // Both survive the rewrite: the user CIDR (verbatim) and the literal-IP
        // server bypass (host-routed as /32).
        assert!(excluded.contains(&"172.17.0.0/16"));
        assert!(excluded.contains(&"1.2.3.4/32"));
    }
}
