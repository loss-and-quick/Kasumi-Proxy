//! Windows desktop routing for the xray data-path. xray exposes a local SOCKS;
//! tun2socks bridges a wintun device to it. To put all traffic through the tun
//! while keeping xray's own connection to the VPN server (and DNS bring-up) off it:
//!   - host-route the resolved server IPs (+ the active DNS servers) via the real
//!     uplink gateway, and
//!   - install a split-default (0.0.0.0/1 + 128.0.0.0/1) into the tun, which
//!     overrides the existing `0.0.0.0/0` without deleting it (classic VPN trick).
//!
//! Everything is driven through `route` / `netsh` / `Get-Net*`, mirroring the Linux
//! `ip` back-end. The exact set of installed routes is persisted so teardown is
//! idempotent.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use kasumi_backend::fsjson::{read_json, write_text_atomic};

use crate::desktop::{run_out, silent};

/// The userspace tun's address + mask; `/15` covers the 198.18/15 test net.
const TUN_ADDR: &str = "198.18.0.1";
const TUN_MASK: &str = "255.254.0.0";

/// The two halves of a split-default route, as (dest, mask) pairs. Each overrides
/// `0.0.0.0/0` for its half without touching the real default.
const SPLIT_DEFAULT: [(&str, &str); 2] = [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteState {
    tun: String,
    tun_ifindex: u32,
    /// Bypass host-routes we added (CIDR strings), to delete on teardown.
    bypass: Vec<String>,
}

/// Run a PowerShell one-liner, returning trimmed stdout (empty on failure).
async fn powershell(script: &str) -> String {
    let (code, out) = run_out(&[
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ])
    .await;
    if code != 0 {
        return String::new();
    }
    out.trim().to_string()
}

/// The current default route's gateway + uplink interface index, or `None`.
pub async fn read_default_route() -> Option<(String, u32)> {
    let out = powershell(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
         | Sort-Object RouteMetric \
         | Select-Object -First 1 -Property NextHop,InterfaceIndex \
         | ConvertTo-Json -Compress",
    )
    .await;
    parse_default_route(&out)
}

/// Pull `(gateway, ifindex)` from the `ConvertTo-Json` object of a default route.
fn parse_default_route(out: &str) -> Option<(String, u32)> {
    let v: Value = serde_json::from_str(out.trim()).ok()?;
    let gw = v.get("NextHop")?.as_str()?.to_string();
    let idx = v.get("InterfaceIndex")?.as_u64()? as u32;
    // A non-routable next hop ("on-link" default) has no gateway to bypass via.
    if gw.is_empty() || gw == "0.0.0.0" {
        return None;
    }
    Some((gw, idx))
}

/// The interface index of the named adapter (the wintun device tun2socks created),
/// or `None` if it isn't up yet.
pub async fn adapter_ifindex(name: &str) -> Option<u32> {
    let out = powershell(&format!(
        "(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue).InterfaceIndex"
    ))
    .await;
    out.lines().next()?.trim().parse().ok()
}

/// The DNS server IPs of every active interface (so name resolution keeps working
/// while the tun is up). The Linux side reads /etc/resolv.conf; here it's WMI.
pub async fn read_resolvers() -> Vec<String> {
    let out = powershell(
        "Get-DnsClientServerAddress -AddressFamily IPv4 \
         | Select-Object -ExpandProperty ServerAddresses \
         | Sort-Object -Unique",
    )
    .await;
    out.lines()
        .map(|l| l.trim().to_string())
        .filter(|ip| !ip.is_empty() && ip != "127.0.0.1" && ip != "::1")
        .collect()
}

/// Resolve every server host in the xray config to bypass CIDRs, plus the active
/// DNS servers. The config parsing + resolution is shared with Linux; only the
/// resolver source is Windows-specific (WMI vs /etc/resolv.conf).
pub async fn resolve_bypass_cidrs(xray_cfg_text: &str) -> Vec<String> {
    crate::desktop::net::resolve_bypass_cidrs(xray_cfg_text, &read_resolvers().await).await
}

/// `1.2.3.4/32` → `("1.2.3.4", true)`; `2001:db8::1/128` → `("2001:db8::1", false)`.
/// Returns the bare address and whether it's IPv4.
fn split_cidr(cidr: &str) -> (&str, bool) {
    let addr = cidr.split('/').next().unwrap_or(cidr);
    (addr, !addr.contains(':'))
}

/// Bring up xray routing: host-route the bypass CIDRs via the uplink, address the
/// tun and split-default into it. Persists the installed set.
pub async fn apply_xray_routing(
    tun: &str,
    bypass: &[String],
    route_state_file: &str,
) -> anyhow::Result<()> {
    let Some((gw, uplink)) = read_default_route().await else {
        anyhow::bail!("no default route — cannot set up tun bypass");
    };
    let Some(tun_ifindex) = adapter_ifindex(tun).await else {
        anyhow::bail!("tun adapter '{tun}' not found — tun2socks did not bring it up");
    };
    let uplink = uplink.to_string();
    let tun_idx = tun_ifindex.to_string();

    // Host-route each proxy server / DNS server out via the real uplink gateway.
    for c in bypass {
        let (addr, v4) = split_cidr(c);
        if v4 {
            silent(&[
                "route",
                "add",
                addr,
                "mask",
                "255.255.255.255",
                &gw,
                "metric",
                "1",
                "if",
                &uplink,
            ])
            .await;
        } else {
            silent(&[
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                c,
                &uplink,
                &gw,
            ])
            .await;
        }
    }

    // Address the tun and pull the split-default into it (gateway = the tun's own
    // on-link address, scoped to the tun interface).
    silent(&[
        "netsh",
        "interface",
        "ip",
        "set",
        "address",
        &format!("name={tun}"),
        "static",
        TUN_ADDR,
        TUN_MASK,
    ])
    .await;
    for (dest, mask) in SPLIT_DEFAULT {
        silent(&[
            "route", "add", dest, "mask", mask, TUN_ADDR, "metric", "1", "if", &tun_idx,
        ])
        .await;
    }

    let state = RouteState {
        tun: tun.to_string(),
        tun_ifindex,
        bypass: bypass.to_vec(),
    };
    write_text_atomic(route_state_file, &serde_json::to_string(&state)?).await?;
    Ok(())
}

/// Tear down everything `apply_xray_routing` installed. Idempotent.
pub async fn clear_xray_routing(route_state_file: &str) {
    let Some(state) = read_json::<RouteState>(route_state_file).await else {
        return;
    };
    for (dest, mask) in SPLIT_DEFAULT {
        silent(&["route", "delete", dest, "mask", mask]).await;
    }
    for c in &state.bypass {
        let (addr, v4) = split_cidr(c);
        if v4 {
            silent(&["route", "delete", addr, "mask", "255.255.255.255"]).await;
        } else {
            let ifidx = state.tun_ifindex.to_string();
            silent(&["netsh", "interface", "ipv6", "delete", "route", c, &ifidx]).await;
        }
    }
    kasumi_backend::fs::remove_file(route_state_file).await;
}

/// No-op on Windows: native sing-box rides its embedded wintun, whose driver
/// reclaims the adapter (and its routes) when the core process exits, so there are
/// no orphaned `auto_route` ip-rules/tables to flush like on Linux. (A hard kill
/// leaving a wedged adapter is a separate wintun job-object concern.) The signature
/// matches the Linux seam so `platform.rs` can call it unconditionally.
pub async fn clear_singbox_autoroute(_tun_iface_file: &str, _tun2_iface_file: &str) {}

/// The physical uplink adapter name of the current default route — what a
/// helper-spawned test core binds its outbound to (`bind_interface` /
/// `sockopt.interface`) so it escapes an active tun. `None` when offline.
pub async fn uplink_device() -> Option<String> {
    let alias = powershell(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
         | Sort-Object RouteMetric \
         | Select-Object -First 1 -ExpandProperty InterfaceAlias",
    )
    .await;
    let alias = alias.trim();
    (!alias.is_empty()).then(|| alias.to_string())
}

/// Source-address pin for the uplink bind. Windows binds by interface index
/// (`IP_UNICAST_IF`), which doesn't suffer the multi-homed source-selection issue the
/// Linux `SO_BINDTODEVICE` path does, so no source override is emitted here.
pub async fn uplink_source() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_route_json() {
        let out = r#"{"NextHop":"192.168.1.1","InterfaceIndex":12}"#;
        assert_eq!(
            parse_default_route(out),
            Some(("192.168.1.1".to_string(), 12))
        );
        // On-link default (no gateway) is not bypassable.
        assert_eq!(
            parse_default_route(r#"{"NextHop":"0.0.0.0","InterfaceIndex":12}"#),
            None
        );
        assert_eq!(parse_default_route("not json"), None);
    }

    #[test]
    fn splits_cidr_family() {
        assert_eq!(split_cidr("1.2.3.4/32"), ("1.2.3.4", true));
        assert_eq!(split_cidr("2001:db8::1/128"), ("2001:db8::1", false));
    }
}
