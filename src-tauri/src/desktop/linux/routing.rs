//! Linux desktop routing for the xray data-path. xray exposes a local SOCKS;
//! tun2socks bridges a userspace tun to it. To put all traffic through the tun
//! while keeping xray's own connection to the VPN server (and DNS bring-up) off it:
//!   - host-route the resolved server IPs (+ /etc/resolv.conf nameservers) via the
//!     real uplink gateway, and
//!   - install a split-default (0.0.0.0/1 + 128.0.0.0/1) into the tun, which
//!     overrides the existing `default` without deleting it (classic VPN trick).
//!
//! The exact set of installed routes is persisted so teardown is idempotent.

use serde::{Deserialize, Serialize};

use kasumi_backend::fs::read_text;
use kasumi_backend::fsjson::{read_json, write_text_atomic};

use crate::desktop::{run_out, silent};

use super::os::{IP, TUN_ADDR};

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

/// Resolve every server host in the xray config to bypass CIDRs, plus the resolv.conf
/// nameservers. The config parsing + resolution is shared; only the resolver source
/// is Linux-specific.
pub async fn resolve_bypass_cidrs(xray_cfg_text: &str) -> Vec<String> {
    crate::desktop::net::resolve_bypass_cidrs(xray_cfg_text, &read_resolvers().await).await
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

/// The physical uplink device of the current default route — what a helper-spawned
/// test core binds its outbound to (`SO_BINDTODEVICE`) so it escapes an active tun.
/// `None` when there's no default route (offline: nothing to test against anyway).
pub async fn uplink_device() -> Option<String> {
    read_default_route().await.map(|(_, dev)| dev)
}

/// The preferred source address of the current default route (`default … src <ip>`).
/// Pinned alongside the uplink device so a multi-homed host can't pick another NIC's
/// source and black-hole the reply (see `outbound_bind::bind_uplink_outbounds`).
/// `None` when the default route carries no `src` (then the device bind is used alone).
pub async fn uplink_source() -> Option<String> {
    let (code, out) = run_out(&[IP, "route", "show", "default"]).await;
    if code != 0 {
        return None;
    }
    parse_default_src(&out)
}

/// Pull the `src <ip>` from a `default via … dev … src <ip>` line.
fn parse_default_src(out: &str) -> Option<String> {
    let line = out
        .lines()
        .find(|l| l.trim_start().starts_with("default"))?;
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.windows(2)
        .find(|w| w[0] == "src")
        .map(|w| w[1].to_string())
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
    fn parses_default_src() {
        let out = "default via 192.168.1.1 dev eno1 proto dhcp src 192.168.1.5 metric 100";
        assert_eq!(parse_default_src(out), Some("192.168.1.5".to_string()));
        // A default route without a src (and no default line at all) yields None.
        assert_eq!(
            parse_default_src("default via 192.168.1.1 dev eno1 metric 100"),
            None
        );
        assert_eq!(
            parse_default_src("192.168.1.0/24 dev eno1 src 192.168.1.5"),
            None
        );
    }
}
