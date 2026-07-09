//! Linux desktop routing for an external-tun data-path. The core exposes a local SOCKS;
//! tun2socks bridges a userspace tun to it. To put all traffic through the tun
//! while keeping the core's own connection to the VPN server (and DNS bring-up) off it:
//!   - host-route the resolved server IPs (+ /etc/resolv.conf nameservers) via the
//!     real uplink gateway, and
//!   - install a split-default (0.0.0.0/1 + 128.0.0.0/1) into the tun, which
//!     overrides the existing `default` without deleting it (classic VPN trick).
//!
//! The exact set of installed routes is persisted so teardown is idempotent.

use serde::{Deserialize, Serialize};

use kasumi_backend::fs::read_text;
use kasumi_backend::fsjson::{read_json, write_text_atomic};

use crate::desktop::net::is_loopback;
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
            if !is_loopback(ip) {
                ips.push(ip.to_string());
            }
        }
    }
    ips
}

/// Resolve every server host in the core config to bypass CIDRs, plus the resolv.conf
/// nameservers. The config parsing + resolution is shared; only the resolver source
/// is Linux-specific.
pub async fn resolve_bypass_cidrs(cfg_text: &str) -> Vec<String> {
    crate::desktop::net::resolve_bypass_cidrs(cfg_text, &read_resolvers().await).await
}

/// Bring up external-tun routing: host-route the bypass CIDRs via the uplink, address + up
/// the tun, and split-default into it. Persists the installed set.
pub async fn apply_external_tun_routing(
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

    // `replace` (not `add`) so re-runs are idempotent and a tun that already has
    // its address (engines that self-assign) doesn't make this fail.
    silent(&[IP, "addr", "replace", TUN_ADDR, "dev", tun]).await;
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

/// Tear down everything `apply_external_tun_routing` installed. Idempotent.
pub async fn clear_external_tun_routing(route_state_file: &str) {
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

/// Install the fwmark escape rule for a native sing-box tun. The core stamps its
/// own egress sockets with `SINGBOX_ESCAPE_MARK` (`route.default_mark`, injected by
/// `prepare_singbox_config`); this rule — evaluated ahead of every `auto_route`
/// rule — jumps marked traffic straight to the system's main-table rule (32766),
/// so the core's uplink and geo-`direct` dials leave via the physical default
/// route while everything unmarked (any uid, root included) is captured by the
/// tun. `goto 32766` rather than `lookup main`: were the main lookup to fail
/// (uplink flap), evaluation must not fall through into the auto_route rules
/// below and loop the marked traffic. A host may lack the 32766 main rule
/// altogether (some VPNs delete it), which leaves the `goto` unresolved and the
/// kernel skips it — the `unreachable` backstop right behind then hard-fails
/// marked traffic instead of letting it loop. Idempotent — sweeps the
/// priorities first.
pub async fn apply_singbox_escape_rule() {
    use kasumi_core::singbox_config::{
        SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO, SINGBOX_ESCAPE_MARK, SINGBOX_ESCAPE_RULE_PRIO,
    };

    let prio = SINGBOX_ESCAPE_RULE_PRIO.to_string();
    let backstop = SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO.to_string();
    let mark = format!("{SINGBOX_ESCAPE_MARK:#x}");
    for v6 in [false, true] {
        let mut base = vec![IP];
        if v6 {
            base.push("-6");
        }
        for p in [&prio, &backstop] {
            let mut del = base.clone();
            del.extend(["rule", "del", "priority", p]);
            while silent(&del).await == 0 {}
        }
        let mut add = base.clone();
        add.extend([
            "rule", "add", "priority", &prio, "fwmark", &mark, "goto", "32766",
        ]);
        silent(&add).await;
        let mut add = base;
        add.extend([
            "rule",
            "add",
            "priority",
            &backstop,
            "fwmark",
            &mark,
            "unreachable",
        ]);
        silent(&add).await;
    }
}

/// Tear down orphaned native-sing-box `auto_route` artifacts (policy ip-rules, route
/// tables, split-default) that a core left behind when it didn't exit cleanly — a
/// crash or a SIGKILL after the graceful window. sing-box removes these itself on a
/// clean SIGTERM; this is the fallback for when it can't, and the orphans otherwise
/// wedge routing into a now-dead tun (with `strict_route` on, a stuck kill-switch),
/// black-holing all traffic until `~/kasumi-panic.sh` is run by hand.
///
/// Idempotent and scoped to the exact tables/rule-priorities Magic configures (see
/// `kasumi_core::singbox_config`), so Tailscale / WireGuard / xray routing is left
/// untouched. Safe to call in xray mode (no rules at these priorities exist there).
pub async fn clear_singbox_autoroute(tun_iface_file: &str, tun2_iface_file: &str) {
    use kasumi_core::singbox_config::{
        SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO, SINGBOX_ESCAPE_RULE_PRIO, SINGBOX_FORCE_RULE_PRIO,
        SINGBOX_FORCE_TABLE, SINGBOX_MAIN_RULE_PRIO, SINGBOX_MAIN_TABLE,
    };

    // The fwmark escape rules (goto + unreachable backstop) are ours, not
    // sing-box's, but they orphan the same way when the data-path dies uncleanly
    // (both families; v6 exists when installed).
    for prio in [SINGBOX_ESCAPE_RULE_PRIO, SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO] {
        let p = prio.to_string();
        while silent(&[IP, "rule", "del", "priority", &p]).await == 0 {}
        while silent(&[IP, "-6", "rule", "del", "priority", &p]).await == 0 {}
    }

    // Policy ip-rules: a single priority can carry more than one rule, so loop on
    // `del` until it reports there's nothing left at that priority.
    for prio in SINGBOX_MAIN_RULE_PRIO..=SINGBOX_FORCE_RULE_PRIO {
        let p = prio.to_string();
        while silent(&[IP, "rule", "del", "priority", &p]).await == 0 {}
    }
    // Drain the per-tun route tables (main + force).
    for table in [SINGBOX_MAIN_TABLE, SINGBOX_FORCE_TABLE] {
        silent(&[IP, "route", "flush", "table", &table.to_string()]).await;
    }
    // Split-default routes — delete a `0/1` / `128/1` only when it points at one of
    // *our* tun devices; a foreign VPN's split-default must survive.
    let mut ours: Vec<String> = Vec::new();
    for f in [tun_iface_file, tun2_iface_file] {
        if let Some(name) = read_text(f).await.map(|s| s.trim().to_owned())
            && !name.is_empty()
        {
            ours.push(name);
        }
    }
    for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
        let (code, out) = run_out(&[IP, "route", "show", cidr]).await;
        if code == 0 && parse_route_dev(&out).is_some_and(|d| ours.iter().any(|n| n == d)) {
            silent(&[IP, "route", "del", cidr]).await;
        }
    }
    silent(&[IP, "route", "flush", "cache"]).await;
}

/// The `dev <name>` of a single-route `ip route show <cidr>` line, or `None`.
fn parse_route_dev(out: &str) -> Option<&str> {
    let line = out.lines().next()?;
    let toks: Vec<&str> = line.split_whitespace().collect();
    toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1])
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
    fn parses_route_dev() {
        // sing-box installs the split-default into its tun.
        assert_eq!(
            parse_route_dev("0.0.0.0/1 dev tun8f3a scope link"),
            Some("tun8f3a")
        );
        assert_eq!(
            parse_route_dev("128.0.0.0/1 dev tun8f3a table 2022"),
            Some("tun8f3a")
        );
        // No device (or empty output) yields None.
        assert_eq!(parse_route_dev("unreachable 0.0.0.0/1"), None);
        assert_eq!(parse_route_dev(""), None);
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
