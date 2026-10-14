//! Linux desktop routing for an external-tun data-path. The core exposes a local SOCKS;
//! tun2socks bridges a userspace tun to it. Policy routing puts all traffic through
//! the tun while the core's own dials leave by the main table:
//!   - the core marks its egress sockets with `SINGBOX_ESCAPE_MARK` (as a native
//!     sing-box tun does), and the escape rules send marked traffic to the main
//!     table, whose default route follows the uplink by itself;
//!   - the LAN rule keeps more specific main-table routes (the LAN, docker,
//!     other VPNs) off the tun, except for DNS, which the core answers;
//!   - user exclusions, and the system's resolvers for a core that resolves
//!     through them itself, look up the main table;
//!   - everything else looks up a table whose only route is the tun.
//!
//! Nothing here names the uplink, so an uplink change needs nothing rebuilt.

use serde::{Deserialize, Serialize};

use kasumi_backend::fs::read_text;
use kasumi_backend::fsjson::{read_json, write_text_atomic};
use kasumi_core::outbound_bind::UplinkSource;

use crate::desktop::net::is_loopback;
use crate::desktop::{run_out, silent};

use super::os::{IP, TUN_ADDR};

/// Route table + ip-rule priority of the external tun's capture (`lookup <table>`,
/// the table holding one `default dev <tun>`), and the priority of the exclusions
/// ahead of it. After the escape and LAN rules (`kasumi_core::singbox_config`),
/// before the native sing-box ones. Older versions captured only DNS at the same
/// table and priority, so one teardown clears either.
const TUN_TABLE: &str = "2024";

/// An external tun's core escapes by the fwmark the escape rules route past the
/// tun, not by binding the uplink.
pub const CORE_ESCAPES_BY_MARK: bool = true;
const TUN_RULE_PRIO: &str = "8995";
const EXCLUDE_RULE_PRIO: &str = "8994";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteState {
    tun: String,
    /// The bypass host-routes an older version added to the main table, next to
    /// a split default into the tun; deleted on teardown after an upgrade.
    #[serde(default)]
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

/// What stays off the tun besides the core's marked dials: the user's TUN-exclude
/// CIDRs (e.g. docker networks) and, with `keep_resolvers`, the system's DNS
/// servers (/etc/resolv.conf), for a core that may resolve through them with a
/// socket it doesn't mark (a socks-only sing-box). An xray core reaches its servers
/// through pinned `dns.hosts` instead, so its system DNS goes through the tun. The
/// proxy servers need no entry: only the core dials them, and its dials are marked.
pub async fn bypass_cidrs(
    _servers: &std::collections::BTreeMap<String, Vec<String>>,
    tun_exclude: &[String],
    keep_resolvers: bool,
) -> Vec<String> {
    let resolvers = if keep_resolvers {
        read_resolvers().await
    } else {
        Vec::new()
    };
    crate::desktop::net::bypass_cidrs(&Default::default(), &resolvers, tun_exclude)
}

/// Bring up external-tun routing: the escape and LAN rules, address + up the tun,
/// the exclusions, and the capture of everything else into the tun's table.
pub async fn apply_external_tun_routing(
    tun: &str,
    bypass: &[String],
    // Windows-seam signature match: DNS is captured here whatever this says, since
    // the LAN rule leaves port 53 to the capture. A core that resolves through the
    // system's resolvers gets them in `bypass`.
    _capture_dns: bool,
    _core_bin: &str,
    route_state_file: &str,
) -> anyhow::Result<()> {
    clear_tun_capture().await;
    // The core's first dials already carry the mark, so the escape goes in first.
    apply_escape_rules().await;

    // `replace` (not `add`) so re-runs are idempotent and a tun that already has
    // its address (engines that self-assign) doesn't make this fail.
    silent(&[IP, "addr", "replace", TUN_ADDR, "dev", tun]).await;
    silent(&[IP, "link", "set", tun, "up"]).await;
    silent(&[
        IP, "route", "replace", "default", "dev", tun, "table", TUN_TABLE,
    ])
    .await;
    for c in bypass {
        let family = if c.contains(':') { "-6" } else { "-4" };
        silent(&[
            IP,
            family,
            "rule",
            "add",
            "priority",
            EXCLUDE_RULE_PRIO,
            "to",
            c,
            "lookup",
            "main",
        ])
        .await;
    }
    silent(&[
        IP,
        "rule",
        "add",
        "priority",
        TUN_RULE_PRIO,
        "lookup",
        TUN_TABLE,
    ])
    .await;

    let state = RouteState {
        tun: tun.to_string(),
        bypass: Vec::new(),
    };
    let json = serde_json::to_string(&state)?;
    write_text_atomic(route_state_file, &json).await?;
    Ok(())
}

/// Tear down everything `apply_external_tun_routing` installed. Idempotent.
pub async fn clear_external_tun_routing(route_state_file: &str) {
    // Swept by priority whatever the state file says, so rules left by an unclean
    // exit can't keep capturing traffic into a dead tun.
    clear_tun_capture().await;
    clear_escape_rules().await;
    let Some(state) = read_json::<RouteState>(route_state_file).await else {
        return;
    };
    // What an older version put in the main table.
    silent(&[IP, "route", "del", "0.0.0.0/1", "dev", &state.tun]).await;
    silent(&[IP, "route", "del", "128.0.0.0/1", "dev", &state.tun]).await;
    for c in &state.bypass {
        silent(&[IP, "route", "del", c]).await;
    }
    kasumi_backend::fs::remove_file(route_state_file).await;
}

/// Remove the capture and exclusion rules and the tun's table. Idempotent.
async fn clear_tun_capture() {
    for prio in [TUN_RULE_PRIO, EXCLUDE_RULE_PRIO] {
        while silent(&[IP, "rule", "del", "priority", prio]).await == 0 {}
        while silent(&[IP, "-6", "rule", "del", "priority", prio]).await == 0 {}
    }
    silent(&[IP, "route", "flush", "table", TUN_TABLE]).await;
}

/// Install the fwmark escape rules for a tun the core escapes by mark: a native
/// sing-box tun or the external one. The core stamps its own egress sockets with
/// `SINGBOX_ESCAPE_MARK` (sing-box `route.default_mark`, xray `sockopt.mark`); this
/// rule — evaluated ahead of every capture rule — jumps marked traffic straight to
/// the system's main-table rule (32766), so the core's uplink and geo-`direct` dials
/// leave via the physical default route while everything unmarked (any uid, root
/// included) is captured by the tun. `goto 32766` rather than `lookup main`: were
/// the main lookup to fail (uplink flap), evaluation must not fall through into the
/// capture rules below and loop the marked traffic. A host may lack the 32766 main
/// rule altogether (some VPNs delete it), which leaves the `goto` unresolved and the
/// kernel skips it — the `unreachable` backstop right behind then hard-fails
/// marked traffic instead of letting it loop.
///
/// Right behind them goes the LAN rule (`SINGBOX_LAN_RULE_PRIO`): non-DNS traffic
/// takes a specific main-table route when one exists, so the LAN and replies to
/// connections opened from it stay off the tun. Idempotent — sweeps the
/// priorities first.
pub async fn apply_escape_rules() {
    use kasumi_core::singbox_config::{
        SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO, SINGBOX_ESCAPE_MARK, SINGBOX_ESCAPE_RULE_PRIO,
        SINGBOX_LAN_RULE_PRIO,
    };

    let prio = SINGBOX_ESCAPE_RULE_PRIO.to_string();
    let backstop = SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO.to_string();
    let lan = SINGBOX_LAN_RULE_PRIO.to_string();
    let mark = format!("{SINGBOX_ESCAPE_MARK:#x}");
    for v6 in [false, true] {
        let mut base = vec![IP];
        if v6 {
            base.push("-6");
        }
        for p in [&prio, &backstop, &lan] {
            let mut del = base.clone();
            del.extend(["rule", "del", "priority", p]);
            while silent(&del).await == 0 {}
        }
        let mut add = base.clone();
        add.extend([
            "rule", "add", "priority", &prio, "fwmark", &mark, "goto", "32766",
        ]);
        silent(&add).await;
        let mut add = base.clone();
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
        let mut add = base;
        add.extend([
            "rule",
            "add",
            "priority",
            &lan,
            "not",
            "dport",
            "53",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
        ]);
        silent(&add).await;
    }
}

/// Remove what [`apply_escape_rules`] installs, both families. Idempotent.
async fn clear_escape_rules() {
    use kasumi_core::singbox_config::{
        SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO, SINGBOX_ESCAPE_RULE_PRIO, SINGBOX_LAN_RULE_PRIO,
    };

    for prio in [
        SINGBOX_ESCAPE_RULE_PRIO,
        SINGBOX_ESCAPE_BACKSTOP_RULE_PRIO,
        SINGBOX_LAN_RULE_PRIO,
    ] {
        let p = prio.to_string();
        while silent(&[IP, "rule", "del", "priority", &p]).await == 0 {}
        while silent(&[IP, "-6", "rule", "del", "priority", &p]).await == 0 {}
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
        SINGBOX_FORCE_RULE_PRIO, SINGBOX_FORCE_TABLE, SINGBOX_MAIN_RULE_PRIO, SINGBOX_MAIN_TABLE,
    };

    // The fwmark escape rules (goto + unreachable backstop) and the LAN rule are
    // ours, not sing-box's, but they orphan the same way when the data-path dies
    // uncleanly.
    clear_escape_rules().await;

    // Policy ip-rules: a single priority can carry more than one rule, so loop on
    // `del` until it reports there's nothing left at that priority.
    for prio in SINGBOX_MAIN_RULE_PRIO..=SINGBOX_FORCE_RULE_PRIO {
        let p = prio.to_string();
        while silent(&[IP, "rule", "del", "priority", &p]).await == 0 {}
        // sing-box puts a tun's IPv6 rules in the same range.
        while silent(&[IP, "-6", "rule", "del", "priority", &p]).await == 0 {}
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

/// Bind `socket` to the uplink device (`SO_BINDTODEVICE`, needs `CAP_NET_RAW`) and,
/// when its family matches `dest`, the uplink's source address — the same pair
/// `bind_uplink_outbounds` pins for test cores. No uplink leaves it unbound.
pub async fn bind_uplink(
    socket: &tokio::net::TcpSocket,
    dest: std::net::IpAddr,
) -> std::io::Result<()> {
    let Some(dev) = uplink_device().await else {
        return Ok(());
    };
    socket.bind_device(Some(dev.as_bytes()))?;
    let source = uplink_source(&dev).await;
    let pin = match dest {
        std::net::IpAddr::V4(_) => source.v4,
        std::net::IpAddr::V6(_) => source.v6,
    };
    if let Some(src) = pin.and_then(|s| s.parse::<std::net::IpAddr>().ok()) {
        socket.bind(std::net::SocketAddr::new(src, 0))?;
    }
    Ok(())
}

/// The source addresses to pin alongside the uplink device `dev`, so a multi-homed
/// host can't pick another NIC's source and black-hole the reply (see
/// `outbound_bind::bind_uplink_outbounds`). IPv4 is the default route's `src`.
/// IPv6 default routes rarely carry one, so the kernel is asked which source it
/// would pick on `dev` for a global destination (a documentation address; nothing
/// is sent). A family left `None` keeps the device bind alone.
pub async fn uplink_source(dev: &str) -> UplinkSource {
    let (code, out) = run_out(&[IP, "route", "show", "default"]).await;
    let v4 = (code == 0).then(|| parse_default_src(&out)).flatten();
    let (code, out) = run_out(&[IP, "-6", "route", "get", V6_PROBE, "oif", dev]).await;
    let v6 = (code == 0).then(|| parse_route_src_v6(&out)).flatten();
    UplinkSource { v4, v6 }
}

/// A global IPv6 destination for `ip route get` (RFC 3849 documentation prefix).
const V6_PROBE: &str = "2001:db8::1";

/// The `src` of an `ip -6 route get` answer, unless it is link-local: binding one
/// needs a scope id the cores don't take.
fn parse_route_src_v6(out: &str) -> Option<String> {
    let toks: Vec<&str> = out.split_whitespace().collect();
    let src = toks.windows(2).find(|w| w[0] == "src").map(|w| w[1])?;
    let ip: std::net::Ipv6Addr = src.parse().ok()?;
    ((ip.segments()[0] & 0xffc0) != 0xfe80).then(|| src.to_string())
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
    fn parses_the_ipv6_route_source() {
        let out = "2001:db8::1 from :: via fe80::1 dev eno1 proto ra src 2a02:6b8::5 metric 100 pref medium";
        assert_eq!(parse_route_src_v6(out), Some("2a02:6b8::5".to_string()));
        // A link-local source can't be bound without its scope.
        assert_eq!(
            parse_route_src_v6("2001:db8::1 via fe80::1 dev eno1 src fe80::5 metric 100"),
            None
        );
        assert_eq!(
            parse_route_src_v6("2001:db8::1 via fe80::1 dev eno1 metric 100"),
            None
        );
        assert_eq!(parse_route_src_v6(""), None);
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
