//! Proxying the devices tethered to the phone (Wi-Fi hotspot, USB, Bluetooth).
//!
//! Off by default: tethered clients are forwarded straight out the uplink by
//! Android's own tethering rules, and nothing here is installed. When the user
//! turns it on, the packets that *arrive on a tethering interface* are steered
//! into the proxy's tun, and the tun's replies are steered back to that interface.
//!
//! Everything is keyed on the tethering interface (`iif <tether>`) and on the tun,
//! never on the uplink. A rule keyed on the uplink (`iif <uplink> lookup <uplink>`,
//! which older versions installed under sing-box `strict_route`) also matches the
//! de-NATed replies of tethered clients, which arrive on the uplink, and sends them
//! straight back out: the clients lost their internet. Nothing below may name the
//! uplink; the plan builder is only handed tethering interfaces and the tun.
//!
//! A hotspot can be switched on long after the proxy started, and the setting can
//! be flipped at any time, so a small watcher task re-reads both every few seconds
//! and reconciles the rules. Teardown ([`clear_tethering`]) always removes
//! everything, whatever the setting says by then.

use std::sync::Mutex;
use std::time::Duration;

use tokio::task::JoinHandle;

use kasumi_core::singbox_config::SINGBOX_MAIN_TABLE;

use super::paths::{IP, IP6TABLES, IPTABLES, TUN_IFACE_FILE};
use super::platform::{read_iface, read_settings};
use super::routing::{TUN_TABLE, ip_rule};
use super::sysctl::lock_tun_iface;
use super::{default_uplink, run_out, silent};

/// Our own chain in `filter FORWARD` (accepts) and `nat PREROUTING` (DNS).
const CHAIN: &str = "KASUMI_PROXY_TETHER";
/// Holds the tethering subnets' connected routes, so the tun's replies can find the
/// way back to the client without depending on how the OS files those routes.
const REPLY_TABLE: &str = "1102";
/// Above the app-mark rules (1000/1010) and below everything else, the OS's own
/// rules and sing-box's `auto_route` rules (9000+, including its uid-0 exemption
/// that forwarded packets would otherwise fall under) included.
const PRIO_STEER: &str = "1015";
const PRIO_REPLY: &str = "1016";
/// Where tethered clients' DNS is sent. They ask the phone's resolver on the
/// gateway address, which is a local destination: it never reaches the tun, and the
/// phone would answer from the carrier's DNS while the connections go through the
/// proxy. Redirecting port 53 to a routable address sends it through the tun like
/// the phone's own lookups, where the core's DNS handling answers whatever the
/// destination is. The conntrack reverse NAT restores the gateway as the source.
const DNS_REDIRECT: &str = "1.1.1.1";
const POLL: Duration = Duration::from_secs(4);

/// Which data path the tun belongs to; decides the route table the steered
/// packets are looked up in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TetherPath {
    /// A userspace tun bridge (tun2socks / hev / sidecar sing-box) and our own
    /// table 1100 whose default route is that tun.
    External,
    /// Native sing-box `auto_route`: its table holds the default route into the tun.
    Native,
}

impl TetherPath {
    fn table(self) -> String {
        match self {
            Self::External => TUN_TABLE.to_string(),
            Self::Native => SINGBOX_MAIN_TABLE.to_string(),
        }
    }
}

/// One tethering interface and the subnet it serves.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TetherIface {
    pub name: String,
    /// `a.b.c.0/24`
    pub net: String,
}

/// The commands that make tethered traffic go through the proxy. Each entry is the
/// argument list of one command (without the `ip` / `iptables` binary).
#[derive(Default, Debug, PartialEq, Eq)]
pub struct TetherPlan {
    pub ip_routes: Vec<Vec<String>>,
    pub ip_rules: Vec<Vec<String>>,
    /// `filter FORWARD` chain, IPv4.
    pub filter4: Vec<Vec<String>>,
    /// `filter FORWARD` chain, IPv6.
    pub filter6: Vec<Vec<String>>,
    /// `nat PREROUTING` chain, IPv4.
    pub nat4: Vec<Vec<String>>,
}

impl TetherPlan {
    pub fn is_empty(&self) -> bool {
        self.ip_routes.is_empty()
            && self.ip_rules.is_empty()
            && self.filter4.is_empty()
            && self.filter6.is_empty()
            && self.nat4.is_empty()
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// The rules for `ifaces` going through `tun`, looking steered packets up in
/// `table`. No interfaces, no rules.
pub fn tether_plan(ifaces: &[TetherIface], tun: &str, table: &str) -> TetherPlan {
    let mut plan = TetherPlan::default();
    for t in ifaces {
        let (name, net) = (t.name.as_str(), t.net.as_str());
        plan.ip_routes.push(args(&[
            "route",
            "replace",
            net,
            "dev",
            name,
            "table",
            REPLY_TABLE,
        ]));
        // Forwarded packets carry uid 0 and would fall under the tun's root
        // exemption; matching the ingress interface ahead of it captures them.
        plan.ip_rules.push(args(&[
            "rule", "add", "iif", name, "lookup", table, "pref", PRIO_STEER,
        ]));
        // The tun's replies arrive on the tun, addressed to the client.
        plan.ip_rules.push(args(&[
            "rule",
            "add",
            "iif",
            tun,
            "to",
            net,
            "lookup",
            REPLY_TABLE,
            "pref",
            PRIO_REPLY,
        ]));
        // Android's tether FORWARD chain only knows the uplink pair.
        plan.filter4
            .push(args(&["-i", name, "-o", tun, "-j", "ACCEPT"]));
        plan.filter4
            .push(args(&["-i", tun, "-o", name, "-j", "ACCEPT"]));
        // No IPv6 path through the tun for clients: refuse it so they fall back to
        // IPv4 at once instead of leaking around the proxy.
        plan.filter6.push(args(&[
            "-i",
            name,
            "-j",
            "REJECT",
            "--reject-with",
            "icmp6-no-route",
        ]));
        for proto in ["udp", "tcp"] {
            plan.nat4.push(args(&[
                "-i",
                name,
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "DNAT",
                "--to-destination",
                DNS_REDIRECT,
            ]));
        }
    }
    plan
}

/// What to install: nothing unless the option is on.
fn wanted(enabled: bool, detected: Vec<TetherIface>) -> Vec<TetherIface> {
    if enabled { detected } else { Vec::new() }
}

/// Interface names a tethering downstream can have. Matching by name only narrows
/// the candidates; [`parse_tether_ifaces`] then needs the address Android gives a
/// downstream. `wlan0` and `eth0` are in, because single-radio phones host the
/// hotspot on `wlan0`; the uplink is excluded separately.
fn is_tether_name(name: &str) -> bool {
    [
        "wlan", "ap", "swlan", "softap", "rndis", "ncm", "usb", "bt-pan", "bnep", "eth", "wigig",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

fn private_v4(o: [u8; 4]) -> bool {
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Tethering interfaces out of `ip -o -4 addr show`. Android makes itself the
/// gateway of a tethering downstream: a private `x.y.z.1/24` on the interface. A
/// Wi-Fi station on someone's LAN (a DHCP lease, almost never the `.1` of a `/24`)
/// and the uplinks don't look like that. `exclude` names interfaces that must never
/// qualify (the uplink, the tuns).
pub fn parse_tether_ifaces(addr_out: &str, exclude: &[&str]) -> Vec<TetherIface> {
    let mut found: Vec<TetherIface> = Vec::new();
    for line in addr_out.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = toks.iter().position(|t| *t == "inet") else {
            continue;
        };
        let (Some(name), Some(cidr)) = (toks.get(1), toks.get(i + 1)) else {
            continue;
        };
        let name = name.trim_end_matches(':').split('@').next().unwrap_or("");
        if name.is_empty() || exclude.contains(&name) || !is_tether_name(name) {
            continue;
        }
        let Some((ip, prefix)) = cidr.split_once('/') else {
            continue;
        };
        let octets: Vec<u8> = ip.split('.').filter_map(|o| o.parse().ok()).collect();
        let Ok(o) = <[u8; 4]>::try_from(octets) else {
            continue;
        };
        if prefix != "24" || o[3] != 1 || !private_v4(o) {
            continue;
        }
        if found.iter().any(|f| f.name == name) {
            continue;
        }
        found.push(TetherIface {
            name: name.to_string(),
            net: format!("{}.{}.{}.0/24", o[0], o[1], o[2]),
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// The tethering interfaces that are up right now.
async fn detect(tuns: &[&str]) -> Vec<TetherIface> {
    // Reading sysfs is free; only spawn `ip` when something could be a downstream.
    let mut any = false;
    if let Ok(mut rd) = tokio::fs::read_dir("/sys/class/net").await {
        while let Ok(Some(e)) = rd.next_entry().await {
            if is_tether_name(&e.file_name().to_string_lossy()) {
                any = true;
                break;
            }
        }
    }
    if !any {
        return Vec::new();
    }
    let uplink = default_uplink().await;
    let mut exclude: Vec<&str> = tuns.to_vec();
    if let Some(u) = uplink.as_deref() {
        exclude.push(u);
    }
    let (_, out) = run_out(&[IP, "-o", "-4", "addr", "show"]).await;
    parse_tether_ifaces(&out, &exclude)
}

async fn ipt(bin: &str, table: Option<&str>, rest: &[&str]) -> i32 {
    let mut a = vec![bin];
    if let Some(t) = table {
        a.extend(["-t", t]);
    }
    a.extend_from_slice(rest);
    silent(&a).await
}

async fn install(plan: &TetherPlan) {
    for r in &plan.ip_routes {
        let a: Vec<&str> = r.iter().map(String::as_str).collect();
        ip_rule(false, &a).await;
    }
    for r in &plan.ip_rules {
        let a: Vec<&str> = r.iter().map(String::as_str).collect();
        ip_rule(false, &a).await;
    }
    for (bin, table, hook, rules) in [
        (IPTABLES, None, "FORWARD", &plan.filter4),
        (IP6TABLES, None, "FORWARD", &plan.filter6),
        (IPTABLES, Some("nat"), "PREROUTING", &plan.nat4),
    ] {
        ipt(bin, table, &["-N", CHAIN]).await;
        ipt(bin, table, &["-F", CHAIN]).await;
        for r in rules {
            let mut a = vec!["-A", CHAIN];
            a.extend(r.iter().map(String::as_str));
            ipt(bin, table, &a).await;
        }
        while ipt(bin, table, &["-D", hook, "-j", CHAIN]).await == 0 {}
        ipt(bin, table, &["-I", hook, "1", "-j", CHAIN]).await;
    }
}

/// Remove everything [`install`] adds, in any state. Safe to call when nothing
/// was installed.
pub async fn clear_tethering() {
    for (bin, table, hook) in [
        (IPTABLES, None, "FORWARD"),
        (IP6TABLES, None, "FORWARD"),
        (IPTABLES, Some("nat"), "PREROUTING"),
    ] {
        while ipt(bin, table, &["-D", hook, "-j", CHAIN]).await == 0 {}
        ipt(bin, table, &["-F", CHAIN]).await;
        ipt(bin, table, &["-X", CHAIN]).await;
    }
    for pref in [PRIO_STEER, PRIO_REPLY] {
        for _ in 0..8 {
            if ip_rule(false, &["rule", "del", "pref", pref]).await != 0 {
                break;
            }
        }
    }
    ip_rule(false, &["route", "flush", "table", REPLY_TABLE]).await;
}

async fn watch(path: TetherPath) {
    let table = path.table();
    let mut applied: Vec<TetherIface> = Vec::new();
    loop {
        let enabled = read_settings().await.is_some_and(|s| s.proxy_tethering);
        let tun = read_iface(TUN_IFACE_FILE).await;
        let want = match (enabled, tun.as_deref()) {
            (true, Some(tun)) => wanted(true, detect(&[tun]).await),
            _ => Vec::new(),
        };
        if want != applied {
            clear_tethering().await;
            if let Some(tun) = tun.as_deref()
                && !want.is_empty()
            {
                // A native sing-box tun is not rp_filter-locked at bring-up.
                lock_tun_iface(tun).await;
                install(&tether_plan(&want, tun, &table)).await;
            }
            applied = want;
        }
        tokio::time::sleep(POLL).await;
    }
}

static WATCHER: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// Start watching the setting and the tethering interfaces for the running data
/// path. Replaces a previous watcher.
pub async fn start_tether_watcher(path: TetherPath) {
    stop_tether_watcher().await;
    let handle = tokio::spawn(watch(path));
    *WATCHER.lock().unwrap() = Some(handle);
}

/// Stop the watcher (the caller then runs the full teardown).
pub async fn stop_tether_watcher() {
    let handle = WATCHER.lock().unwrap().take();
    if let Some(h) = handle {
        h.abort();
        let _ = h.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, net: &str) -> TetherIface {
        TetherIface {
            name: name.into(),
            net: net.into(),
        }
    }

    fn flat(plan: &TetherPlan) -> Vec<String> {
        [
            &plan.ip_routes,
            &plan.ip_rules,
            &plan.filter4,
            &plan.filter6,
            &plan.nat4,
        ]
        .iter()
        .flat_map(|v| v.iter().map(|r| r.join(" ")))
        .collect()
    }

    #[test]
    fn off_emits_nothing() {
        let detected = vec![iface("wlan1", "192.168.43.0/24")];
        let want = wanted(false, detected);
        assert!(want.is_empty());
        assert!(tether_plan(&want, "tun0", "1100").is_empty());
    }

    #[test]
    fn on_steers_the_tether_iface_into_the_tun_and_back() {
        let plan = tether_plan(&[iface("wlan1", "192.168.43.0/24")], "tun0", "1100");
        let all = flat(&plan);
        assert_eq!(
            plan.ip_rules,
            [
                args(&[
                    "rule", "add", "iif", "wlan1", "lookup", "1100", "pref", "1015"
                ]),
                args(&[
                    "rule",
                    "add",
                    "iif",
                    "tun0",
                    "to",
                    "192.168.43.0/24",
                    "lookup",
                    "1102",
                    "pref",
                    "1016"
                ]),
            ]
        );
        assert_eq!(
            plan.ip_routes,
            [args(&[
                "route",
                "replace",
                "192.168.43.0/24",
                "dev",
                "wlan1",
                "table",
                "1102"
            ])]
        );
        assert!(all.contains(&"-i wlan1 -o tun0 -j ACCEPT".to_string()));
        assert!(all.contains(&"-i tun0 -o wlan1 -j ACCEPT".to_string()));
        assert!(
            all.contains(
                &"-i wlan1 -p udp --dport 53 -j DNAT --to-destination 1.1.1.1".to_string()
            )
        );
        assert!(
            all.contains(
                &"-i wlan1 -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1".to_string()
            )
        );
        assert!(all.contains(&"-i wlan1 -j REJECT --reject-with icmp6-no-route".to_string()));
    }

    #[test]
    fn native_path_looks_up_the_singbox_table() {
        assert_eq!(TetherPath::Native.table(), "2022");
        assert_eq!(TetherPath::External.table(), "1100");
    }

    #[test]
    fn no_rule_is_keyed_on_the_uplink() {
        // The uplink never reaches the plan builder; whatever tethering interfaces
        // and tun it is handed are the only interface names that can appear.
        let ifaces = [
            iface("wlan1", "192.168.43.0/24"),
            iface("rndis0", "192.168.42.0/24"),
        ];
        let plan = tether_plan(&ifaces, "tun0", "1100");
        let uplink_like = ["wlan0", "rmnet_data0", "eth0", "ccmni1"];
        for rule in flat(&plan) {
            for tok in rule.split_whitespace() {
                assert!(!uplink_like.contains(&tok), "{rule}");
            }
        }
        // Every iif/-i match names a tethering interface or the tun, nothing else.
        for r in plan.ip_rules.iter().chain(&plan.filter4).chain(&plan.nat4) {
            for w in r.windows(2) {
                if w[0] == "iif" || w[0] == "-i" {
                    assert!(
                        ["wlan1", "rndis0", "tun0"].contains(&w[1].as_str()),
                        "{r:?}"
                    );
                }
            }
        }
    }

    const ADDRS: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
5: wlan0    inet 192.168.1.37/24 brd 192.168.1.255 scope global wlan0\\       valid_lft forever
6: wlan1    inet 192.168.43.1/24 brd 192.168.43.255 scope global wlan1\\       valid_lft forever
7: rndis0    inet 192.168.42.129/24 brd 192.168.42.255 scope global rndis0\\       valid_lft forever
8: rmnet_data2    inet 10.20.30.1/24 scope global rmnet_data2\\       valid_lft forever
9: bt-pan    inet 192.168.44.1/24 brd 192.168.44.255 scope global bt-pan\\       valid_lft forever
10: ncm0    inet 172.20.5.1/24 brd 172.20.5.255 scope global ncm0\\       valid_lft forever
11: usb0    inet 8.8.8.1/24 scope global usb0\\       valid_lft forever
12: tun0    inet 10.10.0.1/24 scope global tun0\\       valid_lft forever
";

    #[test]
    fn detects_downstreams_by_name_and_gateway_address() {
        let got = parse_tether_ifaces(ADDRS, &["tun0"]);
        let names: Vec<&str> = got.iter().map(|t| t.name.as_str()).collect();
        // wlan0 is a station on a LAN (not the .1 of its /24), rndis0 is a client
        // lease, rmnet is an uplink name, usb0 is not private, tun0 is excluded.
        assert_eq!(names, ["bt-pan", "ncm0", "wlan1"]);
        assert_eq!(got[2].net, "192.168.43.0/24");
        assert_eq!(got[1].net, "172.20.5.0/24");
    }

    #[test]
    fn single_radio_hotspot_on_wlan0_is_found_unless_it_is_the_uplink() {
        let out = "5: wlan0    inet 192.168.43.1/24 brd 192.168.43.255 scope global wlan0\\\n";
        assert_eq!(parse_tether_ifaces(out, &[]).len(), 1);
        assert!(parse_tether_ifaces(out, &["wlan0"]).is_empty());
    }
}
