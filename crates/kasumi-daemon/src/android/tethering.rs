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
//! and reconciles the rules. While the option is on, Android's tethering offload is
//! held off ([`super::tether_offload`]), since offloaded packets never reach the
//! rules. Teardown ([`clear_tethering`]) always removes everything and restores
//! the offload setting, whatever the option says by then.

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::task::JoinHandle;

use kasumi_core::singbox_config::SINGBOX_MAIN_TABLE;

use super::paths::{IP, IP6TABLES, IPTABLES, TUN_IFACE_FILE};
use super::platform::{read_iface, read_settings};
use super::routing::{TUN_TABLE, ip_rule};
use super::sysctl::lock_tun_iface;
use super::tether_offload::{
    BpfHold, hold_tether_bpf, reconcile_hw_offload, release_all_tether_bpf, release_tether_bpf,
    restore_hw_offload,
};
use super::{default_uplink, run_out, silent};

/// Our own chain in `filter FORWARD` (accepts) and `nat PREROUTING` (DNS).
const CHAIN: &str = "KASUMI_PROXY_TETHER";
/// Our chain in IPv6 `filter INPUT`. Separate from [`CHAIN`], whose blanket IPv6
/// reject would also cut the clients' neighbour discovery with the phone.
const CHAIN_IN: &str = "KASUMI_PROXY_TETHER_IN";

/// A built-in chain that jumps to one of ours.
struct Hook {
    bin: &'static str,
    table: Option<&'static str>,
    hook: &'static str,
    chain: &'static str,
}

/// Every hook [`install`] uses, in the order of [`TetherPlan::sections`];
/// [`clear_rules`] removes all of them.
const HOOKS: [Hook; 4] = [
    Hook {
        bin: IPTABLES,
        table: None,
        hook: "FORWARD",
        chain: CHAIN,
    },
    Hook {
        bin: IP6TABLES,
        table: None,
        hook: "FORWARD",
        chain: CHAIN,
    },
    Hook {
        bin: IPTABLES,
        table: Some("nat"),
        hook: "PREROUTING",
        chain: CHAIN,
    },
    Hook {
        bin: IP6TABLES,
        table: None,
        hook: "INPUT",
        chain: CHAIN_IN,
    },
];
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
    /// The downstream's IPv4 subnet, e.g. `10.249.48.0/24`.
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
    /// `filter INPUT` chain, IPv6.
    pub input6: Vec<Vec<String>>,
}

impl TetherPlan {
    pub fn is_empty(&self) -> bool {
        self.ip_routes.is_empty()
            && self.ip_rules.is_empty()
            && self.sections().iter().all(|s| s.is_empty())
    }

    /// The iptables rules for each of [`HOOKS`].
    fn sections(&self) -> [&Vec<Vec<String>>; 4] {
        [&self.filter4, &self.filter6, &self.nat4, &self.input6]
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
        // With an IPv6 upstream, Tethering advertises the phone's own address on
        // the downstream as the DNS server (`IpServer.getLocalDnsIpFor`). That is
        // local delivery, which the IPv4-only redirect above cannot reach (the
        // kernel may lack IPv6 NAT), and the phone answers from the upstream's DNS.
        // Refuse it so clients fall back to their IPv4 resolver at once.
        for (proto, reply) in [("udp", "icmp6-port-unreachable"), ("tcp", "tcp-reset")] {
            plan.input6.push(args(&[
                "-i",
                name,
                "-p",
                proto,
                "--dport",
                "53",
                "-j",
                "REJECT",
                "--reject-with",
                reply,
            ]));
        }
    }
    plan
}

/// What to install: nothing unless the option is on.
fn wanted(enabled: bool, detected: Vec<TetherIface>) -> Vec<TetherIface> {
    if enabled { detected } else { Vec::new() }
}

/// `RULE_PRIORITY_TETHERING` in AOSP netd (`server/RouteController.h`). For every
/// downstream that shares the phone's connection, netd's
/// `RouteController::modifyTetheredNetwork` installs `iif <downstream> lookup
/// <upstream>` at this priority. The Tethering module asks for it together with the
/// `tetherctrl_FORWARD` pair (`RoutingCoordinatorService.addInterfaceForward`), so
/// it marks exactly the downstreams Android forwards. A local-only hotspot or a
/// Wi-Fi Direct group gets none.
const ANDROID_TETHER_PRIO: &str = "21000";

/// Downstream interfaces out of `ip -4 rule show`: the `iif` of every rule at
/// [`ANDROID_TETHER_PRIO`]. Names and addresses are no guide. Android 11+ picks a
/// random subnet and host address for each downstream, and the hotspot can be
/// `wlan0`, the name a Wi-Fi station has on other phones.
pub fn parse_tether_downstreams(rules_out: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in rules_out.lines() {
        let Some((pref, rest)) = line.split_once(':') else {
            continue;
        };
        if pref.trim() != ANDROID_TETHER_PRIO {
            continue;
        }
        let toks: Vec<&str> = rest.split_whitespace().collect();
        let Some(name) = toks.windows(2).find(|w| w[0] == "iif").map(|w| w[1]) else {
            continue;
        };
        if valid_ifname(name) && !found.iter().any(|f| f == name) {
            found.push(name.to_string());
        }
    }
    found.sort();
    found
}

/// Linux interface names are 1-15 bytes without `/` or whitespace.
fn valid_ifname(name: &str) -> bool {
    (1..16).contains(&name.len()) && !name.contains('/') && !name.contains(char::is_whitespace)
}

/// The IPv4 subnet of every address out of `ip -o -4 addr show`, as
/// `(iface, "a.b.c.d/n")` with the host bits cleared.
fn parse_iface_nets(addr_out: &str) -> Vec<(String, String)> {
    let mut nets = Vec::new();
    for line in addr_out.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = toks.iter().position(|t| *t == "inet") else {
            continue;
        };
        let (Some(name), Some(cidr)) = (toks.get(1), toks.get(i + 1)) else {
            continue;
        };
        let name = name.trim_end_matches(':').split('@').next().unwrap_or("");
        let Some((ip, prefix)) = cidr.split_once('/') else {
            continue;
        };
        let (Ok(ip), Ok(prefix)) = (ip.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
            continue;
        };
        if prefix > 32 {
            continue;
        }
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        let net = Ipv4Addr::from(u32::from(ip) & mask);
        nets.push((name.to_string(), format!("{net}/{prefix}")));
    }
    nets
}

/// The tethering downstreams with their subnets. A downstream without an IPv4
/// address yet waits for the next poll. `exclude` names interfaces that must never
/// qualify (the uplink, the tuns).
pub fn tether_ifaces(rules_out: &str, addr_out: &str, exclude: &[&str]) -> Vec<TetherIface> {
    let nets = parse_iface_nets(addr_out);
    parse_tether_downstreams(rules_out)
        .into_iter()
        .filter(|name| !exclude.contains(&name.as_str()))
        .filter_map(|name| {
            let net = nets.iter().find(|(n, _)| *n == name)?.1.clone();
            Some(TetherIface { name, net })
        })
        .collect()
}

/// The downstreams Android is tethering right now, given `ip -4 rule show`.
async fn detect(rules: &str, tuns: &[&str]) -> Vec<TetherIface> {
    if parse_tether_downstreams(rules).is_empty() {
        return Vec::new();
    }
    let uplink = default_uplink().await;
    let mut exclude: Vec<&str> = tuns.to_vec();
    if let Some(u) = uplink.as_deref() {
        exclude.push(u);
    }
    let (_, addrs) = run_out(&[IP, "-o", "-4", "addr", "show"]).await;
    tether_ifaces(rules, &addrs, &exclude)
}

/// Whether the rules [`install`] put in for `ifaces` are all still there, judged
/// from `ip -4 rule show`, `ip -4 route show table 1102` and whether the `FORWARD`
/// jump exists. The kernel drops a device's routes when the device goes away, so a
/// downstream recreated under the same name and subnet (tethering switched off and
/// on) comes back with the rules in place but table 1102 empty.
fn plan_in_place(
    ifaces: &[TetherIface],
    tun: &str,
    rules_out: &str,
    routes_out: &str,
    hooked: bool,
) -> bool {
    let rule_lines: Vec<(&str, Vec<&str>)> = rules_out
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(pref, rest)| (pref.trim(), rest.split_whitespace().collect()))
        .collect();
    let has_rule = |pref: &str, pairs: &[[&str; 2]]| {
        rule_lines.iter().any(|(p, toks)| {
            *p == pref
                && pairs
                    .iter()
                    .all(|pair| toks.windows(2).any(|w| w == pair.as_slice()))
        })
    };
    let has_route = |t: &TetherIface| {
        routes_out.lines().any(|l| {
            let toks: Vec<&str> = l.split_whitespace().collect();
            toks.starts_with(&[t.net.as_str(), "dev", t.name.as_str()])
        })
    };
    hooked
        && ifaces.iter().all(|t| {
            has_route(t)
                && has_rule(PRIO_STEER, &[["iif", &t.name]])
                && has_rule(PRIO_REPLY, &[["iif", tun], ["to", &t.net]])
        })
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
    for (h, rules) in HOOKS.iter().zip(plan.sections()) {
        let (bin, table, chain) = (h.bin, h.table, h.chain);
        ipt(bin, table, &["-N", chain]).await;
        ipt(bin, table, &["-F", chain]).await;
        for r in rules {
            let mut a = vec!["-A", chain];
            a.extend(r.iter().map(String::as_str));
            ipt(bin, table, &a).await;
        }
        while ipt(bin, table, &["-D", h.hook, "-j", chain]).await == 0 {}
        ipt(bin, table, &["-I", h.hook, "1", "-j", chain]).await;
    }
}

/// Remove everything [`install`] adds, in any state. Safe to call when nothing
/// was installed.
async fn clear_rules() {
    for h in &HOOKS {
        while ipt(h.bin, h.table, &["-D", h.hook, "-j", h.chain]).await == 0 {}
        ipt(h.bin, h.table, &["-F", h.chain]).await;
        ipt(h.bin, h.table, &["-X", h.chain]).await;
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

/// Data-path teardown: remove the rules, hand BPF offload back and give the
/// offload setting back.
pub async fn clear_tethering() {
    clear_rules().await;
    release_all_tether_bpf().await;
    restore_hw_offload().await;
}

/// The interfaces held from BPF offload that are no longer steered.
fn departed(held: &[(String, BpfHold)], applied: &[TetherIface]) -> Vec<String> {
    held.iter()
        .filter(|(name, _)| !applied.iter().any(|t| t.name == *name))
        .map(|(name, _)| name.clone())
        .collect()
}

async fn watch(path: TetherPath) {
    let table = path.table();
    let mut applied: Vec<TetherIface> = Vec::new();
    let mut held: Vec<(String, BpfHold)> = Vec::new();
    loop {
        let enabled = read_settings().await.is_some_and(|s| s.proxy_tethering);
        let tun = read_iface(TUN_IFACE_FILE).await;
        let tun = tun.as_deref().filter(|_| enabled);
        let rules = match tun {
            Some(_) => run_out(&[IP, "-4", "rule", "show"]).await.1,
            None => String::new(),
        };
        let want = match tun {
            Some(tun) => wanted(true, detect(&rules, &[tun]).await),
            None => Vec::new(),
        };
        // Kept off whenever the option is on, so a hotspot started later comes up
        // without hardware offload.
        if tun.is_some() {
            reconcile_hw_offload().await;
        } else {
            restore_hw_offload().await;
        }
        let intact = match tun {
            Some(tun) if want == applied && !applied.is_empty() => {
                let (_, routes) = run_out(&[IP, "-4", "route", "show", "table", REPLY_TABLE]).await;
                let hooked = ipt(IPTABLES, None, &["-C", "FORWARD", "-j", CHAIN]).await == 0;
                plan_in_place(&applied, tun, &rules, &routes, hooked)
            }
            _ => want == applied,
        };
        if !intact {
            clear_rules().await;
            if let Some(tun) = tun
                && !want.is_empty()
            {
                // A native sing-box tun is not rp_filter-locked at bring-up.
                lock_tun_iface(tun).await;
                install(&tether_plan(&want, tun, &table)).await;
            }
            applied = want;
        }
        for name in departed(&held, &applied) {
            release_tether_bpf(&name).await;
        }
        let mut now = Vec::with_capacity(applied.len());
        for t in &applied {
            let hold = hold_tether_bpf(&t.name).await;
            if !held.contains(&(t.name.clone(), hold)) {
                match hold {
                    BpfHold::Pinned => log::info!("tethering: BPF offload held off on {}", t.name),
                    BpfHold::Detached => log::warn!(
                        "tethering: cannot add the tc filter on {}, removing BPF \
                         offload programs on every poll",
                        t.name
                    ),
                }
            }
            now.push((t.name.clone(), hold));
        }
        held = now;
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
            &plan.input6,
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

    // `ip -o -4 addr show` and `ip -4 rule show` on a motorola edge 70 (Android 16)
    // with USB tethering on and a native sing-box tun up.
    const USB_ADDRS: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
18: rmnet_data1    inet 30.87.229.51/29 scope global rmnet_data1\\       valid_lft forever preferred_lft forever
28: rmnet_data3    inet 100.78.31.181/30 scope global rmnet_data3\\       valid_lft forever preferred_lft forever
31: p2fbf546d    inet 198.18.0.1/15 brd 198.19.255.255 scope global p2fbf546d\\       valid_lft forever preferred_lft forever
32: rndis0    inet 10.249.48.65/24 brd 10.249.48.255 scope global rndis0\\       valid_lft forever preferred_lft forever
";
    const USB_RULES: &str = "\
11000:\tfrom all iif lo oif rndis0 uidrange 0-0 lookup rndis0 
16000:\tfrom all fwmark 0x10063/0x1ffff iif lo lookup local_network 
16000:\tfrom all fwmark 0x10068/0x1ffff iif lo lookup rndis0 
16000:\tfrom all fwmark 0x10063/0x1ffff iif lo lookup rndis0 
17000:\tfrom all iif lo oif rndis0 lookup rndis0 
20000:\tfrom all fwmark 0x0/0x10000 lookup local_network 
20000:\tfrom all fwmark 0x0/0x10000 lookup rndis0 
21000:\tfrom all iif rndis0 lookup rmnet_data3 
23000:\tfrom all fwmark 0x68/0x1ffff iif lo lookup rndis0 
";

    // The same phone with the Wi-Fi hotspot on instead: the hotspot is `wlan0`.
    const WIFI_ADDRS: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
18: rmnet_data1    inet 30.87.229.51/29 scope global rmnet_data1\\       valid_lft forever preferred_lft forever
25: wlan0    inet 10.183.251.42/24 brd 10.183.251.255 scope global wlan0\\       valid_lft forever preferred_lft forever
28: rmnet_data3    inet 100.78.31.181/30 scope global rmnet_data3\\       valid_lft forever preferred_lft forever
31: p2fbf546d    inet 198.18.0.1/15 brd 198.19.255.255 scope global p2fbf546d\\       valid_lft forever preferred_lft forever
";
    const WIFI_RULES: &str = "21000:\tfrom all iif wlan0 lookup rmnet_data3 \n";

    #[test]
    fn detects_usb_tethering_with_a_random_host_address() {
        let got = tether_ifaces(USB_RULES, USB_ADDRS, &["p2fbf546d", "rmnet_data3"]);
        assert_eq!(got, [iface("rndis0", "10.249.48.0/24")]);
    }

    #[test]
    fn detects_a_wifi_hotspot_on_wlan0() {
        let got = tether_ifaces(WIFI_RULES, WIFI_ADDRS, &["p2fbf546d", "rmnet_data3"]);
        assert_eq!(got, [iface("wlan0", "10.183.251.0/24")]);
    }

    #[test]
    fn wlan0_as_a_wifi_station_is_not_a_downstream() {
        // A phone on someone's Wi-Fi, no tethering: wlan0 holds a DHCP lease and no
        // tethering rule names it.
        let addrs = "5: wlan0    inet 192.168.1.1/24 brd 192.168.1.255 scope global wlan0\\\n";
        let rules = "\
20000:\tfrom all fwmark 0x0/0x10000 lookup local_network 
22000:\tfrom all fwmark 0x10064/0x1ffff iif lo uidrange 0-99999 lookup wlan0 
";
        assert!(tether_ifaces(rules, addrs, &[]).is_empty());
    }

    #[test]
    fn only_android_tethering_rules_name_downstreams() {
        // Our own steering rule and the OS's per-network rules never count.
        let rules = "\
1015:\tfrom all iif rndis0 lookup 2022 
17000:\tfrom all iif lo oif wlan1 lookup wlan1 
21000:\tfrom all iif bt-pan lookup rmnet_data3 
21000:\tfrom all iif wlan1 lookup rmnet_data3 [detached] 
";
        assert_eq!(parse_tether_downstreams(rules), ["bt-pan", "wlan1"]);
    }

    #[test]
    fn a_downstream_without_an_address_waits() {
        assert!(tether_ifaces(USB_RULES, WIFI_ADDRS, &[]).is_empty());
    }

    #[test]
    fn the_uplink_and_the_tun_never_qualify() {
        let rules = "21000:\tfrom all iif rmnet_data3 lookup rmnet_data3 \n";
        assert!(tether_ifaces(rules, USB_ADDRS, &["p2fbf546d", "rmnet_data3"]).is_empty());
    }

    #[test]
    fn subnet_keeps_the_kernel_prefix() {
        let addrs = "9: ap0    inet 172.20.5.77/20 scope global ap0\\\n";
        let rules = "21000:\tfrom all iif ap0 lookup wlan0 \n";
        assert_eq!(
            tether_ifaces(rules, addrs, &[]),
            [iface("ap0", "172.20.0.0/20")]
        );
    }

    #[test]
    fn plan_for_the_captured_usb_layout() {
        let ifaces = tether_ifaces(USB_RULES, USB_ADDRS, &["p2fbf546d", "rmnet_data3"]);
        let plan = tether_plan(&ifaces, "p2fbf546d", &TetherPath::Native.table());
        assert_eq!(
            flat(&plan),
            [
                "route replace 10.249.48.0/24 dev rndis0 table 1102",
                "rule add iif rndis0 lookup 2022 pref 1015",
                "rule add iif p2fbf546d to 10.249.48.0/24 lookup 1102 pref 1016",
                "-i rndis0 -o p2fbf546d -j ACCEPT",
                "-i p2fbf546d -o rndis0 -j ACCEPT",
                "-i rndis0 -j REJECT --reject-with icmp6-no-route",
                "-i rndis0 -p udp --dport 53 -j DNAT --to-destination 1.1.1.1",
                "-i rndis0 -p tcp --dport 53 -j DNAT --to-destination 1.1.1.1",
                "-i rndis0 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable",
                "-i rndis0 -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
            ]
        );
    }

    #[test]
    fn ipv6_dns_to_the_phone_is_refused_on_every_downstream() {
        let ifaces = [
            iface("rndis0", "10.249.48.0/24"),
            iface("wlan0", "10.183.251.0/24"),
        ];
        let plan = tether_plan(&ifaces, "p2fbf546d", "2022");
        let input6: Vec<String> = plan.input6.iter().map(|r| r.join(" ")).collect();
        assert_eq!(
            input6,
            [
                "-i rndis0 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable",
                "-i rndis0 -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
                "-i wlan0 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable",
                "-i wlan0 -p tcp --dport 53 -j REJECT --reject-with tcp-reset",
            ]
        );
        // Only DNS: the clients' neighbour discovery with the phone stays open.
        assert!(plan.input6.iter().all(|r| r.contains(&"53".to_string())));
    }

    #[test]
    fn every_rule_lands_in_a_chain_that_teardown_removes() {
        let ifaces = [
            iface("rndis0", "10.249.48.0/24"),
            iface("wlan0", "10.183.251.0/24"),
        ];
        let plan = tether_plan(&ifaces, "p2fbf546d", "2022");
        // install() fills HOOKS[i] from sections()[i], clear_rules() walks HOOKS.
        for (h, rules) in HOOKS.iter().zip(plan.sections()) {
            assert!(!rules.is_empty(), "{} {}", h.bin, h.hook);
        }
        let mut hooks: Vec<_> = HOOKS.iter().map(|h| (h.bin, h.table, h.hook)).collect();
        hooks.sort();
        hooks.dedup();
        assert_eq!(hooks.len(), HOOKS.len());
        // The IPv6 INPUT jump must not reach the FORWARD chain's blanket reject.
        let input = HOOKS.iter().find(|h| h.hook == "INPUT").unwrap();
        assert_ne!(input.chain, CHAIN);
    }

    // USB tethering switched off and on with the option on (reported from the
    // device): rndis0 came back with the same name and subnet, the rules stayed,
    // but the kernel had dropped its route from table 1102.
    const RECREATED_RULES: &str = "\
1015:\tfrom all iif rndis0 lookup 2022 
1016:\tfrom all iif p2fbf546d to 10.173.7.0/24 lookup 1102 
9000:\tfrom all uidrange 0-0 goto 9010 
9001:\tfrom all iif p2fbf546d goto 9010 
21000:\tfrom all iif rndis0 lookup rmnet_data3 
";
    const REPLY_ROUTES: &str = "10.173.7.0/24 dev rndis0 scope link \n";

    #[test]
    fn a_recreated_downstream_is_reinstalled() {
        let applied = [iface("rndis0", "10.173.7.0/24")];
        assert!(!plan_in_place(
            &applied,
            "p2fbf546d",
            RECREATED_RULES,
            "",
            true
        ));
        assert!(plan_in_place(
            &applied,
            "p2fbf546d",
            RECREATED_RULES,
            REPLY_ROUTES,
            true
        ));
    }

    #[test]
    fn a_missing_rule_or_forward_jump_is_reinstalled() {
        let applied = [iface("rndis0", "10.173.7.0/24")];
        let no_reply = RECREATED_RULES.replace("1016:", "1017:");
        let no_steer = RECREATED_RULES.replace("1015:", "1014:");
        for rules in [no_reply.as_str(), no_steer.as_str()] {
            assert!(!plan_in_place(
                &applied,
                "p2fbf546d",
                rules,
                REPLY_ROUTES,
                true
            ));
        }
        assert!(!plan_in_place(
            &applied,
            "p2fbf546d",
            RECREATED_RULES,
            REPLY_ROUTES,
            false
        ));
    }

    #[test]
    fn a_downstream_that_stops_being_steered_is_released() {
        let held = [
            ("rndis0".to_string(), BpfHold::Pinned),
            ("wlan0".to_string(), BpfHold::Detached),
        ];
        let applied = [iface("wlan0", "10.183.251.0/24")];
        assert_eq!(departed(&held, &applied), ["rndis0"]);
        assert_eq!(departed(&held, &[]), ["rndis0", "wlan0"]);
        assert!(departed(&[], &applied).is_empty());
    }

    #[test]
    fn the_route_must_point_at_the_downstream() {
        let applied = [iface("rndis0", "10.173.7.0/24")];
        let elsewhere = "10.173.7.0/24 dev wlan0 scope link \n";
        assert!(!plan_in_place(
            &applied,
            "p2fbf546d",
            RECREATED_RULES,
            elsewhere,
            true
        ));
    }
}
