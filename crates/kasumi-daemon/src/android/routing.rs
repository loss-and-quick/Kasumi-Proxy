//! Packet routing for the xray data-path: iptables marking + ip rules/tables +
//! fwmark. sing-box manages its own tun via auto_route, so these run for xray only.

use std::collections::BTreeMap;

use kasumi_backend::lifecycle::orphaned_tun_rules;
use kasumi_core::state::{AppCaptureMode, AppFilterMode, app_filter_uid};
use kasumi_core::tun::{TUN_IPV4_CIDR, TUN_IPV6_CIDR, TUN2_IPV4_CIDR, TUN2_IPV6_CIDR};

use super::paths::{IP, IP6TABLES, IPTABLES};
use super::tethering::clear_tethering;
use super::{run_out, silent};

pub const FWMARK: u32 = 255;
const LEGACY_MARK_RULE_PRIORITY: &str = "1000";
const MARK_CHAIN: &str = "KASUMI_PROXY_MARK";

// Our own route-table numbers (v4 and v6 share them).
pub(super) const TUN_TABLE: &str = "1100";
const TUN_TABLE_FORCE: &str = "1101";
const PRIO_TUN: &str = "1010";
const PRIO_TUN_FORCE: &str = "1011";

// Priority of the `iif <uplink> lookup <uplink>` rule older versions installed
// under sing-box strict_route. Only removed now (see `clear_legacy_strict_carveouts`).
const STRICT_CARVEOUT_PREF: &str = "8500";

/// The per-app capture configuration the routing rules are built from.
pub struct AppFilter {
    pub capture_mode: AppCaptureMode,
    /// `"pkg:uid"` → mode.
    pub entries: BTreeMap<String, AppFilterMode>,
    /// Kill-switch: mark every uid but root, not just system + apps.
    pub strict: bool,
}

pub struct RoutingState {
    pub tun_iface: Option<String>,
    pub tun2_iface: Option<String>,
    pub filter: AppFilter,
    pub socks_port: u16,
    pub http_port: u16,
}

fn uid_of(key: &str) -> Option<String> {
    app_filter_uid(key).map(|u| u.to_string())
}

/// Delete the sing-box tun rules a helper that died uncleanly left behind, in both
/// families (see [`orphaned_tun_rules`]).
pub async fn clear_orphaned_tun_rules() {
    for v6 in [false, true] {
        let family = if v6 { "-6" } else { "-4" };
        let (_, listing) = run_out(&[IP, family, "rule", "show"]).await;
        for del in orphaned_tun_rules(&listing) {
            let args: Vec<&str> = del.iter().map(String::as_str).collect();
            ip_rule(v6, &args).await;
        }
    }
}

/// `ip [-6] <args>`.
pub(super) async fn ip_rule(v6: bool, args: &[&str]) -> i32 {
    let mut a: Vec<&str> = vec![IP];
    if v6 {
        a.push("-6");
    }
    a.extend_from_slice(args);
    silent(&a).await
}

async fn mark_uid(ipt: &str, range: &str) {
    silent(&[
        ipt,
        "-t",
        "mangle",
        "-A",
        MARK_CHAIN,
        "-m",
        "owner",
        "--uid-owner",
        range,
        "-j",
        "MARK",
        "--set-xmark",
        "1",
    ])
    .await;
}

/// Append the catch-all uid capture: strict marks every uid but root (1-max);
/// otherwise capture "all" marks system (1000) + apps (9999+). Per-uid bypass /
/// force-proxy rules and the local/REPLY exclusions are added before this, so they
/// take precedence. capture "none" adds nothing.
async fn capture_mark_rules(ipt: &str, filter: &AppFilter) {
    if filter.strict {
        mark_uid(ipt, "1-2147483647").await;
    } else if filter.capture_mode == AppCaptureMode::All {
        mark_uid(ipt, "1000").await;
        mark_uid(ipt, "9999-2147483647").await;
    }
}

/// Older versions pinned packets arriving on the uplink back to the uplink table
/// under sing-box strict_route. That rule also caught the de-NATed replies for
/// hotspot/USB-tethering clients and sent them back out the uplink, so tethered
/// devices lost internet. It is no longer needed: `tune_config` excludes uid 0 from
/// the tun, and the kernel routes forwarded packets (and their rp_filter checks) as
/// uid 0, so they already skip sing-box's strict rule. Removed on teardown only, to
/// clean up after an upgrade.
async fn clear_legacy_strict_carveouts() {
    for v6 in [false, true] {
        for _ in 0..4 {
            if ip_rule(v6, &["rule", "del", "pref", STRICT_CARVEOUT_PREF]).await != 0 {
                break;
            }
        }
    }
}

/// Older versions pinned an `fwmark 255` rule to the uplink table, carried over
/// from the shell module, where Xray marked its sockets 255. No config marks the
/// cores' sockets now (they leave as uid 0), and the tun helpers' marked sockets
/// only reach the local SOCKS port. Removed on teardown only, to clean up after an
/// upgrade.
async fn clear_legacy_mark_rule() {
    for v6 in [false, true] {
        ip_rule(
            v6,
            &[
                "rule",
                "del",
                "fwmark",
                "255",
                "priority",
                LEGACY_MARK_RULE_PRIORITY,
            ],
        )
        .await;
    }
}

async fn app_uid_rules(ipt: &str, filter: &AppFilter) {
    for (key, mode) in &filter.entries {
        let Some(uid) = uid_of(key) else {
            continue;
        };
        match mode {
            AppFilterMode::Bypass => {
                silent(&[
                    ipt,
                    "-t",
                    "mangle",
                    "-A",
                    MARK_CHAIN,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &uid,
                    "-j",
                    "RETURN",
                ])
                .await;
            }
            AppFilterMode::ForceProxy => {
                silent(&[
                    ipt,
                    "-t",
                    "mangle",
                    "-A",
                    MARK_CHAIN,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &uid,
                    "-j",
                    "MARK",
                    "--set-xmark",
                    "2",
                ])
                .await;
                silent(&[
                    ipt,
                    "-t",
                    "mangle",
                    "-A",
                    MARK_CHAIN,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &uid,
                    "-j",
                    "RETURN",
                ])
                .await;
            }
        }
    }
}

async fn local_ipv4_exclusions() {
    for cidr in [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
    ] {
        silent(&[
            IPTABLES, "-t", "mangle", "-A", MARK_CHAIN, "-d", cidr, "-j", "RETURN",
        ])
        .await;
    }
}

async fn local_ipv6_exclusions() {
    for cidr in ["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"] {
        silent(&[
            IP6TABLES, "-t", "mangle", "-A", MARK_CHAIN, "-d", cidr, "-j", "RETURN",
        ])
        .await;
    }
}

/// Filter-table chain holding the per-app guards (see [`guard_rules`]), hooked
/// from `OUTPUT` and rebuilt whole whenever the data path starts or the app filter
/// changes, so a removed app never keeps a stale rule.
const GUARD_CHAIN: &str = "KASUMI_PROXY_GUARD";

/// The guards an app outside the proxy must not get around, for one iptables
/// family. Each entry is the argument list of one `-A GUARD_CHAIN` rule.
///
/// - A bypass-mode app is refused on the local proxy ports (socks, http and the
///   always-noauth force-in), so it can't learn the proxy's exit address by
///   dialing the core itself.
/// - An app the filter keeps off the tun can still ask for it by name or index
///   (`SO_BINDTODEVICE`, unprivileged since Linux 5.7): routing never runs for
///   such a socket, so its packets would reach the core all the same. Packets
///   leaving through a tun are dropped for those uids — the bypass list in
///   capture-all mode; in capture-none mode everything but the force-proxy apps
///   and root (the daemon). `--socket-exists` keeps packets with no owning socket
///   (a kernel reply for a closed connection) out of that catch-all.
fn guard_rules(filter: &AppFilter, ports: &[u16], tuns: &[&str]) -> Vec<Vec<String>> {
    let uids = |want: AppFilterMode| -> Vec<String> {
        filter
            .entries
            .iter()
            .filter(|(_, m)| **m == want)
            .filter_map(|(k, _)| uid_of(k))
            .collect()
    };
    let bypass = uids(AppFilterMode::Bypass);
    let rule = |parts: &[&str]| parts.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut rules = Vec::new();
    for uid in &bypass {
        for port in ports {
            let port = port.to_string();
            rules.push(rule(&[
                "-o",
                "lo",
                "-p",
                "tcp",
                "--dport",
                &port,
                "-m",
                "owner",
                "--uid-owner",
                uid,
                "-j",
                "REJECT",
                "--reject-with",
                "tcp-reset",
            ]));
        }
    }
    for tun in tuns {
        match filter.capture_mode {
            AppCaptureMode::All => {
                for uid in &bypass {
                    rules.push(rule(&[
                        "-o",
                        tun,
                        "-m",
                        "owner",
                        "--uid-owner",
                        uid,
                        "-j",
                        "DROP",
                    ]));
                }
            }
            AppCaptureMode::None => {
                let force = uids(AppFilterMode::ForceProxy);
                let allowed = std::iter::once("0").chain(force.iter().map(String::as_str));
                for uid in allowed {
                    rules.push(rule(&[
                        "-o",
                        tun,
                        "-m",
                        "owner",
                        "--uid-owner",
                        uid,
                        "-j",
                        "ACCEPT",
                    ]));
                }
                rules.push(rule(&[
                    "-o",
                    tun,
                    "-m",
                    "owner",
                    "--socket-exists",
                    "-j",
                    "DROP",
                ]));
            }
        }
    }
    rules
}

/// Install (or refresh) the per-app guards for both families. The tun names are
/// the running data path's; `ports` are its local proxy ports.
pub async fn apply_guards(filter: &AppFilter, ports: &[u16], tuns: &[&str]) {
    for ipt in [IPTABLES, IP6TABLES] {
        silent(&[ipt, "-N", GUARD_CHAIN]).await;
        silent(&[ipt, "-F", GUARD_CHAIN]).await;
        while silent(&[ipt, "-D", "OUTPUT", "-j", GUARD_CHAIN]).await == 0 {}
        silent(&[ipt, "-I", "OUTPUT", "-j", GUARD_CHAIN]).await;
        for r in guard_rules(filter, ports, tuns) {
            let mut args = vec![ipt, "-A", GUARD_CHAIN];
            args.extend(r.iter().map(String::as_str));
            silent(&args).await;
        }
    }
}

async fn clear_guards() {
    for ipt in [IPTABLES, IP6TABLES] {
        while silent(&[ipt, "-D", "OUTPUT", "-j", GUARD_CHAIN]).await == 0 {}
        silent(&[ipt, "-F", GUARD_CHAIN]).await;
        silent(&[ipt, "-X", GUARD_CHAIN]).await;
    }
}

/// Older versions added the bypass-app port rejects straight to `OUTPUT`, one
/// rule per uid and port. Removed on teardown only, to clean up after an upgrade.
async fn clear_legacy_port_rules(filter: &AppFilter, socks_port: u16, http_port: u16) {
    for (key, mode) in &filter.entries {
        if *mode != AppFilterMode::Bypass {
            continue;
        }
        let Some(uid) = uid_of(key) else {
            continue;
        };
        for port in [socks_port.to_string(), http_port.to_string()] {
            for ipt in [IPTABLES, IP6TABLES] {
                silent(&[
                    ipt,
                    "-D",
                    "OUTPUT",
                    "-o",
                    "lo",
                    "-p",
                    "tcp",
                    "--dport",
                    &port,
                    "-m",
                    "owner",
                    "--uid-owner",
                    &uid,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ])
                .await;
            }
        }
    }
}

/// Tear down every rule/table/device the xray data-path installed.
pub async fn clear_routing_rules(st: &RoutingState) {
    clear_legacy_mark_rule().await;
    clear_legacy_strict_carveouts().await;
    clear_guards().await;
    // Whatever the tethering option installed, whether or not it is on right now:
    // the setting may have been flipped while the data path ran.
    clear_tethering().await;
    clear_legacy_port_rules(&st.filter, st.socks_port, st.http_port).await;

    // IPv4 mark chain
    silent(&[IPTABLES, "-t", "mangle", "-D", "OUTPUT", "-j", MARK_CHAIN]).await;
    silent(&[IPTABLES, "-t", "mangle", "-F", MARK_CHAIN]).await;
    silent(&[IPTABLES, "-t", "mangle", "-X", MARK_CHAIN]).await;
    ip_rule(
        false,
        &[
            "rule", "del", "fwmark", "1", "table", TUN_TABLE, "priority", PRIO_TUN,
        ],
    )
    .await;
    ip_rule(
        false,
        &[
            "rule",
            "del",
            "fwmark",
            "2",
            "table",
            TUN_TABLE_FORCE,
            "priority",
            PRIO_TUN_FORCE,
        ],
    )
    .await;
    ip_rule(
        true,
        &[
            "rule",
            "del",
            "fwmark",
            "2",
            "table",
            TUN_TABLE_FORCE,
            "priority",
            PRIO_TUN_FORCE,
        ],
    )
    .await;

    // Older versions sent every RFC1918 source to the tun table (5030-5050, the
    // shell module's hotspot capture, now done per tethering interface) and local
    // ones to the uplink's table (5020-5022). Named after the uplink of the moment,
    // the latter sent Wi-Fi-sourced traffic out the mobile link after a switch, so
    // Android could no longer validate Wi-Fi. Removed on teardown only, to clean
    // up after an upgrade; the band is ours (the OS lives at pref 10000+) and the
    // loop clears any stacked duplicate.
    for pref in ["5020", "5021", "5022", "5030", "5040", "5050"] {
        for _ in 0..4 {
            if ip_rule(false, &["rule", "del", "pref", pref]).await != 0 {
                break;
            }
        }
    }
    for table in [TUN_TABLE, TUN_TABLE_FORCE] {
        ip_rule(false, &["route", "flush", "table", table]).await;
        ip_rule(true, &["route", "flush", "table", table]).await;
    }
    if let Some(tun) = &st.tun_iface {
        silent(&[IPTABLES, "-D", "FORWARD", "-o", tun, "-j", "ACCEPT"]).await;
        silent(&[IPTABLES, "-D", "FORWARD", "-i", tun, "-j", "ACCEPT"]).await;
        silent(&[
            IPTABLES,
            "-t",
            "mangle",
            "-D",
            "FORWARD",
            "-o",
            tun,
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,RST",
            "SYN",
            "-j",
            "TCPMSS",
            "--set-mss",
            "1350",
        ])
        .await;
    }
    if let Some(tun2) = &st.tun2_iface {
        silent(&[IPTABLES, "-D", "FORWARD", "-o", tun2, "-j", "ACCEPT"]).await;
        silent(&[IPTABLES, "-D", "FORWARD", "-i", tun2, "-j", "ACCEPT"]).await;
        silent(&[IP, "link", "delete", "dev", tun2]).await;
    }

    // IPv6 mark chain
    silent(&[IP6TABLES, "-t", "mangle", "-D", "OUTPUT", "-j", MARK_CHAIN]).await;
    silent(&[IP6TABLES, "-t", "mangle", "-F", MARK_CHAIN]).await;
    silent(&[IP6TABLES, "-t", "mangle", "-X", MARK_CHAIN]).await;
    ip_rule(
        true,
        &[
            "rule", "del", "fwmark", "1", "table", TUN_TABLE, "priority", PRIO_TUN,
        ],
    )
    .await;
    silent(&[
        IP6TABLES,
        "-D",
        "FORWARD",
        "-j",
        "REJECT",
        "--reject-with",
        "icmp6-no-route",
    ])
    .await;

    if let Some(tun) = &st.tun_iface {
        silent(&[IP, "link", "delete", "dev", tun]).await;
    }
}

/// Bring up tun device addresses/routes/rules and the xray marking chain.
pub async fn apply_external_tun_routing(st: &RoutingState) {
    let Some(tun) = st.tun_iface.as_deref() else {
        return;
    };
    let tun2 = st.tun2_iface.as_deref();

    silent(&[IP, "addr", "add", TUN_IPV4_CIDR, "dev", tun]).await;
    silent(&[IP, "link", "set", "dev", tun, "up"]).await;
    silent(&[
        IP, "route", "replace", "default", "dev", tun, "table", TUN_TABLE,
    ])
    .await;
    ip_rule(
        false,
        &[
            "rule", "del", "fwmark", "1", "table", TUN_TABLE, "priority", PRIO_TUN,
        ],
    )
    .await;
    ip_rule(
        false,
        &[
            "rule", "add", "fwmark", "1", "table", TUN_TABLE, "priority", PRIO_TUN,
        ],
    )
    .await;
    if let Some(tun2) = tun2 {
        silent(&[IP, "addr", "add", TUN2_IPV4_CIDR, "dev", tun2]).await;
        silent(&[IP, "link", "set", "dev", tun2, "up"]).await;
        silent(&[
            IP,
            "route",
            "replace",
            "default",
            "dev",
            tun2,
            "table",
            TUN_TABLE_FORCE,
        ])
        .await;
        ip_rule(
            false,
            &[
                "rule",
                "del",
                "fwmark",
                "2",
                "table",
                TUN_TABLE_FORCE,
                "priority",
                PRIO_TUN_FORCE,
            ],
        )
        .await;
        ip_rule(
            false,
            &[
                "rule",
                "add",
                "fwmark",
                "2",
                "table",
                TUN_TABLE_FORCE,
                "priority",
                PRIO_TUN_FORCE,
            ],
        )
        .await;
    }

    // IPv4 marking chain
    silent(&[IPTABLES, "-t", "mangle", "-F", MARK_CHAIN]).await;
    silent(&[IPTABLES, "-t", "mangle", "-D", "OUTPUT", "-j", MARK_CHAIN]).await;
    silent(&[IPTABLES, "-t", "mangle", "-X", MARK_CHAIN]).await;
    silent(&[IPTABLES, "-t", "mangle", "-N", MARK_CHAIN]).await;
    silent(&[
        IPTABLES, "-t", "mangle", "-A", MARK_CHAIN, "-m", "mark", "--mark", "255", "-j", "RETURN",
    ])
    .await;
    silent(&[
        IPTABLES,
        "-t",
        "mangle",
        "-A",
        MARK_CHAIN,
        "-m",
        "conntrack",
        "--ctdir",
        "REPLY",
        "-j",
        "RETURN",
    ])
    .await;
    local_ipv4_exclusions().await;
    app_uid_rules(IPTABLES, &st.filter).await;
    capture_mark_rules(IPTABLES, &st.filter).await;
    silent(&[IPTABLES, "-t", "mangle", "-A", "OUTPUT", "-j", MARK_CHAIN]).await;
    silent(&[IPTABLES, "-I", "FORWARD", "-o", tun, "-j", "ACCEPT"]).await;
    silent(&[IPTABLES, "-I", "FORWARD", "-i", tun, "-j", "ACCEPT"]).await;
    silent(&[
        IPTABLES,
        "-t",
        "mangle",
        "-I",
        "FORWARD",
        "-o",
        tun,
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
        "-j",
        "TCPMSS",
        "--set-mss",
        "1350",
    ])
    .await;

    // IPv6 addresses/routes + marking chain
    silent(&[IP, "-6", "addr", "add", TUN_IPV6_CIDR, "dev", tun]).await;
    silent(&[IP, "-6", "link", "set", "dev", tun, "up"]).await;
    silent(&[
        IP, "-6", "route", "replace", "default", "dev", tun, "table", TUN_TABLE,
    ])
    .await;
    ip_rule(
        true,
        &[
            "rule", "del", "fwmark", "1", "table", TUN_TABLE, "priority", PRIO_TUN,
        ],
    )
    .await;
    ip_rule(
        true,
        &[
            "rule", "add", "fwmark", "1", "table", TUN_TABLE, "priority", PRIO_TUN,
        ],
    )
    .await;
    if let Some(tun2) = tun2 {
        silent(&[IP, "-6", "addr", "add", TUN2_IPV6_CIDR, "dev", tun2]).await;
        silent(&[IP, "-6", "link", "set", "dev", tun2, "up"]).await;
        silent(&[
            IP,
            "-6",
            "route",
            "replace",
            "default",
            "dev",
            tun2,
            "table",
            TUN_TABLE_FORCE,
        ])
        .await;
        ip_rule(
            true,
            &[
                "rule",
                "del",
                "fwmark",
                "2",
                "table",
                TUN_TABLE_FORCE,
                "priority",
                PRIO_TUN_FORCE,
            ],
        )
        .await;
        ip_rule(
            true,
            &[
                "rule",
                "add",
                "fwmark",
                "2",
                "table",
                TUN_TABLE_FORCE,
                "priority",
                PRIO_TUN_FORCE,
            ],
        )
        .await;
    }
    silent(&[IP6TABLES, "-t", "mangle", "-F", MARK_CHAIN]).await;
    silent(&[IP6TABLES, "-t", "mangle", "-D", "OUTPUT", "-j", MARK_CHAIN]).await;
    silent(&[IP6TABLES, "-t", "mangle", "-X", MARK_CHAIN]).await;
    silent(&[IP6TABLES, "-t", "mangle", "-N", MARK_CHAIN]).await;
    silent(&[
        IP6TABLES, "-t", "mangle", "-A", MARK_CHAIN, "-m", "mark", "--mark", "255", "-j", "RETURN",
    ])
    .await;
    silent(&[
        IP6TABLES,
        "-t",
        "mangle",
        "-A",
        MARK_CHAIN,
        "-m",
        "conntrack",
        "--ctdir",
        "REPLY",
        "-j",
        "RETURN",
    ])
    .await;
    local_ipv6_exclusions().await;
    app_uid_rules(IP6TABLES, &st.filter).await;
    capture_mark_rules(IP6TABLES, &st.filter).await;
    silent(&[IP6TABLES, "-t", "mangle", "-A", "OUTPUT", "-j", MARK_CHAIN]).await;
    silent(&[
        IP6TABLES,
        "-I",
        "FORWARD",
        "-j",
        "REJECT",
        "--reject-with",
        "icmp6-no-route",
    ])
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_of_extracts_numeric_suffix() {
        assert_eq!(uid_of("com.app:10123").as_deref(), Some("10123"));
        assert_eq!(uid_of("exe:/usr/bin/curl"), None);
        assert_eq!(uid_of("com.app:abc"), None);
        assert_eq!(uid_of("com.app:"), None);
    }

    fn filter(mode: AppCaptureMode, entries: &[(&str, AppFilterMode)]) -> AppFilter {
        AppFilter {
            capture_mode: mode,
            entries: entries.iter().map(|(k, m)| (k.to_string(), *m)).collect(),
            strict: false,
        }
    }

    fn joined(rules: &[Vec<String>]) -> Vec<String> {
        rules.iter().map(|r| r.join(" ")).collect()
    }

    #[test]
    fn guards_bypass_apps_in_capture_all() {
        let f = filter(
            AppCaptureMode::All,
            &[
                ("bank:10123", AppFilterMode::Bypass),
                ("game:10200", AppFilterMode::ForceProxy),
            ],
        );
        let rules = joined(&guard_rules(&f, &[10808, 10809, 10810], &["t0", "t1"]));
        assert_eq!(
            rules,
            [
                "-o lo -p tcp --dport 10808 -m owner --uid-owner 10123 -j REJECT --reject-with tcp-reset",
                "-o lo -p tcp --dport 10809 -m owner --uid-owner 10123 -j REJECT --reject-with tcp-reset",
                "-o lo -p tcp --dport 10810 -m owner --uid-owner 10123 -j REJECT --reject-with tcp-reset",
                "-o t0 -m owner --uid-owner 10123 -j DROP",
                "-o t1 -m owner --uid-owner 10123 -j DROP",
            ]
        );
    }

    #[test]
    fn capture_none_lets_only_root_and_force_apps_onto_the_tun() {
        let f = filter(
            AppCaptureMode::None,
            &[("game:10200", AppFilterMode::ForceProxy)],
        );
        let rules = joined(&guard_rules(&f, &[10808], &["t0"]));
        assert_eq!(
            rules,
            [
                "-o t0 -m owner --uid-owner 0 -j ACCEPT",
                "-o t0 -m owner --uid-owner 10200 -j ACCEPT",
                "-o t0 -m owner --socket-exists -j DROP",
            ]
        );
        // No tun (not up yet): nothing to guard there.
        assert!(guard_rules(&f, &[10808], &[]).is_empty());
    }
}
