//! Packet routing for the xray data-path: iptables marking + ip rules/tables +
//! fwmark. sing-box manages its own tun via auto_route, so these run for xray only.

use std::collections::BTreeMap;

use kasumi_core::state::{AppCaptureMode, AppFilterMode};

use super::paths::{IP, IP6TABLES, IPTABLES};
use super::{default_uplink, silent};

pub const FWMARK: u32 = 255;
const RULE_PRIORITY: &str = "1000";
const MARK_CHAIN: &str = "KASUMI_PROXY_MARK";

// Our own route-table numbers (v4 and v6 share them).
const TUN_TABLE: &str = "1100";
const TUN_TABLE_FORCE: &str = "1101";
const PRIO_TUN: &str = "1010";
const PRIO_TUN_FORCE: &str = "1011";

// Below sing-box's strict_route rules (pref 9000+), above the OS band, distinct
// from our xray LAN-bypass rules (5020-5050).
const STRICT_CARVEOUT_PREF: &str = "8500";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Add,
    Del,
}

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

pub fn has_force_proxy(f: &AppFilter) -> bool {
    f.entries.values().any(|m| *m == AppFilterMode::ForceProxy)
}

fn uid_of(key: &str) -> Option<&str> {
    let uid = key.rsplit(':').next()?;
    (!uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit())).then_some(uid)
}

/// `ip [-6] <args>`.
async fn ip_rule(v6: bool, args: &[&str]) -> i32 {
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

/// Strict-mode carve-out (sing-box): its `strict_route` adds a rule funnelling
/// every non-loopback-origin packet — including incoming connections and the reply
/// path of uplink-pinned traffic — into the tunnel. Pin packets arriving on the
/// physical uplink back to the uplink's own table at higher priority so the device
/// stays reachable under the kill-switch. xray needs no equivalent (its
/// REPLY-direction RETURN already spares incoming).
pub async fn apply_strict_carveouts() {
    let Some(uplink) = default_uplink().await else {
        return;
    };
    for v6 in [false, true] {
        ip_rule(
            v6,
            &[
                "rule",
                "del",
                "iif",
                &uplink,
                "lookup",
                &uplink,
                "pref",
                STRICT_CARVEOUT_PREF,
            ],
        )
        .await;
        ip_rule(
            v6,
            &[
                "rule",
                "add",
                "iif",
                &uplink,
                "lookup",
                &uplink,
                "pref",
                STRICT_CARVEOUT_PREF,
            ],
        )
        .await;
    }
}

async fn clear_strict_carveouts() {
    for v6 in [false, true] {
        for _ in 0..4 {
            if ip_rule(v6, &["rule", "del", "pref", STRICT_CARVEOUT_PREF]).await != 0 {
                break;
            }
        }
    }
}

pub async fn remove_mark_rule() {
    ip_rule(
        false,
        &["rule", "del", "fwmark", "255", "priority", RULE_PRIORITY],
    )
    .await;
    ip_rule(
        true,
        &["rule", "del", "fwmark", "255", "priority", RULE_PRIORITY],
    )
    .await;
}

/// Bind the proxy fwmark to the active uplink's route table.
pub async fn apply_mark_rule(iface: &str) {
    if iface.is_empty() {
        return;
    }
    remove_mark_rule().await;
    ip_rule(
        false,
        &[
            "rule",
            "add",
            "fwmark",
            "255",
            "table",
            iface,
            "priority",
            RULE_PRIORITY,
        ],
    )
    .await;
    ip_rule(
        true,
        &[
            "rule",
            "add",
            "fwmark",
            "255",
            "table",
            iface,
            "priority",
            RULE_PRIORITY,
        ],
    )
    .await;
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
                    uid,
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
                    uid,
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
                    uid,
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

/// Reject loopback proxy-port access from bypass-mode apps so they can't probe the
/// running proxy. Removes existing rules first to avoid stacking.
pub async fn protect_local_ports(
    action: Action,
    filter: &AppFilter,
    socks_port: u16,
    http_port: u16,
) {
    let socks = socks_port.to_string();
    let http = http_port.to_string();
    for (key, mode) in &filter.entries {
        if *mode != AppFilterMode::Bypass {
            continue;
        }
        let Some(uid) = uid_of(key) else {
            continue;
        };
        for port in [socks.as_str(), http.as_str()] {
            for ipt in [IPTABLES, IP6TABLES] {
                let rule = [
                    "-o",
                    "lo",
                    "-p",
                    "tcp",
                    "--dport",
                    port,
                    "-m",
                    "owner",
                    "--uid-owner",
                    uid,
                    "-j",
                    "REJECT",
                    "--reject-with",
                    "tcp-reset",
                ];
                let mut del = vec![ipt, "-D", "OUTPUT"];
                del.extend_from_slice(&rule);
                silent(&del).await;
                if action == Action::Add {
                    let mut add = vec![ipt, "-A", "OUTPUT"];
                    add.extend_from_slice(&rule);
                    silent(&add).await;
                }
            }
        }
    }
}

/// Tear down every rule/table/device the xray data-path installed.
pub async fn clear_routing_rules(st: &RoutingState) {
    remove_mark_rule().await;
    clear_strict_carveouts().await;
    protect_local_ports(Action::Del, &st.filter, st.socks_port, st.http_port).await;

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

    // Our LAN-bypass rules: pref 5020-5022 send RFC1918 sources to the uplink
    // table, 5030-5050 to our tun table. Delete by priority — the band is ours
    // (the OS lives at pref 10000+); the loop clears any stacked duplicate.
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
pub async fn apply_xray_routing(st: &RoutingState) {
    let Some(tun) = st.tun_iface.as_deref() else {
        return;
    };
    let tun2 = st.tun2_iface.as_deref();

    silent(&[IP, "addr", "add", "198.18.0.1/15", "dev", tun]).await;
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
        silent(&[IP, "addr", "add", "198.19.0.1/16", "dev", tun2]).await;
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

    // Pin local-origin traffic to the physical uplink so it doesn't loop the tun.
    if let Some(uplink) = default_uplink().await {
        for (src, pref) in [
            ("10.0.0.0/8", "5020"),
            ("172.16.0.0/12", "5021"),
            ("192.168.0.0/16", "5022"),
        ] {
            ip_rule(
                false,
                &[
                    "rule", "del", "from", src, "iif", "lo", "lookup", &uplink, "pref", pref,
                ],
            )
            .await;
            ip_rule(
                false,
                &[
                    "rule", "add", "from", src, "iif", "lo", "lookup", &uplink, "pref", pref,
                ],
            )
            .await;
        }
    }
    for (src, pref) in [
        ("10.0.0.0/8", "5030"),
        ("172.16.0.0/12", "5040"),
        ("192.168.0.0/16", "5050"),
    ] {
        ip_rule(
            false,
            &[
                "rule", "del", "from", src, "lookup", TUN_TABLE, "pref", pref,
            ],
        )
        .await;
        ip_rule(
            false,
            &[
                "rule", "add", "from", src, "lookup", TUN_TABLE, "pref", pref,
            ],
        )
        .await;
    }
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
    silent(&[IP, "-6", "addr", "add", "fdfe:dcba:9876::1/64", "dev", tun]).await;
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
        silent(&[IP, "-6", "addr", "add", "fdfe:dcba:9877::1/64", "dev", tun2]).await;
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

/// Reload xray app-filter rules without a core restart (reload-app-filter).
pub async fn reload_app_filter_rules(filter: &AppFilter) {
    for ipt in [IPTABLES, IP6TABLES] {
        silent(&[ipt, "-t", "mangle", "-F", MARK_CHAIN]).await;
        app_uid_rules(ipt, filter).await;
        capture_mark_rules(ipt, filter).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_of_extracts_numeric_suffix() {
        assert_eq!(uid_of("com.app:10123"), Some("10123"));
        assert_eq!(uid_of("10123"), Some("10123"));
        assert_eq!(uid_of("com.app:abc"), None);
        assert_eq!(uid_of("com.app:"), None);
    }

    #[test]
    fn has_force_proxy_detects_mode() {
        let mut entries = BTreeMap::new();
        entries.insert("a:1".to_string(), AppFilterMode::Bypass);
        let f = AppFilter {
            capture_mode: AppCaptureMode::All,
            entries: entries.clone(),
            strict: false,
        };
        assert!(!has_force_proxy(&f));
        entries.insert("b:2".to_string(), AppFilterMode::ForceProxy);
        let f2 = AppFilter {
            capture_mode: AppCaptureMode::All,
            entries,
            strict: false,
        };
        assert!(has_force_proxy(&f2));
    }
}
