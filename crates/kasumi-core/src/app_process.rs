//! The per-app filter on desktop, where apps are matched by executable instead of
//! by uid.
//!
//! An `appFilter` key `exe:<path>` names an installed program (listed from the
//! desktop's launcher entries). It becomes a routing rule on the core's process
//! matcher (sing-box `process_name`, xray `process`) — bypass apps go `direct`,
//! force-proxy apps go `proxy`, both ahead of the user's routing rules, and in
//! capture-none mode everything else goes `direct`. Android keys (`pkg:uid`) are
//! routed by uid in the platform and never reach this.
//!
//! A core only sees the process behind a connection that it accepts itself: its
//! local proxy ports (the non-tun modes) or the native sing-box tun. Behind an
//! external tun helper every connection comes from the helper, so no rules are
//! emitted there ([`sees_processes`]); the UI says the filter is unavailable.

use serde_json::{Value, json};

use crate::core::{owns_native_tun, resolve_tun};
use crate::enums::CoreEngine;
use crate::state::{AdvancedSettings, AppCaptureMode, AppFilterMode, ProxyMode};

/// `appFilter` key prefix for a desktop program.
pub const EXE_KEY_PREFIX: &str = "exe:";

/// Whether `engine` can tell which program opened a connection under `s`.
pub fn sees_processes(engine: CoreEngine, s: &AdvancedSettings) -> bool {
    s.proxy_mode != ProxyMode::Tun || owns_native_tun(engine, resolve_tun(engine, s))
}

/// The process names a program shows up under. The executable's own name, plus
/// the name Nix's wrappers give the real binary (`.firefox-wrapped`), since a
/// launcher on NixOS points at the wrapper. A Windows name keeps its `.exe`.
fn process_names(path: &str) -> Vec<String> {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path);
    if base.is_empty() {
        return Vec::new();
    }
    let mut names = vec![base.to_string()];
    if !base.to_ascii_lowercase().ends_with(".exe") {
        names.push(format!(".{base}-wrapped"));
    }
    names
}

fn names_for(s: &AdvancedSettings, want: AppFilterMode) -> Vec<String> {
    let mut names: Vec<String> = s
        .app_filter
        .iter()
        .filter(|(_, m)| **m == want)
        .filter_map(|(k, _)| k.strip_prefix(EXE_KEY_PREFIX))
        .flat_map(process_names)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Insert the program rules into a built config, after the rules that must keep
/// running first (traffic sniffing / DNS hijack, the always-on force inbound) and
/// ahead of everything else. A no-op when the filter is empty or the core can't
/// see processes in this mode.
pub fn apply_process_filter(engine: CoreEngine, s: &AdvancedSettings, cfg: &mut Value) {
    if !sees_processes(engine, s) {
        return;
    }
    let bypass = names_for(s, AppFilterMode::Bypass);
    let force = names_for(s, AppFilterMode::ForceProxy);
    let capture_none = s.app_capture_mode == AppCaptureMode::None;
    if bypass.is_empty() && force.is_empty() && !capture_none {
        return;
    }
    let mut add: Vec<Value> = Vec::new();
    match engine {
        CoreEngine::SingBox => {
            if !bypass.is_empty() {
                add.push(json!({ "process_name": bypass, "outbound": "direct" }));
            }
            if !force.is_empty() {
                add.push(json!({ "process_name": force, "outbound": "proxy" }));
            }
            if capture_none {
                add.push(json!({ "network": ["tcp", "udp"], "outbound": "direct" }));
            }
        }
        CoreEngine::Xray => {
            if !bypass.is_empty() {
                add.push(json!({ "type": "field", "process": bypass, "outboundTag": "direct" }));
            }
            if !force.is_empty() {
                add.push(json!({ "type": "field", "process": force, "outboundTag": "proxy" }));
            }
            if capture_none {
                add.push(json!({ "type": "field", "network": "tcp,udp", "outboundTag": "direct" }));
            }
        }
    }
    let rules_key = match engine {
        CoreEngine::SingBox => "route",
        CoreEngine::Xray => "routing",
    };
    let Some(rules) = cfg
        .get_mut(rules_key)
        .and_then(|r| r.get_mut("rules"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    let at = rules
        .iter()
        .rposition(|r| keeps_running_first(engine, r))
        .map_or(0, |i| i + 1);
    rules.splice(at..at, add);
}

/// A rule the program rules must not pre-empt.
fn keeps_running_first(engine: CoreEngine, rule: &Value) -> bool {
    let tags = |key: &str| -> Vec<&str> {
        rule.get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    };
    match engine {
        // `sniff` / `hijack-dns`, and the force inbounds that always go `proxy`.
        CoreEngine::SingBox => {
            rule.get("action").is_some()
                || tags("inbound")
                    .iter()
                    .any(|t| matches!(*t, "force-in" | "tun-force"))
        }
        // The force inbound, DNS answered by the core's DNS module, and that
        // module's own upstream queries.
        CoreEngine::Xray => {
            rule.get("port").is_some_and(|p| p == 53 || p == "53")
                || tags("inboundTag")
                    .iter()
                    .any(|t| matches!(*t, "force-in" | "dns-module"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::TunEngine;

    fn settings(entries: &[(&str, AppFilterMode)], mode: ProxyMode) -> AdvancedSettings {
        AdvancedSettings {
            proxy_mode: mode,
            app_filter: entries.iter().map(|(k, m)| (k.to_string(), *m)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn names_cover_nix_wrappers_and_keep_exe() {
        assert_eq!(
            process_names("/usr/bin/firefox"),
            ["firefox", ".firefox-wrapped"]
        );
        assert_eq!(
            process_names(r"C:\Program Files\Mozilla Firefox\firefox.exe"),
            ["firefox.exe"]
        );
    }

    #[test]
    fn singbox_rules_follow_sniff_and_force_and_precede_user_rules() {
        let s = settings(
            &[
                ("exe:/usr/bin/firefox", AppFilterMode::Bypass),
                ("exe:/usr/bin/telegram-desktop", AppFilterMode::ForceProxy),
                // An Android key is never matched by process.
                ("com.app:10123", AppFilterMode::Bypass),
            ],
            ProxyMode::Tun,
        );
        let mut cfg = json!({ "route": { "rules": [
            { "action": "sniff" },
            { "protocol": ["dns"], "action": "hijack-dns" },
            { "inbound": ["force-in"], "outbound": "proxy" },
            { "ip_is_private": true, "outbound": "direct" },
        ] } });
        apply_process_filter(CoreEngine::SingBox, &s, &mut cfg);
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(
            rules[3],
            json!({ "process_name": [".firefox-wrapped", "firefox"], "outbound": "direct" })
        );
        assert_eq!(
            rules[4],
            json!({ "process_name": [".telegram-desktop-wrapped", "telegram-desktop"], "outbound": "proxy" })
        );
        assert_eq!(rules[5]["ip_is_private"], true);
        assert_eq!(rules.len(), 6);
    }

    #[test]
    fn capture_none_sends_everything_else_direct() {
        let mut s = settings(
            &[("exe:/usr/bin/curl", AppFilterMode::ForceProxy)],
            ProxyMode::ProxyOnly,
        );
        s.app_capture_mode = AppCaptureMode::None;
        let mut cfg = json!({ "routing": { "rules": [
            { "type": "field", "inboundTag": ["force-in"], "outboundTag": "proxy" },
            { "type": "field", "inboundTag": ["socks-in"], "port": 53, "outboundTag": "direct" },
            { "type": "field", "inboundTag": ["socks-in"], "network": "tcp,udp", "outboundTag": "proxy" },
        ] } });
        apply_process_filter(CoreEngine::Xray, &s, &mut cfg);
        let rules = cfg["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules[2]["process"], json!([".curl-wrapped", "curl"]));
        assert_eq!(rules[2]["outboundTag"], "proxy");
        assert_eq!(
            rules[3],
            json!({ "type": "field", "network": "tcp,udp", "outboundTag": "direct" })
        );
        assert_eq!(rules[4]["inboundTag"], json!(["socks-in"]));
    }

    #[test]
    fn skipped_where_the_core_cannot_see_processes() {
        let s = settings(
            &[("exe:/usr/bin/firefox", AppFilterMode::Bypass)],
            ProxyMode::Tun,
        );
        // xray behind tun2socks: every connection comes from the helper.
        assert!(!sees_processes(CoreEngine::Xray, &s));
        let mut cfg = json!({ "routing": { "rules": [] } });
        apply_process_filter(CoreEngine::Xray, &s, &mut cfg);
        assert_eq!(cfg["routing"]["rules"], json!([]));
        // sing-box behind an external helper is the same.
        let mut s2 = s.clone();
        s2.tun_by_core
            .insert(CoreEngine::SingBox, TunEngine::Tun2socks);
        assert!(!sees_processes(CoreEngine::SingBox, &s2));
        // Its native tun, and any non-tun mode, see the process.
        assert!(sees_processes(CoreEngine::SingBox, &s));
        assert!(sees_processes(
            CoreEngine::Xray,
            &settings(&[], ProxyMode::System)
        ));
    }

    #[test]
    fn empty_filter_changes_nothing() {
        let s = settings(&[], ProxyMode::ProxyOnly);
        let mut cfg = json!({ "route": { "rules": [{ "action": "sniff" }] } });
        let before = cfg.clone();
        apply_process_filter(CoreEngine::SingBox, &s, &mut cfg);
        assert_eq!(cfg, before);
    }
}
