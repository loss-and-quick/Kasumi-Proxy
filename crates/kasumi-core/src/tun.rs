//! Runtime tuning for an external TUN engine, resolved from [`AdvancedSettings`].
//!
//! This is the small, transport-shaped subset of the settings an external engine
//! (hev today) needs to spawn. It is resolved once where the data-path is started
//! and travels with the start request — on desktop that means across the privilege
//! boundary inside `StartDataPath` — so neither the root helper nor the Android
//! daemon has to re-read the settings schema to build the engine config.

use serde::{Deserialize, Serialize};

use crate::state::{AdvancedSettings, LogLevel};

// ── Split-tun addresses ──────────────────────────────────────────────────────
// The addresses the desktop and Android data-paths give their userspace tun(s).
// Three independent writers must agree on them: a self-addressing engine (hev)
// assigns them from its YAML, the `ip addr add` routing assigns them for tun2socks,
// and the sing-box native tun bakes them into its inbound. They live here once so a
// renumber can't update some copies and black-hole the rest. The `_CIDR` forms carry
// the interface prefix; `tun_cidrs_match_hosts` guards each host/CIDR pair.

/// Primary tun IPv4 host address.
pub const TUN_IPV4: &str = "198.18.0.1";
/// Primary tun IPv4 address with its interface prefix.
pub const TUN_IPV4_CIDR: &str = "198.18.0.1/15";
/// Primary tun IPv6 host address.
pub const TUN_IPV6: &str = "fdfe:dcba:9876::1";
/// Primary tun IPv6 address with its interface prefix.
pub const TUN_IPV6_CIDR: &str = "fdfe:dcba:9876::1/64";
/// Force-proxy second tun IPv4 host (Android-only; desktop has a single tun).
pub const TUN2_IPV4: &str = "198.19.0.1";
/// Force-proxy second tun IPv4 with its interface prefix.
pub const TUN2_IPV4_CIDR: &str = "198.19.0.1/16";
/// Force-proxy second tun IPv6 host.
pub const TUN2_IPV6: &str = "fdfe:dcba:9877::1";
/// Force-proxy second tun IPv6 with its interface prefix.
pub const TUN2_IPV6_CIDR: &str = "fdfe:dcba:9877::1/64";

/// Resolved external-TUN tuning. Numbers are widened to `u32`/`u16` here so the
/// config builders never re-validate the persisted `i64`s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunOptions {
    pub mtu: u32,
    pub connect_timeout_ms: u32,
    pub tcp_rw_timeout_ms: u32,
    pub udp_rw_timeout_ms: u32,
    pub tcp_buffer_size: u32,
    pub udp_recv_buffer_size: u32,
    /// Log level in the engine's own vocabulary (`debug|info|warn|error`), mapped
    /// from the app log level.
    pub log_level: String,
}

/// Clamp a persisted `i64` knob to `u32`, falling back to `default` when it is
/// non-positive (a corrupt/old value should never disable the engine).
fn knob(value: i64, default: u32) -> u32 {
    if value > 0 {
        value.min(i64::from(u32::MAX)) as u32
    } else {
        default
    }
}

/// Map the app log level to hev's vocabulary. hev has no "none"; the quietest it
/// offers is `error`. An unset app level uses hev's own default, `warn`.
fn hev_log_level(level: Option<LogLevel>) -> &'static str {
    match level {
        Some(LogLevel::Debug) => "debug",
        Some(LogLevel::Info) => "info",
        Some(LogLevel::Warning) => "warn",
        Some(LogLevel::Error) | Some(LogLevel::None) => "error",
        None => "warn",
    }
}

impl AdvancedSettings {
    /// Resolve the external-TUN tuning from the global settings.
    pub fn tun_options(&self) -> TunOptions {
        TunOptions {
            mtu: knob(self.tun_mtu, 9000),
            connect_timeout_ms: knob(self.tun_connect_timeout_ms, 10_000),
            tcp_rw_timeout_ms: knob(self.tun_tcp_rw_timeout_ms, 300_000),
            udp_rw_timeout_ms: knob(self.tun_udp_rw_timeout_ms, 60_000),
            tcp_buffer_size: knob(self.tun_tcp_buffer_size, 65_536),
            udp_recv_buffer_size: knob(self.tun_udp_recv_buffer_size, 524_288),
            log_level: hev_log_level(self.log_level).to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_cidrs_match_hosts() {
        // A `_CIDR` const must be its host address plus a prefix, so the two forms
        // can't drift when someone renumbers the tun.
        for (host, cidr) in [
            (TUN_IPV4, TUN_IPV4_CIDR),
            (TUN_IPV6, TUN_IPV6_CIDR),
            (TUN2_IPV4, TUN2_IPV4_CIDR),
            (TUN2_IPV6, TUN2_IPV6_CIDR),
        ] {
            assert!(
                cidr.starts_with(&format!("{host}/")),
                "{cidr} is not {host} + a prefix"
            );
        }
    }

    #[test]
    fn options_from_defaults() {
        let o = AdvancedSettings::default().tun_options();
        assert_eq!(o.mtu, 9000);
        assert_eq!(o.connect_timeout_ms, 10_000);
        assert_eq!(o.log_level, "warn");
    }

    #[test]
    fn knob_falls_back_on_garbage() {
        assert_eq!(knob(-1, 9000), 9000);
        assert_eq!(knob(0, 9000), 9000);
        assert_eq!(knob(1400, 9000), 1400);
    }

    #[test]
    fn log_level_maps_to_hev_vocab() {
        let warn = AdvancedSettings {
            log_level: Some(LogLevel::Warning),
            ..Default::default()
        };
        assert_eq!(warn.tun_options().log_level, "warn");
        let none = AdvancedSettings {
            log_level: Some(LogLevel::None),
            ..Default::default()
        };
        assert_eq!(none.tun_options().log_level, "error");
    }
}
