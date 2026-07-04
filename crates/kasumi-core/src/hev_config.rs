//! Build the YAML config for `hev-socks5-tunnel`.
//!
//! hev owns its TUN device: from this config it creates the interface named
//! `tunnel.name` and assigns `tunnel.ipv4` (and `tunnel.ipv6` when present), then
//! relays everything to the local SOCKS5 the proxy core exposes. The OS routing we
//! install around it (split-default + server bypass) is identical to the tun2socks
//! path, so only this file knows hev's config shape.

use serde::Serialize;

use crate::tun::TunOptions;

#[derive(Serialize)]
struct HevConfig {
    tunnel: Tunnel,
    socks5: Socks5,
    misc: Misc,
}

#[derive(Serialize)]
struct Tunnel {
    name: String,
    mtu: u32,
    ipv4: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv6: Option<String>,
}

#[derive(Serialize)]
struct Socks5 {
    port: u16,
    address: &'static str,
    /// UDP relay mode. Always `"udp"` (standard SOCKS5 UDP ASSOCIATE): the cores we
    /// front (xray / sing-box SOCKS inbounds) speak that, not hev's `"tcp"`
    /// UDP-in-TCP framing, which needs a hev-socks5-server upstream.
    udp: &'static str,
    /// SO_MARK stamped on hev's own upstream sockets so an `ip rule` keeps them out
    /// of the tunnel — load-bearing on Android (mirrors tun2socks' `-fwmark`), unused
    /// on desktop (the core binds to the uplink instead), so omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Misc {
    log_level: &'static str,
    connect_timeout: u32,
    tcp_read_write_timeout: u32,
    udp_read_write_timeout: u32,
    tcp_buffer_size: u32,
    udp_recv_buffer_size: u32,
}

/// Render the hev YAML for an interface `iface` (which hev creates and addresses
/// with `ipv4`/`ipv6`) bridging to `127.0.0.1:<socks_port>`. `ipv6` is omitted on
/// IPv4-only data-paths (the desktop external-tun path).
pub fn build_hev_config(
    iface: &str,
    ipv4: &str,
    ipv6: Option<&str>,
    socks_port: u16,
    fwmark: Option<u32>,
    opts: &TunOptions,
) -> String {
    let cfg = HevConfig {
        tunnel: Tunnel {
            name: iface.to_owned(),
            mtu: opts.mtu,
            ipv4: ipv4.to_owned(),
            ipv6: ipv6.map(str::to_owned),
        },
        socks5: Socks5 {
            port: socks_port,
            address: "127.0.0.1",
            udp: "udp",
            mark: fwmark,
        },
        misc: Misc {
            log_level: hev_level(&opts.log_level),
            connect_timeout: opts.connect_timeout_ms,
            tcp_read_write_timeout: opts.tcp_rw_timeout_ms,
            udp_read_write_timeout: opts.udp_rw_timeout_ms,
            tcp_buffer_size: opts.tcp_buffer_size,
            udp_recv_buffer_size: opts.udp_recv_buffer_size,
        },
    };
    // Infallible for this plain-scalar shape.
    yaml_serde::to_string(&cfg).expect("hev config serializes")
}

/// Constrain the resolved level string to hev's four levels (defensive: the
/// resolver already produces these, but a stray value must not reach hev).
fn hev_level(level: &str) -> &'static str {
    match level {
        "debug" => "debug",
        "info" => "info",
        "error" => "error",
        _ => "warn",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AdvancedSettings;

    #[test]
    fn renders_expected_keys() {
        let opts = AdvancedSettings::default().tun_options();
        let yaml = build_hev_config("kt0", crate::tun::TUN_IPV4, None, 10808, None, &opts);
        assert!(yaml.contains("name: kt0"));
        assert!(yaml.contains("mtu: 9000"));
        assert!(yaml.contains("ipv4: 198.18.0.1"));
        assert!(!yaml.contains("ipv6"));
        assert!(yaml.contains("port: 10808"));
        assert!(yaml.contains("address: 127.0.0.1"));
        assert!(yaml.contains("udp: udp"));
        assert!(yaml.contains("log-level: warn"));
        assert!(yaml.contains("connect-timeout: 10000"));
        assert!(yaml.contains("tcp-read-write-timeout: 300000"));
        assert!(yaml.contains("udp-recv-buffer-size: 524288"));
        // No fwmark passed → no mark key at all.
        assert!(!yaml.contains("mark:"));
    }

    #[test]
    fn ipv6_emitted_when_present() {
        let opts = AdvancedSettings::default().tun_options();
        let yaml = build_hev_config(
            "kt0",
            crate::tun::TUN_IPV4,
            Some(crate::tun::TUN_IPV6),
            10808,
            None,
            &opts,
        );
        assert!(yaml.contains("ipv6: fdfe:dcba:9876::1"));
    }

    #[test]
    fn mark_emitted_when_fwmark_set() {
        // Android passes a fwmark so hev's own sockets escape the tunnel like
        // tun2socks' `-fwmark`; desktop passes None (see `build_hev_config`).
        let opts = AdvancedSettings::default().tun_options();
        let yaml = build_hev_config("kt0", crate::tun::TUN_IPV4, None, 10808, Some(255), &opts);
        assert!(yaml.contains("mark: 255"));
    }
}
