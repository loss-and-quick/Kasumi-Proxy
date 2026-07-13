//! Build the YAML config for `tun2socks` (xjasonlyu/tun2socks).
//!
//! tun2socks creates the TUN device named in `device` (the OS routing layer then
//! addresses it and steers traffic in — unlike hev it does not self-address) and
//! relays everything to the local SOCKS5 the proxy core exposes. Passing a config
//! file instead of CLI flags keeps us independent of the binary's flag parser
//! (v2.7.0 switched to pflag, which rejects the single-dash long flags older
//! builds accepted) and lets the TUN tuning knobs reach it like they reach hev.
//! The keys mirror upstream `engine.Key`; only this file knows that shape.

use serde::Serialize;

use crate::tun::TunOptions;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Tun2socksConfig {
    device: String,
    proxy: String,
    mtu: u32,
    loglevel: String,
    /// Wire format is a Go `time.Duration` string ("60000ms"); a bare integer is
    /// rejected by the parser.
    udp_timeout: String,
    /// Per-connection netstack TCP buffer sizes, in bytes (upstream parses the
    /// string with an optional size suffix).
    tcp_send_buffer_size: String,
    tcp_receive_buffer_size: String,
    /// SO_MARK stamped on tun2socks' own upstream sockets so an `ip rule` keeps
    /// them out of the tunnel — load-bearing on Android (mirrors hev's
    /// `socks5.mark`), unused on desktop (the core binds to the uplink instead),
    /// so omitted when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    fwmark: Option<u32>,
}

/// Render the tun2socks YAML for an interface `iface` (which tun2socks creates;
/// the routing layer addresses it) bridging to `127.0.0.1:<socks_port>`.
pub fn build_tun2socks_config(
    iface: &str,
    socks_port: u16,
    fwmark: Option<u32>,
    opts: &TunOptions,
) -> String {
    let cfg = Tun2socksConfig {
        device: format!("tun://{iface}"),
        proxy: format!("socks5://127.0.0.1:{socks_port}"),
        mtu: opts.mtu,
        // The resolved level vocabulary (debug|info|warn|error) is a subset of
        // tun2socks' own (which adds silent), so it passes through unmapped.
        loglevel: opts.log_level.clone(),
        udp_timeout: format!("{}ms", opts.udp_rw_timeout_ms),
        tcp_send_buffer_size: opts.tcp_buffer_size.to_string(),
        tcp_receive_buffer_size: opts.tcp_buffer_size.to_string(),
        fwmark,
    };
    // Infallible for this plain-scalar shape.
    yaml_serde::to_string(&cfg).expect("tun2socks config serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AdvancedSettings;

    #[test]
    fn renders_expected_keys() {
        let opts = AdvancedSettings::default().tun_options();
        let yaml = build_tun2socks_config("kt0", 10808, None, &opts);
        assert!(yaml.contains("device: tun://kt0"));
        assert!(yaml.contains("proxy: socks5://127.0.0.1:10808"));
        assert!(yaml.contains("mtu: 9000"));
        assert!(yaml.contains("loglevel: warn"));
        assert!(yaml.contains("udp-timeout: 60000ms"));
        assert!(yaml.contains("tcp-send-buffer-size: '65536'"));
        assert!(yaml.contains("tcp-receive-buffer-size: '65536'"));
        // No fwmark passed → no key at all.
        assert!(!yaml.contains("fwmark"));
    }

    #[test]
    fn fwmark_emitted_when_set() {
        // Android passes a fwmark so tun2socks' own sockets escape the tunnel;
        // desktop passes None (see `build_tun2socks_config`).
        let opts = AdvancedSettings::default().tun_options();
        let yaml = build_tun2socks_config("kt0", 10808, Some(255), &opts);
        assert!(yaml.contains("fwmark: 255"));
    }
}
