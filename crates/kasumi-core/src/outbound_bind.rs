//! Binding the core's own egress outbounds to a physical uplink interface.
//!
//! Invariant across every platform: a core's own egress outbounds (`proxy` +
//! `direct`) must leave via the physical uplink and never re-enter the tun, or they
//! loop (tun → tun-engine → core SOCKS → outbound → tun → …). How that's achieved
//! depends on the tun mode, not the engine:
//!   - **bridged** (xray/sing-box behind an external tun engine like tun2socks/hev,
//!     with a split-default pulling traffic into the tun): bind the egress outbounds
//!     to the uplink at the socket layer — this helper. Engine- and
//!     tun-engine-agnostic; the escape is on the core's socket, so swapping the tun
//!     engine changes nothing here.
//!   - **self-managed** (sing-box `auto_route`): the core owns the tun and escapes
//!     via its own `auto_detect_interface` — do *not* call this there, an explicit
//!     `bind_interface` would defeat the auto-detection and pin a stale interface.
//!   - **Android**: a per-uid policy-routing model excludes root from marking, so the
//!     core (run as root) escapes without an explicit bind. It doesn't call this
//!     today, but the helper is shared so it can if a future need arises.

use serde_json::{json, Value};

use crate::enums::CoreEngine;

/// The core's own egress outbounds, by tag. Service outbounds (`block`, `dns`) carry
/// no traffic to the network and are left untouched.
const EGRESS_TAGS: [&str; 2] = ["proxy", "direct"];

/// Bind every egress (`proxy`/`direct`) outbound's upstream socket to `iface` so the
/// core's traffic to the server *and* its direct (geo-`direct`) traffic egress the
/// physical uplink and escape an active tun — no per-connection OS routing involved.
/// xray exposes this as `streamSettings.sockopt.interface` (→ `SO_BINDTODEVICE` /
/// `IP_UNICAST_IF`); sing-box as a top-level `bind_interface`. sing-box's wireguard
/// outbound lives under `endpoints`, so both arrays are scanned.
pub fn bind_uplink_outbounds(engine: CoreEngine, cfg: &mut Value, iface: &str) {
    for key in ["outbounds", "endpoints"] {
        let Some(arr) = cfg.get_mut(key).and_then(Value::as_array_mut) else {
            continue;
        };
        for ob in arr {
            let tag = ob.get("tag").and_then(Value::as_str);
            if !tag.is_some_and(|t| EGRESS_TAGS.contains(&t)) {
                continue;
            }
            let Some(map) = ob.as_object_mut() else {
                continue;
            };
            match engine {
                CoreEngine::Xray => {
                    let stream = map.entry("streamSettings").or_insert_with(|| json!({}));
                    if let Some(sock) = stream
                        .as_object_mut()
                        .map(|s| s.entry("sockopt").or_insert_with(|| json!({})))
                        .and_then(Value::as_object_mut)
                    {
                        sock.insert("interface".into(), iface.into());
                    }
                }
                CoreEngine::SingBox => {
                    map.insert("bind_interface".into(), iface.into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_egress_outbounds_only() {
        // xray: sets streamSettings.sockopt.interface on both the proxy and direct
        // outbounds, creating the streamSettings/sockopt objects when absent, and
        // leaves service outbounds (block/dns) untouched.
        let mut x = json!({ "outbounds": [
            { "tag": "proxy", "protocol": "socks" },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" },
        ] });
        bind_uplink_outbounds(CoreEngine::Xray, &mut x, "eno1");
        assert_eq!(
            x["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert_eq!(
            x["outbounds"][1]["streamSettings"]["sockopt"]["interface"],
            "eno1"
        );
        assert!(x["outbounds"][2].get("streamSettings").is_none());

        // sing-box: top-level bind_interface on the proxy + direct outbounds and the
        // wireguard proxy endpoint, leaving service outbounds untouched.
        let mut s = json!({
            "outbounds": [
                { "tag": "proxy", "type": "vless" },
                { "tag": "direct", "type": "direct" },
                { "tag": "dns", "type": "dns" },
            ],
            "endpoints": [{ "tag": "proxy", "type": "wireguard" }],
        });
        bind_uplink_outbounds(CoreEngine::SingBox, &mut s, "wlan0");
        assert_eq!(s["outbounds"][0]["bind_interface"], "wlan0");
        assert_eq!(s["outbounds"][1]["bind_interface"], "wlan0");
        assert!(s["outbounds"][2].get("bind_interface").is_none());
        assert_eq!(s["endpoints"][0]["bind_interface"], "wlan0");
    }
}
