//! Core-engine resolution — profile override + per-protocol defaults, with
//! capability guards for transports/protocols only one core can build.

use crate::enums::{CoreEngine, Flow, HeaderType, Network, PacketEncoding, Security, TunEngine};
use crate::mixins::Transport;
use crate::profile::{Profile, Protocol};
use crate::state::AdvancedSettings;

fn is_singbox_only(proto: Protocol) -> bool {
    matches!(
        proto,
        Protocol::Tuic | Protocol::Anytls | Protocol::Naive | Protocol::Shadowtls
    )
}

/// Engine a protocol uses when nothing overrides it.
pub fn default_core_for(proto: Protocol) -> CoreEngine {
    if proto == Protocol::Hysteria2 || is_singbox_only(proto) {
        CoreEngine::SingBox
    } else {
        CoreEngine::Xray
    }
}

/// Engine the profile MUST run on (protocol or transport capability), or `None`
/// if it's selectable.
pub fn forced_core(p: &Profile) -> Option<CoreEngine> {
    use CoreEngine::{SingBox, Xray};
    let proto = p.protocol();
    if proto == Protocol::Custom {
        return Some(Xray);
    }
    if is_singbox_only(proto) {
        return Some(SingBox);
    }

    // ── Protocol-level differences ──
    match p {
        Profile::Vless(v) => {
            if v.flow == Flow::VisionUdp443 {
                return Some(Xray);
            }
            if !v.encryption.is_empty() && v.encryption != "none" {
                return Some(Xray);
            }
            if v.packet_encoding == PacketEncoding::Packetaddr {
                return Some(SingBox);
            }
        }
        Profile::Vmess(v) => {
            if v.packet_encoding == PacketEncoding::Packetaddr {
                return Some(SingBox);
            }
            if v.vmess_global_padding || v.vmess_authenticated_length {
                return Some(SingBox);
            }
        }
        Profile::Shadowsocks(ss) => {
            // Xray dropped its QUIC transport, so v2ray-plugin's QUIC mode runs only
            // on sing-box, whatever the cipher.
            if matches!(ss.transport, Transport::Quic(_)) {
                return Some(SingBox);
            }
            // Every cipher runs on both cores (sing-box under its own names for
            // Xray's `plain` / `chacha20-poly1305` / `xchacha20-poly1305`), so
            // only a v2ray-plugin or obfs-local transport, or the plugin's TLS,
            // pins sing-box.
            if ss.tls.security == Security::Tls
                || ss.transport.network() != Network::Tcp
                || ss.transport.header_type() == HeaderType::Http
            {
                return Some(SingBox);
            }
        }
        _ => {}
    }

    // ── Transport-level differences ──
    if let Some(t) = p.transport() {
        match t {
            Transport::H2(_) | Transport::Quic(_) => return Some(SingBox),
            Transport::Kcp(_) | Transport::Xhttp(_) => return Some(Xray),
            Transport::Httpupgrade(h) => {
                if h.accept_proxy_protocol || h.early_data > 0 {
                    return Some(Xray);
                }
            }
            Transport::Ws(w) => {
                if w.heartbeat_period > 0 || w.accept_proxy_protocol {
                    return Some(Xray);
                }
            }
            Transport::Grpc(g) => {
                // The parser folds the path fallback into `service_name`.
                if g.service_name.starts_with('/') {
                    return Some(Xray);
                }
                if g.ping_timeout > 0 {
                    return Some(SingBox);
                }
                if !g.authority.is_empty()
                    || g.mode == "multi"
                    || g.health_check_timeout > 0
                    || g.initial_window_size > 0
                    || !g.user_agent.is_empty()
                {
                    return Some(Xray);
                }
            }
            Transport::Tcp(_) => {}
        }
    }

    // ── TLS / Reality-level differences (Xray-only fields) ──
    if let Some(tls) = p.tls() {
        if tls.reject_unknown_sni || tls.enable_session_resumption || !tls.vcn.is_empty() {
            return Some(Xray);
        }
        if tls.security == Security::Reality && !tls.pqv.is_empty() {
            return Some(Xray);
        }
    }

    None
}

/// Resolve the actual core for a profile (capabilities > override > table > fallback).
pub fn resolve_core(p: &Profile, s: &AdvancedSettings) -> CoreEngine {
    if let Some(forced) = forced_core(p) {
        return forced;
    }
    if let Some(engine) = p.meta().core_type {
        return engine;
    }
    s.core_by_protocol
        .get(&p.protocol())
        .copied()
        .unwrap_or_else(|| default_core_for(p.protocol()))
}

/// TUN engine a core uses when nothing overrides it: sing-box owns a native TUN,
/// xray has no TUN of its own so it defaults to the `tun2socks` helper.
pub fn default_tun_for(core: CoreEngine) -> TunEngine {
    match core {
        CoreEngine::SingBox => TunEngine::SingboxTun,
        CoreEngine::Xray => TunEngine::Tun2socks,
    }
}

/// Resolve the TUN engine for a resolved core: the per-core override, else the
/// default. Every `TunEngine` is valid for every core — `SingboxTun` on the sing-box
/// core is its own native tun, and on any other core it's a sidecar sing-box
/// bridging that core's SOCKS (see [`owns_native_tun`]).
pub fn resolve_tun(core: CoreEngine, s: &AdvancedSettings) -> TunEngine {
    s.tun_by_core
        .get(&core)
        .copied()
        .unwrap_or_else(|| default_tun_for(core))
}

/// Whether `(core, tun)` means the core owns its TUN natively — true only for the
/// sing-box core running `SingboxTun` (it terminates the tun inside its own process).
/// Every other pair fronts a socks-only core with an external tun helper: `Tun2socks`
/// / `Hev`, or — for `SingboxTun` on a non-sing-box core — a *sidecar* sing-box in
/// tun→socks bridge mode. This is the one place the native/external split is decided.
pub fn owns_native_tun(core: CoreEngine, tun: TunEngine) -> bool {
    core == CoreEngine::SingBox && tun == TunEngine::SingboxTun
}

/// Per-core TUN-engine options for the settings UI: for each core its default
/// engine and the engines valid to pick. Derived from the very same
/// [`default_tun_for`]/[`resolve_tun`] rules the data-path uses (a variant is valid
/// for a core iff `resolve_tun` keeps it — every engine is valid for every core
/// today), so the UI never re-encodes the per-core default or validity; they are
/// emitted to the frontend from here (see `defaults.rs` → `TUN_BY_CORE`).
pub fn tun_by_core_options() -> Vec<TunCoreOptions> {
    use strum::IntoEnumIterator;
    CoreEngine::iter()
        .map(|core| {
            let valid = TunEngine::iter()
                .filter(|&tun| {
                    let mut s = AdvancedSettings::default();
                    s.tun_by_core.insert(core, tun);
                    resolve_tun(core, &s) == tun
                })
                .collect();
            TunCoreOptions {
                core,
                default: default_tun_for(core),
                valid,
            }
        })
        .collect()
}

/// One core's TUN-engine options (see [`tun_by_core_options`]).
pub struct TunCoreOptions {
    pub core: CoreEngine,
    pub default: TunEngine,
    pub valid: Vec<TunEngine>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::SsMethod;
    use crate::share::parse_share_link;

    fn p(uri: &str) -> Profile {
        parse_share_link(uri, None).unwrap()
    }

    #[test]
    fn tun_defaults_and_override() {
        use CoreEngine::{SingBox, Xray};
        // Defaults: sing-box→native TUN, xray→tun2socks helper.
        assert_eq!(default_tun_for(SingBox), TunEngine::SingboxTun);
        assert_eq!(default_tun_for(Xray), TunEngine::Tun2socks);
        let mut s = AdvancedSettings::default();
        assert_eq!(resolve_tun(SingBox, &s), TunEngine::SingboxTun);
        assert_eq!(resolve_tun(Xray, &s), TunEngine::Tun2socks);
        // Per-core override wins; every engine is valid for every core.
        s.tun_by_core.insert(SingBox, TunEngine::Tun2socks);
        assert_eq!(resolve_tun(SingBox, &s), TunEngine::Tun2socks);
        // SingboxTun on xray is kept — it means a sidecar sing-box bridge, not native.
        s.tun_by_core.insert(Xray, TunEngine::SingboxTun);
        assert_eq!(resolve_tun(Xray, &s), TunEngine::SingboxTun);
    }

    #[test]
    fn native_tun_only_for_singbox_core() {
        use CoreEngine::{SingBox, Xray};
        // The sing-box core with its own SingboxTun is the only native pairing.
        assert!(owns_native_tun(SingBox, TunEngine::SingboxTun));
        // xray + SingboxTun is a sidecar (external), not native.
        assert!(!owns_native_tun(Xray, TunEngine::SingboxTun));
        // Any userspace helper is external on either core.
        assert!(!owns_native_tun(SingBox, TunEngine::Tun2socks));
        assert!(!owns_native_tun(Xray, TunEngine::Hev));
    }

    #[test]
    fn defaults_by_protocol() {
        assert_eq!(default_core_for(Protocol::Vless), CoreEngine::Xray);
        assert_eq!(default_core_for(Protocol::Hysteria2), CoreEngine::SingBox);
        assert_eq!(default_core_for(Protocol::Tuic), CoreEngine::SingBox);
    }

    #[test]
    fn singbox_only_protocols_forced() {
        assert_eq!(
            forced_core(&p("tuic://u:pw@t.ex:443?sni=t.ex")),
            Some(CoreEngine::SingBox)
        );
        assert_eq!(
            forced_core(&p("anytls://pw@a.ex:443?sni=a.ex")),
            Some(CoreEngine::SingBox)
        );
    }

    #[test]
    fn xray_only_capabilities() {
        // vless + reality + pqv → xray
        assert_eq!(
            forced_core(&p(
                "vless://u@e.x:443?type=tcp&security=reality&pbk=PK&sni=s&pqv=Q"
            )),
            Some(CoreEngine::Xray)
        );
        // xhttp transport → xray
        assert_eq!(
            forced_core(&p("vless://u@e.x:443?type=xhttp&security=tls")),
            Some(CoreEngine::Xray)
        );
        // A trojan flow pins nothing: xray rejects it and sing-box has none.
        assert_eq!(
            forced_core(&p("trojan://pw@e.x:443?security=tls&flow=xtls-rprx-vision")),
            None
        );
    }

    #[test]
    fn singbox_only_capabilities() {
        // h2 transport → sing-box
        assert_eq!(
            forced_core(&p("vless://u@e.x:443?type=h2&security=tls")),
            Some(CoreEngine::SingBox)
        );
    }

    #[test]
    fn every_shadowsocks_cipher_is_selectable_on_plain_tcp() {
        use strum::IntoEnumIterator;
        for method in SsMethod::iter() {
            let with = |uri: &str| {
                let Profile::Shadowsocks(mut ss) = p(uri) else {
                    panic!("not shadowsocks")
                };
                ss.method = method;
                Profile::Shadowsocks(ss)
            };
            assert_eq!(
                forced_core(&with("ss://YWVzLTI1Ni1nY206cHc=@h.ex:8388#x")),
                None,
                "{method:?} on plain TCP"
            );
            for plugin in [
                "v2ray-plugin%3Bmode%3Dwebsocket",
                "v2ray-plugin%3Btls",
                "obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dh.ex",
            ] {
                assert_eq!(
                    forced_core(&with(&format!(
                        "ss://YWVzLTI1Ni1nY206cHc=@h.ex:8388?plugin={plugin}#x"
                    ))),
                    Some(CoreEngine::SingBox),
                    "{method:?} with {plugin}"
                );
            }
        }
    }

    #[test]
    fn more_url_reachable_forced_branches() {
        use CoreEngine::{SingBox, Xray};
        // The udp443 vision flow is an Xray-only variant.
        assert_eq!(
            forced_core(&p(
                "vless://u@e.x:443?type=tcp&security=tls&flow=xtls-rprx-vision-udp443"
            )),
            Some(Xray)
        );
        // A non-"none" vless encryption is Xray-only.
        assert_eq!(
            forced_core(&p(
                "vless://u@e.x:443?type=tcp&security=tls&encryption=mlkem768"
            )),
            Some(Xray)
        );
        // mKCP transport → Xray; QUIC transport → sing-box.
        assert_eq!(forced_core(&p("vless://u@e.x:443?type=kcp")), Some(Xray));
        assert_eq!(
            forced_core(&p("vless://u@e.x:443?type=quic&security=tls")),
            Some(SingBox)
        );
        // gRPC service-name with a leading slash (the parser's path fallback) → Xray.
        assert_eq!(
            forced_core(&p(
                "vless://u@e.x:443?type=grpc&serviceName=/svc&security=tls"
            )),
            Some(Xray)
        );
        // ws accept-proxy-protocol is an Xray-only knob.
        assert_eq!(
            forced_core(&p(
                "vless://u@e.x:443?type=ws&security=tls&acceptProxyProtocol=1"
            )),
            Some(Xray)
        );
    }

    #[test]
    fn forced_core_struct_only_fields() {
        use crate::profile::empty_profile;
        use CoreEngine::{SingBox, Xray};

        // packetEncoding=packetaddr isn't carried on share links; set it directly.
        let mut v = p("vless://u@e.x:443?type=tcp&security=tls");
        if let Profile::Vless(x) = &mut v {
            x.packet_encoding = crate::enums::PacketEncoding::Packetaddr;
        }
        assert_eq!(forced_core(&v), Some(SingBox));

        // vmess global padding forces sing-box.
        let mut vm = empty_profile(Protocol::Vmess, "g-main");
        if let Profile::Vmess(x) = &mut vm {
            x.vmess_global_padding = true;
        }
        assert_eq!(forced_core(&vm), Some(SingBox));

        // A ws heartbeat is an Xray-only feature.
        let mut wsf = p("vless://u@e.x:443?type=ws&security=tls");
        if let Profile::Vless(x) = &mut wsf
            && let Transport::Ws(w) = &mut x.transport
        {
            w.heartbeat_period = 5;
        }
        assert_eq!(forced_core(&wsf), Some(Xray));
    }

    #[test]
    fn forced_engine_overrides_profile_core_type() {
        // tuic is sing-box-only; an explicit xray override can't move it because a
        // capability force outranks the per-profile core_type.
        let mut prof = p("tuic://u:pw@t.ex:443?sni=t.ex");
        if let Profile::Tuic(t) = &mut prof {
            t.meta.core_type = Some(CoreEngine::Xray);
        }
        let s = AdvancedSettings::default();
        assert_eq!(resolve_core(&prof, &s), CoreEngine::SingBox);
    }

    #[test]
    fn selectable_falls_through_to_override_and_table() {
        // plain vless tcp tls: not forced.
        let mut prof = p("vless://u@e.x:443?type=tcp&security=tls");
        assert_eq!(forced_core(&prof), None);
        let s = AdvancedSettings::default();
        assert_eq!(resolve_core(&prof, &s), CoreEngine::Xray); // default table

        // per-profile override wins over the table.
        if let Profile::Vless(v) = &mut prof {
            v.meta.core_type = Some(CoreEngine::SingBox);
        }
        assert_eq!(resolve_core(&prof, &s), CoreEngine::SingBox);

        // coreByProtocol table applies when there is no per-profile override.
        if let Profile::Vless(v) = &mut prof {
            v.meta.core_type = None;
        }
        let mut s2 = AdvancedSettings::default();
        s2.core_by_protocol
            .insert(Protocol::Vless, CoreEngine::SingBox);
        assert_eq!(resolve_core(&prof, &s2), CoreEngine::SingBox);
    }

    #[test]
    fn shadowsocks_over_quic_runs_on_singbox_with_every_cipher() {
        use strum::IntoEnumIterator;
        for method in SsMethod::iter() {
            let Profile::Shadowsocks(mut ss) = p(
                "ss://YWVzLTI1Ni1nY206cHc=@ss.example:8388?plugin=v2ray-plugin%3Bmode%3Dquic%3Bhost%3Dq.example#q",
            ) else {
                panic!("not shadowsocks")
            };
            ss.method = method;
            let prof = Profile::Shadowsocks(ss);
            assert_eq!(forced_core(&prof), Some(CoreEngine::SingBox), "{method:?}");
        }
    }

    #[test]
    fn xray_cipher_spellings_follow_the_core_choice() {
        for m in ["plain", "chacha20-poly1305", "xchacha20-poly1305"] {
            let mut prof = p(&format!("ss://{m}:pw@h.ex:8388#x"));
            assert_eq!(
                resolve_core(&prof, &AdvancedSettings::default()),
                CoreEngine::Xray,
                "{m}"
            );
            let mut s = AdvancedSettings::default();
            s.core_by_protocol
                .insert(Protocol::Shadowsocks, CoreEngine::SingBox);
            assert_eq!(resolve_core(&prof, &s), CoreEngine::SingBox, "{m}");
            prof.meta_mut().core_type = Some(CoreEngine::SingBox);
            assert_eq!(
                resolve_core(&prof, &AdvancedSettings::default()),
                CoreEngine::SingBox,
                "{m}"
            );
            // A v2ray-plugin transport pins sing-box, as for every cipher.
            assert_eq!(
                forced_core(&p(&format!(
                    "ss://{m}:pw@h.ex:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket#ws"
                ))),
                Some(CoreEngine::SingBox),
                "{m}"
            );
        }
    }

    #[test]
    fn plain_shadowsocks_with_a_shared_cipher_stays_selectable() {
        // aes-256-gcm runs on both cores; only a v2ray-plugin transport pins sing-box.
        assert_eq!(
            forced_core(&p("ss://YWVzLTI1Ni1nY206cHc=@ss.example:8388#plain")),
            None
        );
        assert_eq!(
            forced_core(&p(
                "ss://YWVzLTI1Ni1nY206cHc=@ss.example:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls#ws"
            )),
            Some(CoreEngine::SingBox)
        );
    }
}
