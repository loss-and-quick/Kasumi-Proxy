//! Core-engine resolution — profile override + per-protocol defaults, with
//! capability guards for transports/protocols only one core can build.

use crate::enums::{CoreEngine, Flow, HeaderType, Network, PacketEncoding, Security, SsMethod};
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
        Profile::Trojan(t) if t.flow != Flow::Empty => {
            return Some(Xray);
        }
        Profile::Shadowsocks(ss) => {
            // Ciphers only Xray implements — sing-box has the `-ietf-` chacha variant
            // only and no `plain`, so these must run on Xray even though the default
            // TLS would otherwise route shadowsocks to sing-box below.
            if matches!(
                ss.method,
                SsMethod::Plain | SsMethod::Chacha20Poly1305 | SsMethod::Xchacha20Poly1305
            ) {
                return Some(Xray);
            }
            // The 2022 AEAD ciphers and the IETF chacha variant route to sing-box.
            if matches!(
                ss.method,
                SsMethod::Chacha20IetfPoly1305
                    | SsMethod::Blake3Aes128Gcm
                    | SsMethod::Blake3Aes256Gcm
                    | SsMethod::Blake3Chacha20Poly1305
            ) {
                return Some(SingBox);
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::parse_share_link;

    fn p(uri: &str) -> Profile {
        parse_share_link(uri, None).unwrap()
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
        // trojan flow → xray
        assert_eq!(
            forced_core(&p("trojan://pw@e.x:443?security=tls&flow=xtls-rprx-vision")),
            Some(CoreEngine::Xray)
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
    fn shadowsocks_method_routing_splits_by_core() {
        use CoreEngine::{SingBox, Xray};
        // Ciphers only Xray implements (sing-box has no `plain` and only the IETF
        // chacha variant) — must route to Xray despite shadowsocks' default TLS.
        for m in ["plain", "chacha20-poly1305", "xchacha20-poly1305"] {
            assert_eq!(
                forced_core(&p(&format!("ss://{m}:pw@h.ex:443#x"))),
                Some(Xray),
                "{m} must route to xray"
            );
        }
        // The 2022 AEAD ciphers and the IETF chacha variant route to sing-box.
        for m in [
            "chacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            assert_eq!(
                forced_core(&p(&format!("ss://{m}:pw@h.ex:443#x"))),
                Some(SingBox),
                "{m} must route to sing-box"
            );
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
        // A 2022 shadowsocks AEAD method only sing-box implements.
        assert_eq!(
            forced_core(&p("ss://2022-blake3-aes-128-gcm:pw@e.x:443#X")),
            Some(SingBox)
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
}
