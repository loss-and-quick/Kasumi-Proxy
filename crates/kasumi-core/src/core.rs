//! Core-engine resolution — profile override + per-protocol defaults, with
//! capability guards for transports/protocols only one core can build.

use std::collections::BTreeMap;

use crate::chain::{chain_candidates, chain_hops};
use crate::contract::{CoreConflict, HopConflict, TargetFallback, XrayOnlySetting};
use crate::custom_sanitize::{has_unpinned_allow_insecure, sanitize_provider_xray};
use crate::enums::{
    CoreEngine, Flow, HeaderType, Network, PacketEncoding, Security, SsMethod, TunEngine,
};
use crate::mixins::Transport;
use crate::profile::{Custom, CustomOrigin, Profile, Protocol};
use crate::state::AdvancedSettings;

fn is_singbox_only(proto: Protocol) -> bool {
    matches!(
        proto,
        Protocol::Tuic | Protocol::Anytls | Protocol::Naive | Protocol::Shadowtls
    )
}

/// Which core a protocol is locked to for core presets, if it cannot be reassigned.
pub fn locked_core_for(proto: Protocol) -> Option<CoreEngine> {
    match proto {
        Protocol::Custom => Some(CoreEngine::Xray),
        Protocol::Hysteria2 => Some(CoreEngine::SingBox),
        p if is_singbox_only(p) => Some(CoreEngine::SingBox),
        _ => None,
    }
}

/// Whether the protocol is locked to a single core engine by capability.
pub fn is_locked_core_protocol(proto: Protocol) -> bool {
    locked_core_for(proto).is_some()
}

/// All protocols that are locked to a single core engine.
pub fn locked_core_protocols() -> Vec<Protocol> {
    use strum::IntoEnumIterator;
    Protocol::iter()
        .filter(|&p| is_locked_core_protocol(p))
        .collect()
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
/// if it's selectable. A profile with a [`core_conflict`] keeps the core its
/// protocol or transport pins.
pub fn forced_core(p: &Profile) -> Option<CoreEngine> {
    capability_core(p).or_else(|| skips_cert_check_unpinned(p).then_some(CoreEngine::SingBox))
}

/// TLS that skips the certificate check without a pinned certificate. Xray no
/// longer can (a pin is its only way past the check), so this takes sing-box.
pub(crate) fn skips_cert_check_unpinned(p: &Profile) -> bool {
    p.tls()
        .is_some_and(|t| t.security == Security::Tls && t.allow_insecure && t.pcs.is_empty())
}

/// Why no core can run the profile as configured, if none can.
pub fn core_conflict(p: &Profile) -> Option<CoreConflict> {
    if let Profile::Custom(c) = p {
        return custom_allows_insecure_unpinned(c).then_some(CoreConflict::CustomAllowInsecure);
    }
    (capability_core(p) == Some(CoreEngine::Xray) && skips_cert_check_unpinned(p))
        .then_some(CoreConflict::UnpinnedInsecureTls)
}

/// Checked on what xray would load: a provider config only once sanitised, so an
/// outbound the sanitiser drops doesn't count. Invalid JSON is the builder's error.
fn custom_allows_insecure_unpinned(c: &Custom) -> bool {
    let Ok(raw) = serde_json::from_str::<serde_json::Value>(&c.raw) else {
        return false;
    };
    match c.origin {
        CustomOrigin::User => has_unpinned_allow_insecure(&raw),
        CustomOrigin::Provider => sanitize_provider_xray(&raw)
            .is_ok_and(|s| s.outbounds.iter().any(has_unpinned_allow_insecure)),
    }
}

/// Whether xray can build an outbound for `p`. It has dropped its QUIC and HTTP/2
/// transports and rejects a config naming either, has no outbound for the
/// sing-box-only protocols or a custom config, and would check the certificate
/// of TLS that skips the check unpinned.
pub(crate) fn xray_builds(p: &Profile) -> bool {
    !(is_singbox_only(p.protocol())
        || p.protocol() == Protocol::Custom
        || matches!(p.transport(), Some(Transport::Quic(_) | Transport::H2(_)))
        || matches!(p, Profile::Shadowsocks(ss) if plaintext_ss(ss.method))
        || skips_cert_check_unpinned(p))
}

/// Xray dropped its plaintext Shadowsocks ciphers (`none` / `plain`) in 26.10;
/// sing-box still implements both under `none`.
fn plaintext_ss(method: SsMethod) -> bool {
    matches!(method, SsMethod::None | SsMethod::Plain)
}

/// Why `core` can't build `target` as the outbound of another profile's routing
/// rule. The config builders then send that rule's traffic through the active
/// proxy rather than fail the whole config.
pub fn rule_target_fallback(target: &Profile, core: CoreEngine) -> Option<TargetFallback> {
    if let Profile::Custom(_) = target {
        return Some(TargetFallback::CustomConfig);
    }
    (core == CoreEngine::Xray && !xray_builds(target)).then(|| match core_conflict(target) {
        Some(conflict) => TargetFallback::CantStart { conflict },
        None => TargetFallback::SingBoxOnly,
    })
}

/// [`rule_target_fallback`] for every core that has one.
pub fn rule_target_fallbacks(target: &Profile) -> BTreeMap<CoreEngine, TargetFallback> {
    use strum::IntoEnumIterator;
    CoreEngine::iter()
        .filter_map(|core| rule_target_fallback(target, core).map(|f| (core, f)))
        .collect()
}

/// One setting that pins a core: the core it needs and, for an xray-only setting,
/// the one to warn about when sing-box builds the profile anyway (`None` for an
/// xray-only setting whose loss leaves the connection working).
type Pin = (CoreEngine, Option<XrayOnlySetting>);

fn capability_core(p: &Profile) -> Option<CoreEngine> {
    capability_pins(p).first().map(|&(core, _)| core)
}

/// The xray-only settings of `p` that sing-box can't carry and that break the
/// connection without them. A profile that another setting pins to sing-box still
/// lists them, as does one a routing rule sends to sing-box.
pub fn xray_only_settings(p: &Profile) -> Vec<XrayOnlySetting> {
    let mut found = Vec::new();
    for (core, setting) in capability_pins(p) {
        if let (CoreEngine::Xray, Some(setting)) = (core, setting)
            && !found.contains(&setting)
        {
            found.push(setting);
        }
    }
    found
}

/// Every setting that pins a core, in precedence order: the first decides
/// [`capability_core`].
fn capability_pins(p: &Profile) -> Vec<Pin> {
    use CoreEngine::{SingBox, Xray};
    let proto = p.protocol();
    if proto == Protocol::Custom {
        return vec![(Xray, None)];
    }
    if is_singbox_only(proto) {
        return vec![(SingBox, None)];
    }
    let mut pins: Vec<Pin> = Vec::new();
    let pin = |pins: &mut Vec<Pin>, when: bool, core, setting| {
        if when {
            pins.push((core, setting));
        }
    };

    // ── Protocol-level differences ──
    match p {
        Profile::Vless(v) => {
            pin(
                &mut pins,
                v.flow == Flow::VisionUdp443,
                Xray,
                Some(XrayOnlySetting::VisionUdp443Flow),
            );
            pin(
                &mut pins,
                !v.encryption.is_empty() && v.encryption != "none",
                Xray,
                Some(XrayOnlySetting::VlessEncryption),
            );
            pin(
                &mut pins,
                v.packet_encoding == PacketEncoding::Packetaddr,
                SingBox,
                None,
            );
        }
        Profile::Vmess(v) => pin(
            &mut pins,
            v.packet_encoding == PacketEncoding::Packetaddr
                || v.vmess_global_padding
                || v.vmess_authenticated_length,
            SingBox,
            None,
        ),
        Profile::Shadowsocks(ss) => pin(
            // Xray dropped its QUIC transport, so v2ray-plugin's QUIC mode runs only
            // on sing-box, whatever the cipher. Xray also dropped its plaintext
            // ciphers (`none` / `plain`) in 26.10, so those pin sing-box too. The
            // remaining ciphers run on both cores (sing-box under its own names for
            // Xray's `chacha20-poly1305` / `xchacha20-poly1305`), so only a
            // v2ray-plugin or obfs-local transport, or the plugin's TLS, pins
            // sing-box.
            &mut pins,
            plaintext_ss(ss.method)
                || matches!(ss.transport, Transport::Quic(_))
                || ss.tls.security == Security::Tls
                || ss.transport.network() != Network::Tcp
                || ss.transport.header_type() == HeaderType::Http,
            SingBox,
            None,
        ),
        _ => {}
    }

    // ── Transport-level differences ──
    if let Some(t) = p.transport() {
        match t {
            Transport::H2(_) | Transport::Quic(_) => pins.push((SingBox, None)),
            Transport::Kcp(_) => pins.push((Xray, Some(XrayOnlySetting::Kcp))),
            Transport::Xhttp(_) => pins.push((Xray, Some(XrayOnlySetting::Xhttp))),
            Transport::Httpupgrade(h) => {
                pin(
                    &mut pins,
                    h.accept_proxy_protocol || h.early_data > 0,
                    Xray,
                    None,
                );
            }
            Transport::Ws(w) => {
                pin(
                    &mut pins,
                    w.heartbeat_period > 0 || w.accept_proxy_protocol,
                    Xray,
                    None,
                );
            }
            Transport::Grpc(g) => {
                // The parser folds the path fallback into `service_name`.
                pin(
                    &mut pins,
                    g.service_name.starts_with('/'),
                    Xray,
                    Some(XrayOnlySetting::GrpcServicePath),
                );
                pin(&mut pins, g.ping_timeout > 0, SingBox, None);
                pin(
                    &mut pins,
                    !g.authority.is_empty()
                        || g.mode == "multi"
                        || g.health_check_timeout > 0
                        || g.initial_window_size > 0
                        || !g.user_agent.is_empty(),
                    Xray,
                    None,
                );
            }
            Transport::Tcp(_) => {}
        }
    }

    // ── TLS / Reality-level differences (Xray-only fields) ──
    if let Some(tls) = p.tls() {
        pin(
            &mut pins,
            !tls.vcn.is_empty(),
            Xray,
            Some(XrayOnlySetting::VerifyPeerCertName),
        );
        pin(
            &mut pins,
            tls.reject_unknown_sni
                || tls.enable_session_resumption
                || (tls.security == Security::Reality && !tls.pqv.is_empty()),
            Xray,
            None,
        );
    }
    pins
}

/// The core a profile's proxy chain must run on, and the profile (`p` itself or
/// one of its hops) that needs it. Every hop is an outbound of the same config, so
/// one hop only a single core can run pins the whole chain. A broken chain counts
/// as no hops here; the config builders report it.
pub fn chain_forced_core<'a>(
    p: &'a Profile,
    profiles: &'a [Profile],
) -> Result<Option<(CoreEngine, &'a Profile)>, CoreConflict> {
    let hops = chain_hops(p, profiles).unwrap_or_default();
    let (mut xray, mut sing_box) = (None, None);
    for q in std::iter::once(p).chain(hops) {
        match forced_core(q) {
            Some(CoreEngine::Xray) => xray = xray.or(Some(q)),
            Some(CoreEngine::SingBox) => sing_box = sing_box.or(Some(q)),
            None => {}
        }
    }
    match (xray, sing_box) {
        (Some(x), Some(s)) => Err(CoreConflict::ChainCoreConflict {
            xray: x.meta().remarks.clone(),
            sing_box: s.meta().remarks.clone(),
        }),
        (Some(x), None) => Ok(Some((CoreEngine::Xray, x))),
        (None, Some(s)) => Ok(Some((CoreEngine::SingBox, s))),
        (None, None) => Ok(None),
    }
}

/// The chain candidates of `p` ([`chain_candidates`]) that would leave it with no
/// core able to build the chain, each with the conflict it would cause. `p` may be
/// an unsaved draft; it stands in for its stored copy (same id).
pub fn chain_conflicts(p: &Profile, profiles: &[Profile]) -> Vec<HopConflict> {
    let mut state: Vec<Profile> = profiles
        .iter()
        .filter(|x| x.meta().id != p.meta().id)
        .cloned()
        .collect();
    state.push(p.clone());
    let draft_idx = state.len() - 1;
    chain_candidates(p, profiles)
        .into_iter()
        .filter_map(|id| {
            state[draft_idx].meta_mut().via = Some(id.clone());
            chain_forced_core(&state[draft_idx], &state)
                .err()
                .map(|conflict| HopConflict { id, conflict })
        })
        .collect()
}

/// The core a profile runs on when nothing forces it: its override, else the
/// per-protocol table, else the protocol default.
pub fn preferred_core(p: &Profile, s: &AdvancedSettings) -> CoreEngine {
    if let Some(engine) = p.meta().core_type {
        return engine;
    }
    s.core_by_protocol
        .get(&p.protocol())
        .copied()
        .unwrap_or_else(|| default_core_for(p.protocol()))
}

/// Resolve the actual core for a profile (capabilities of the profile and its
/// chain > override > table > fallback).
pub fn resolve_core(
    p: &Profile,
    s: &AdvancedSettings,
    profiles: &[Profile],
) -> Result<CoreEngine, CoreConflict> {
    Ok(match chain_forced_core(p, profiles)? {
        Some((engine, _)) => engine,
        None => preferred_core(p, s),
    })
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

    const INSECURE: &str = "security=tls&sni=e.x&allowInsecure=1";
    const PIN: &str = "pcs=aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";

    #[test]
    fn an_unpinned_insecure_tls_profile_runs_on_singbox() {
        use CoreEngine::SingBox;
        let ws = p(&format!("vless://u@e.x:443?type=ws&{INSECURE}"));
        assert_eq!(forced_core(&ws), Some(SingBox));
        assert_eq!(core_conflict(&ws), None);
        // It outranks the user's own pick of xray.
        let mut picked = ws.clone();
        picked.meta_mut().core_type = Some(CoreEngine::Xray);
        assert_eq!(
            resolve_core(&picked, &AdvancedSettings::default(), &[]).unwrap(),
            SingBox
        );
        assert_eq!(
            forced_core(&p("hysteria2://pw@h.x:443?sni=h.x&insecure=1")),
            Some(SingBox)
        );
        // A pinned certificate is xray's own way past the check.
        let pinned = p(&format!("vless://u@e.x:443?type=ws&{INSECURE}&{PIN}"));
        assert_eq!(forced_core(&pinned), None);
    }

    #[test]
    fn an_xray_only_unpinned_insecure_profile_is_refused() {
        let xhttp = p(&format!("vless://u@e.x:443?type=xhttp&{INSECURE}"));
        assert_eq!(
            core_conflict(&xhttp),
            Some(CoreConflict::UnpinnedInsecureTls)
        );
        assert_eq!(forced_core(&xhttp), Some(CoreEngine::Xray));
        let err = crate::core_config::build_core_config(
            &xhttp,
            &AdvancedSettings::default(),
            &[],
            std::slice::from_ref(&xhttp),
            "",
            crate::data_path_plan::TEST_HOST,
        )
        .unwrap_err();
        assert_eq!(err, CoreConflict::UnpinnedInsecureTls.to_string());
        // A pin or a certificate check lets it run on xray.
        let pinned = p(&format!("vless://u@e.x:443?type=xhttp&{INSECURE}&{PIN}"));
        assert_eq!(core_conflict(&pinned), None);
        let checked = p("vless://u@e.x:443?type=xhttp&security=tls&sni=e.x");
        assert_eq!(core_conflict(&checked), None);
    }

    #[test]
    fn rule_target_fallback_names_why() {
        use CoreEngine::{SingBox, Xray};
        let fallbacks = |uri: &str| rule_target_fallbacks(&p(uri));
        assert_eq!(
            fallbacks("vless://u@e.x:443?type=tcp&security=tls"),
            BTreeMap::new()
        );
        let only_singbox = BTreeMap::from([(Xray, TargetFallback::SingBoxOnly)]);
        assert_eq!(fallbacks("tuic://u:pw@t.ex:443?sni=t.ex"), only_singbox);
        // Xray can't build the plaintext Shadowsocks cipher either.
        assert_eq!(
            fallbacks("ss://bm9uZTpwYXNzd29yZDEyMw==@ss.example:8388#none"),
            only_singbox
        );
        assert_eq!(
            fallbacks("vless://u@e.x:443?type=h2&security=tls"),
            only_singbox
        );
        assert_eq!(
            fallbacks(&format!("vless://u@e.x:443?type=ws&{INSECURE}")),
            only_singbox
        );
        // Sing-box still builds an xray-only profile, without the parts it lacks.
        assert_eq!(
            fallbacks(&format!("vless://u@e.x:443?type=xhttp&{INSECURE}")),
            BTreeMap::from([(
                Xray,
                TargetFallback::CantStart {
                    conflict: CoreConflict::UnpinnedInsecureTls
                }
            )])
        );
        let custom: Profile = serde_json::from_value(serde_json::json!({
            "protocol": "custom",
            "meta": { "id": "c", "remarks": "C", "groupId": "g-main" },
            "raw": "{}",
        }))
        .unwrap();
        assert_eq!(
            rule_target_fallbacks(&custom),
            BTreeMap::from([
                (Xray, TargetFallback::CustomConfig),
                (SingBox, TargetFallback::CustomConfig),
            ])
        );
    }

    #[test]
    fn xray_only_settings_list_what_breaks_on_singbox() {
        use XrayOnlySetting::{GrpcServicePath, Kcp, VerifyPeerCertName, VlessEncryption, Xhttp};
        let found = |uri: &str| xray_only_settings(&p(uri));
        assert_eq!(found("vless://u@e.x:443?type=xhttp&security=tls"), [Xhttp]);
        assert_eq!(found("vless://u@e.x:443?type=kcp"), [Kcp]);
        assert_eq!(
            found("vless://u@e.x:443?type=tcp&security=tls&encryption=mlkem768"),
            [VlessEncryption]
        );
        assert_eq!(
            found("vless://u@e.x:443?type=grpc&security=tls&serviceName=/x/Tun"),
            [GrpcServicePath]
        );
        assert_eq!(
            found("vless://u@e.x:443?type=xhttp&security=tls&vcn=a.x"),
            [Xhttp, VerifyPeerCertName]
        );
        // Xray-only, but sing-box connects without them.
        assert!(found("vless://u@e.x:443?type=ws&heartbeatPeriod=30").is_empty());
        assert!(found("tuic://u:pw@t.ex:443?sni=t.ex").is_empty());
        // A sing-box pin that comes first doesn't hide what sing-box then drops.
        let mut both = p("vless://u@e.x:443?type=kcp");
        let Profile::Vless(v) = &mut both else {
            unreachable!()
        };
        v.packet_encoding = PacketEncoding::Packetaddr;
        assert_eq!(forced_core(&both), Some(CoreEngine::SingBox));
        assert_eq!(xray_only_settings(&both), [Kcp]);
    }

    #[test]
    fn every_shadowsocks_cipher_runs_on_a_core_that_supports_it() {
        use strum::IntoEnumIterator;
        for method in SsMethod::iter() {
            let with = |uri: &str| {
                let Profile::Shadowsocks(mut ss) = p(uri) else {
                    panic!("not shadowsocks")
                };
                ss.method = method;
                Profile::Shadowsocks(ss)
            };
            // Xray dropped the plaintext ciphers; everything else runs on both.
            let expected = if matches!(method, SsMethod::None | SsMethod::Plain) {
                Some(CoreEngine::SingBox)
            } else {
                None
            };
            assert_eq!(
                forced_core(&with("ss://YWVzLTI1Ni1nY206cHc=@h.ex:8388#x")),
                expected,
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
        assert_eq!(resolve_core(&prof, &s, &[]).unwrap(), CoreEngine::SingBox);
    }

    #[test]
    fn selectable_falls_through_to_override_and_table() {
        // plain vless tcp tls: not forced.
        let mut prof = p("vless://u@e.x:443?type=tcp&security=tls");
        assert_eq!(forced_core(&prof), None);
        let s = AdvancedSettings::default();
        assert_eq!(resolve_core(&prof, &s, &[]).unwrap(), CoreEngine::Xray); // default table

        // per-profile override wins over the table.
        if let Profile::Vless(v) = &mut prof {
            v.meta.core_type = Some(CoreEngine::SingBox);
        }
        assert_eq!(resolve_core(&prof, &s, &[]).unwrap(), CoreEngine::SingBox);

        // coreByProtocol table applies when there is no per-profile override.
        if let Profile::Vless(v) = &mut prof {
            v.meta.core_type = None;
        }
        let mut s2 = AdvancedSettings::default();
        s2.core_by_protocol
            .insert(Protocol::Vless, CoreEngine::SingBox);
        assert_eq!(resolve_core(&prof, &s2, &[]).unwrap(), CoreEngine::SingBox);
    }

    fn chained(uri: &str, id: &str, via: Option<&str>) -> Profile {
        let mut prof = p(uri);
        prof.meta_mut().id = id.into();
        prof.meta_mut().remarks = id.into();
        prof.meta_mut().via = via.map(str::to_owned);
        prof
    }

    #[test]
    fn a_hop_only_one_core_runs_pins_the_chain() {
        let s = AdvancedSettings::default();
        let mut exit = chained(
            "vless://u@e.x:443?type=tcp&security=tls",
            "exit",
            Some("mid"),
        );
        exit.meta_mut().core_type = Some(CoreEngine::Xray);
        let all = vec![
            exit.clone(),
            chained("tuic://u:pw@t.ex:443?sni=t.ex", "mid", Some("entry")),
            chained("vless://u@n.x:443?type=tcp&security=tls", "entry", None),
        ];
        // The tuic hop outranks the exit's own xray override.
        assert_eq!(resolve_core(&exit, &s, &all).unwrap(), CoreEngine::SingBox);
        let (engine, by) = chain_forced_core(&exit, &all).unwrap().unwrap();
        assert_eq!(
            (engine, by.meta().id.as_str()),
            (CoreEngine::SingBox, "mid")
        );

        // An xray-only entry hop pins xray the same way.
        let all = vec![
            chained(
                "vless://u@e.x:443?type=tcp&security=tls",
                "exit",
                Some("entry"),
            ),
            chained("vless://u@n.x:443?type=xhttp&security=tls", "entry", None),
        ];
        assert_eq!(resolve_core(&all[0], &s, &all).unwrap(), CoreEngine::Xray);
    }

    #[test]
    fn hops_that_need_different_cores_conflict() {
        let s = AdvancedSettings::default();
        let all = vec![
            chained(
                "vless://u@e.x:443?type=xhttp&security=tls",
                "exit",
                Some("mid"),
            ),
            chained("tuic://u:pw@t.ex:443?sni=t.ex", "mid", None),
        ];
        let conflict = resolve_core(&all[0], &s, &all).unwrap_err();
        assert_eq!(
            conflict,
            CoreConflict::ChainCoreConflict {
                xray: "exit".into(),
                sing_box: "mid".into(),
            }
        );
        // The hop alone, without the exit, is fine.
        assert_eq!(
            resolve_core(&all[1], &s, &all).unwrap(),
            CoreEngine::SingBox
        );
    }

    #[test]
    fn chain_conflicts_name_the_hops_that_need_the_other_core() {
        let all = vec![
            chained("vless://u@e.x:443?type=xhttp&security=tls", "exit", None),
            chained("tuic://u:pw@t.ex:443?sni=t.ex", "tuic", None),
            chained("trojan://pw@h.x:443?security=tls", "plain", None),
        ];
        assert_eq!(
            chain_conflicts(&all[0], &all),
            [HopConflict {
                id: "tuic".into(),
                conflict: CoreConflict::ChainCoreConflict {
                    xray: "exit".into(),
                    sing_box: "tuic".into(),
                },
            }]
        );
        // An unsaved draft stands in for its stored copy.
        let draft = chained("trojan://pw@d.x:443?security=tls", "plain", None);
        assert!(chain_conflicts(&draft, &all).is_empty());
    }

    #[test]
    fn unforced_chain_keeps_the_profiles_own_choice() {
        let mut s = AdvancedSettings::default();
        s.core_by_protocol
            .insert(Protocol::Vless, CoreEngine::SingBox);
        let all = vec![
            chained(
                "vless://u@e.x:443?type=tcp&security=tls",
                "exit",
                Some("hop"),
            ),
            chained("trojan://pw@h.x:443?security=tls", "hop", None),
        ];
        assert_eq!(chain_forced_core(&all[0], &all).unwrap(), None);
        assert_eq!(
            resolve_core(&all[0], &s, &all).unwrap(),
            CoreEngine::SingBox
        );
        // A broken chain doesn't force anything; the builders report it.
        let looped = vec![chained("tuic://u:pw@t.ex:443?sni=t.ex", "a", Some("a"))];
        assert_eq!(
            resolve_core(&looped[0], &s, &looped).unwrap(),
            CoreEngine::SingBox
        );
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
        for (m, default) in [
            ("plain", CoreEngine::SingBox),
            ("chacha20-poly1305", CoreEngine::Xray),
            ("xchacha20-poly1305", CoreEngine::Xray),
        ] {
            let mut prof = p(&format!("ss://{m}:pw@h.ex:8388#x"));
            assert_eq!(
                resolve_core(&prof, &AdvancedSettings::default(), &[]).unwrap(),
                default,
                "{m}"
            );
            let mut s = AdvancedSettings::default();
            s.core_by_protocol
                .insert(Protocol::Shadowsocks, CoreEngine::SingBox);
            assert_eq!(
                resolve_core(&prof, &s, &[]).unwrap(),
                CoreEngine::SingBox,
                "{m}"
            );
            prof.meta_mut().core_type = Some(CoreEngine::SingBox);
            assert_eq!(
                resolve_core(&prof, &AdvancedSettings::default(), &[]).unwrap(),
                CoreEngine::SingBox,
                "{m}"
            );
            // A plaintext cipher can't be forced back onto Xray, which dropped it.
            if default == CoreEngine::SingBox {
                prof.meta_mut().core_type = Some(CoreEngine::Xray);
                assert_eq!(
                    resolve_core(&prof, &AdvancedSettings::default(), &[]).unwrap(),
                    CoreEngine::SingBox,
                    "{m}"
                );
            }
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
