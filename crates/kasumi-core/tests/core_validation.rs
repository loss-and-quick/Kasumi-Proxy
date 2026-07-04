//! Validates that the configs our builders emit are actually accepted by the real
//! cores (`xray run -test` / `sing-box check`), catching schema drift — e.g. a field
//! our builder emits that a pinned core version rejects. This is the config-output
//! safety net: `core-compat.yml` runs it with staged cores on every PR touching
//! `crates/kasumi-core/**`.
//!
//! The case matrix is GENERATED from our own enums (`Protocol`, `Network`,
//! `Security`, `SsMethod`, `VmessEnc`, `Fingerprint`, `CongestionControl` via
//! `strum::IntoEnumIterator`), not hand-written, so a new protocol/transport/enum
//! variant is swept automatically. On top of the enum sweeps, explicit per-field
//! cases exercise the builder branches that defaults alone don't trigger (e.g.
//! Hysteria2 bandwidth → brutal congestion, SS+WS → v2ray-plugin plugin_opts,
//! TLS cipher suites, gRPC advanced sub-fields).
//!
//! The binaries are NOT committed; stage them with `scripts/fetch-binaries.sh desktop`
//! (pinned versions in `scripts/binary-versions.sh`). When they're absent — as in a
//! plain CI checkout — every case is skipped and the test passes, so this never
//! blocks the normal `cargo test --workspace` path. Point at custom binaries with
//! `KASUMI_XRAY_BIN` / `KASUMI_SINGBOX_BIN`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use strum::IntoEnumIterator;

use kasumi_core::core_config::build_core_config;
use kasumi_core::enums::{
    CongestionControl, CoreEngine, Fingerprint, Flow, HeaderType, Hysteria2Obfs, Network,
    PacketEncoding, Security, SsMethod, VmessEnc,
};
use kasumi_core::mixins::Transport;
use kasumi_core::profile::{Profile, Protocol};
use kasumi_core::state::{
    AdvancedSettings, DomainStrategy, LogLevel, MuxXudp443, RoutingMode, RoutingRule,
};

// ── valid credential / crypto material (cores validate these) ──
const UUID: &str = "11111111-1111-1111-1111-111111111111";
const PW: &str = "password123";
const WG_PRIV: &str = "sOs7Qk6VSmoowjvnQw37LUnV39bIG2rOjmmVItntGUw=";
const WG_PUB: &str = "xK8Tw4nv6TBWHl3WlVqoMLVrNsejQdC7/7jiTlR2rg8=";
// A valid base64 32-byte WireGuard pre-shared key (reuses a valid key shape).
const WG_PSK: &str = "YAnz7T2bQ4uR7Mm3y3Hzx2Ysj5PE2lqZqDY8Y8QpZHM=";
const REALITY_PBK: &str = "c7twR4u_IvJsLGDqYsx2yb1nr2Kg74vsRlA_ou8c4QQ";
const SS_KEY_16: &str = "MTIzNDU2Nzg5MGFiY2RlZg==";
const SS_KEY_32: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
// A valid base64 ECHConfigList (`sing-box generate ech-keypair example.com`),
// the raw form share links carry in the `ech` parameter.
const ECH_CONFIG_LIST_B64: &str = "AEb+DQBCAAAgACAYjkLlzMEK3J2Dcv8wBSVwYDz4j8o9tRSTBPSr+m52FwAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA";
// A 64-char hex SHA-256 (xray `pinnedPeerCertSha256`) — cores syntax-check it.
const PCS_HEX: &str = "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";

/// The wire string of a serde enum (e.g. `Network::Ws` → `"ws"`).
fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn tls_carrying(p: Protocol) -> bool {
    matches!(
        p,
        Protocol::Vless
            | Protocol::Vmess
            | Protocol::Trojan
            | Protocol::Shadowsocks
            | Protocol::Http
            | Protocol::Hysteria2
            | Protocol::Tuic
            | Protocol::Anytls
            | Protocol::Naive
            | Protocol::Shadowtls
    )
}

/// Protocol-specific credentials a config needs to be buildable + core-valid.
fn creds(seed: &mut Value, proto: Protocol) {
    let put = |seed: &mut Value, k: &str, v: &str| seed[k] = json!(v);
    match proto {
        Protocol::Vless | Protocol::Vmess => put(seed, "uuid", UUID),
        Protocol::Tuic => {
            put(seed, "uuid", UUID);
            put(seed, "password", PW);
        }
        Protocol::Trojan | Protocol::Hysteria2 | Protocol::Anytls | Protocol::Shadowtls => {
            put(seed, "password", PW)
        }
        Protocol::Naive | Protocol::Socks | Protocol::Http => {
            put(seed, "username", "user");
            put(seed, "password", PW);
        }
        Protocol::Shadowsocks => {
            put(seed, "password", PW);
            put(seed, "method", "aes-256-gcm");
        }
        Protocol::Wireguard => {
            put(seed, "secretKey", WG_PRIV);
            put(seed, "peerPublicKey", WG_PUB);
        }
        Protocol::Custom => {}
    }
}

/// Build a profile seed for a protocol with an optional transport + TLS mode.
fn make(
    proto: Protocol,
    network: Option<Network>,
    security: Security,
    name: &str,
) -> Option<Profile> {
    if proto == Protocol::Custom {
        return None; // no buildable launch config
    }
    let mut seed = json!({
        "protocol": wire(&proto),
        "meta": { "id": "", "remarks": name, "groupId": "g-main" },
        "endpoint": { "address": "e.example", "port": 443 },
    });
    creds(&mut seed, proto);

    if let Some(net) = network {
        let mut t = json!({ "kind": wire(&net) });
        if net == Network::Grpc {
            t["serviceName"] = json!("GunService");
        }
        seed["transport"] = t;
    }

    if tls_carrying(proto) {
        let mut tls = json!({ "security": wire(&security), "sni": "s.example" });
        if security == Security::Reality {
            tls["publicKey"] = json!(REALITY_PBK);
            tls["shortId"] = json!("ab");
            tls["fingerprint"] = json!("chrome");
        }
        seed["tls"] = tls;
        if security == Security::Reality && proto == Protocol::Vless {
            seed["flow"] = json!("xtls-rprx-vision");
        }
    }

    serde_json::from_value(seed).ok()
}

/// The base64 key a shadowsocks method needs (2022 AEAD methods are length-checked).
fn ss_key(method: SsMethod) -> &'static str {
    match method {
        SsMethod::Blake3Aes128Gcm => SS_KEY_16,
        SsMethod::Blake3Aes256Gcm | SsMethod::Blake3Chacha20Poly1305 => SS_KEY_32,
        _ => PW,
    }
}

/// Every case to validate, generated by sweeping our enums.
fn generate() -> Vec<(String, Profile)> {
    let mut cases: Vec<(String, Profile)> = Vec::new();

    // 1. Every protocol once (default transport, TLS).
    for proto in Protocol::iter() {
        let name = format!("proto/{}", wire(&proto));
        if let Some(p) = make(proto, None, Security::Tls, &name) {
            cases.push((name, p));
        }
    }

    // 2. Transport-carrying protocols × every transport (TLS).
    for proto in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
        for net in Network::iter() {
            let name = format!("xport/{}-{}", wire(&proto), wire(&net));
            if let Some(p) = make(proto, Some(net), Security::Tls, &name) {
                cases.push((name, p));
            }
        }
    }

    // 3. Shadowsocks × every cipher (TCP).
    for method in SsMethod::iter() {
        let name = format!("ss/{}", wire(&method));
        if let Some(Profile::Shadowsocks(mut s)) =
            make(Protocol::Shadowsocks, None, Security::Tls, &name)
        {
            s.method = method;
            s.password = ss_key(method).to_string();
            cases.push((name, Profile::Shadowsocks(s)));
        }
    }

    // 4. VLESS × every TLS security mode (TCP).
    for sec in Security::iter() {
        let name = format!("sec/vless-{}", wire(&sec));
        if let Some(p) = make(Protocol::Vless, Some(Network::Tcp), sec, &name) {
            cases.push((name, p));
        }
    }

    // 5. VLESS-WS carrying an ECH config. Share links ship the raw base64
    // ECHConfigList; sing-box wants it PEM-armored, so this exercises the
    // wrapping in `singbox_config` against the real `sing-box check`.
    {
        let name = "ech/vless-ws".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Ws), Security::Tls, &name)
        {
            v.tls.ech = ECH_CONFIG_LIST_B64.to_string();
            cases.push((name, Profile::Vless(v)));
        }
    }

    // ── explicit per-field cases ──
    //
    // The enum sweeps above exercise every protocol/transport/security/cipher with
    // DEFAULT field values. The cases below set non-default values that trigger
    // distinct builder branches the sweeps don't reach — each branch produces a
    // different config shape that a schema-drift could break silently.

    // 6. VMess × every cipher variant (the enum sweep only hits the default).
    for enc in VmessEnc::iter() {
        let name = format!("vmess-cipher/{}", wire(&enc));
        if let Some(Profile::Vmess(mut v)) =
            make(Protocol::Vmess, Some(Network::Tcp), Security::Tls, &name)
        {
            v.encryption = enc;
            cases.push((name, Profile::Vmess(v)));
        }
    }

    // 7. VMess advanced fields: non-zero alter_id + global_padding +
    //    authenticated_length + packet_encoding. sing-box emits each; defaults
    //    leave them unset so the branches aren't exercised by the sweep.
    {
        let name = "vmess-advanced".to_string();
        if let Some(Profile::Vmess(mut v)) =
            make(Protocol::Vmess, Some(Network::Tcp), Security::Tls, &name)
        {
            v.alter_id = 64;
            v.vmess_global_padding = true;
            v.vmess_authenticated_length = true;
            v.packet_encoding = PacketEncoding::Xudp;
            cases.push((name, Profile::Vmess(v)));
        }
    }

    // 8. VLESS packet_encoding variants the builder branches on. `packetaddr`
    //    produces a different outbound field than the default xudp.
    {
        let name = "vless-packetaddr".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Tcp), Security::Tls, &name)
        {
            v.packet_encoding = PacketEncoding::Packetaddr;
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 9. VLESS flow = xtls-rprx-vision-udp443 (the sweep only covers vision).
    {
        let name = "vless-vision-udp443".to_string();
        if let Some(Profile::Vless(mut v)) = make(
            Protocol::Vless,
            Some(Network::Tcp),
            Security::Reality,
            &name,
        ) {
            v.flow = Flow::VisionUdp443;
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 10. Shadowtls version 1 and 2 (the protocol sweep only hits default 3).
    for ver in [1i64, 2] {
        let name = format!("shadowtls-v{ver}");
        if let Some(Profile::Shadowtls(mut s)) =
            make(Protocol::Shadowtls, None, Security::Tls, &name)
        {
            s.version = ver;
            cases.push((name, Profile::Shadowtls(s)));
        }
    }

    // 11. Hysteria2 with up/down bandwidth — flips congestion to "brutal" and
    //     emits brutalUp/brutalDown (xray) or up_mbps/down_mbps (sing-box).
    {
        let name = "hysteria2-brutal".to_string();
        if let Some(Profile::Hysteria2(mut h)) =
            make(Protocol::Hysteria2, None, Security::Tls, &name)
        {
            h.up_mbps = 100;
            h.down_mbps = 100;
            cases.push((name, Profile::Hysteria2(h)));
        }
    }

    // 12. Hysteria2 with port hopping + salamander obfs — exercises the
    //     server_ports/hop_interval builder branch (sing-box) and the
    //     finalmask.udpHop/finalmask.udp.salamander branch (xray).
    {
        let name = "hysteria2-hop-obfs".to_string();
        if let Some(Profile::Hysteria2(mut h)) =
            make(Protocol::Hysteria2, None, Security::Tls, &name)
        {
            h.ports = "20000-30000".into();
            h.hop_interval = "30".into();
            h.obfs_type = Hysteria2Obfs::Salamander;
            h.obfs_password = "obfspass".into();
            cases.push((name, Profile::Hysteria2(h)));
        }
    }

    // 13. Naive with QUIC transport enabled — flips the `quic` bool sing-box
    //     validates (a separate config shape from the default TCP/HTTP/2).
    {
        let name = "naive-quic".to_string();
        if let Some(Profile::Naive(mut n)) = make(Protocol::Naive, None, Security::Tls, &name) {
            n.naive_quic = true;
            cases.push((name, Profile::Naive(n)));
        }
    }

    // 14. TUIC non-default congestion control + udp_relay_mode + zero_rtt +
    //     heartbeat. sing-box emits each as a distinct outbound field.
    for cc in [CongestionControl::Cubic, CongestionControl::NewReno] {
        let name = format!("tuic-cc/{}", wire(&cc));
        if let Some(Profile::Tuic(mut t)) = make(Protocol::Tuic, None, Security::Tls, &name) {
            t.congestion_control = cc;
            t.udp_relay_mode = "native".into();
            t.zero_rtt = true;
            t.heartbeat = "10s".into();
            cases.push((name, Profile::Tuic(t)));
        }
    }

    // 15. WireGuard with pre_shared_key + persistent_keepalive + reserved
    //     bytes. Both builders emit each conditionally; defaults skip them.
    {
        let name = "wireguard-full".to_string();
        if let Some(Profile::Wireguard(mut w)) =
            make(Protocol::Wireguard, None, Security::None, &name)
        {
            w.pre_shared_key = WG_PSK.into();
            w.persistent_keepalive = 25;
            w.reserved = vec![0, 0, 0];
            cases.push((name, Profile::Wireguard(w)));
        }
    }

    // 16. Shadowsocks plugin code paths. SS+WS triggers the v2ray-plugin
    //     websocket branch; SS+TCP+http-header triggers obfs-local. Neither
    //     is reached by the SS cipher sweep (which uses TCP+TLS).
    {
        let name = "ss-plugin/ws".to_string();
        if let Some(Profile::Shadowsocks(mut s)) = make(
            Protocol::Shadowsocks,
            Some(Network::Ws),
            Security::Tls,
            &name,
        ) {
            if let Transport::Ws(ref mut w) = s.transport {
                w.host = "cdn.example".into();
                w.path = "/sw".into();
            }
            cases.push((name, Profile::Shadowsocks(s)));
        }
    }
    {
        let name = "ss-plugin/obfs-http".to_string();
        if let Some(Profile::Shadowsocks(mut s)) = make(
            Protocol::Shadowsocks,
            Some(Network::Tcp),
            Security::None,
            &name,
        ) {
            if let Transport::Tcp(ref mut tc) = s.transport {
                tc.header_type = HeaderType::Http;
                tc.host = "obfs.example".into();
                tc.path = "/".into();
            }
            cases.push((name, Profile::Shadowsocks(s)));
        }
    }

    // 17. TLS sub-fields on VLESS+TLS that the builder emits conditionally.
    //     Each is a distinct tlsSettings / tls object key a core must accept.
    {
        let name = "tls-fields/full".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Tcp), Security::Tls, &name)
        {
            v.tls.fingerprint = Fingerprint::Firefox;
            v.tls.alpn = vec!["h2".into(), "http/1.1".into()];
            v.tls.tls_min_version = "1.2".into();
            v.tls.tls_max_version = "1.3".into();
            v.tls.tls_cipher_suites = vec!["TLS_AES_128_GCM_SHA256".into()];
            v.tls.tls_curve_preferences = vec!["X25519".into()];
            v.tls.pcs = PCS_HEX.into();
            v.tls.reject_unknown_sni = true;
            v.tls.enable_session_resumption = true;
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 18. Reality sub-fields: spider_x (xray only) — emitted into realitySettings.
    {
        let name = "reality/spider-x".to_string();
        if let Some(Profile::Vless(mut v)) = make(
            Protocol::Vless,
            Some(Network::Tcp),
            Security::Reality,
            &name,
        ) {
            v.tls.spider_x = "/abc123".into();
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 19. gRPC transport sub-fields (authority, multiMode, idle_timeout,
    //     permit_without_stream, initial_window_size, user_agent).
    {
        let name = "grpc-advanced".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Grpc), Security::Tls, &name)
        {
            if let Transport::Grpc(ref mut g) = v.transport {
                g.authority = "grpc.example".into();
                g.mode = "multi".into();
                g.idle_timeout = 60;
                g.health_check_timeout = 30;
                g.ping_timeout = 20;
                g.permit_without_stream = true;
                g.initial_window_size = 65536;
                g.user_agent = "grpc-test".into();
            }
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 20. WS transport sub-fields (early_data, early_data_header,
    //     heartbeat_period, accept_proxy_protocol, custom headers).
    {
        let name = "ws-advanced".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Ws), Security::Tls, &name)
        {
            if let Transport::Ws(ref mut w) = v.transport {
                w.host = "cdn.example".into();
                w.path = "/sw".into();
                w.early_data = 2048;
                w.early_data_header = "Sec-WebSocket-Protocol".into();
                w.heartbeat_period = 30;
                w.accept_proxy_protocol = true;
                w.headers.insert("X-Custom".into(), "value".into());
            }
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 21. mKCP transport sub-fields (mtu, tti, uplink, downlink, cwnd_multiplier,
    //     max_sending_window, seed).
    {
        let name = "kcp-advanced".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Kcp), Security::Tls, &name)
        {
            if let Transport::Kcp(ref mut k) = v.transport {
                k.header_type = HeaderType::WechatVideo;
                k.seed = "kcpseed".into();
                k.mtu = 1350;
                k.tti = 50;
                k.uplink = 50;
                k.downlink = 100;
                k.cwnd_multiplier = 2;
                k.max_sending_window = 128;
            }
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 22. XHTTP transport sub-fields (mode + extra JSON blob).
    {
        let name = "xhttp-mode".to_string();
        if let Some(Profile::Vless(mut v)) =
            make(Protocol::Vless, Some(Network::Xhttp), Security::Tls, &name)
        {
            if let Transport::Xhttp(ref mut x) = v.transport {
                x.host = "xhttp.example".into();
                x.path = "/xh".into();
                x.mode = "packet-up".into();
                x.extra = r#"{"x":"y"}"#.into();
            }
            cases.push((name, Profile::Vless(v)));
        }
    }

    // 23. HTTPUpgrade early data + acceptProxyProtocol.
    {
        let name = "httpupgrade-ed".to_string();
        if let Some(Profile::Vless(mut v)) = make(
            Protocol::Vless,
            Some(Network::Httpupgrade),
            Security::Tls,
            &name,
        ) {
            if let Transport::Httpupgrade(ref mut h) = v.transport {
                h.host = "hu.example".into();
                h.path = "/hu".into();
                h.early_data = 2048;
                h.accept_proxy_protocol = true;
            }
            cases.push((name, Profile::Vless(v)));
        }
    }

    cases
}

// ── settings/routing matrix ──
//
// The protocol sweep above exercises every protocol/transport/security with
// DEFAULT settings and no rules. To also cover the config-builder branches the
// golden fixtures used to pin (routing modes, sniffing, fragment, mux, socks auth,
// fake-dns, LAN listen, domain strategy, DNS routing), sweep a representative
// profile through a settings matrix — once per engine (forced via
// `core_by_protocol`) so both builders are exercised. Variants are geo-independent
// except where noted (`needs_geo`): routing-rules mode is covered with plain
// domain/IP rules that need no geoip/geosite/srs data, so the matrix runs wherever
// the cores are staged; a geo-needing variant (e.g. xray fake-dns, whose DNS rule
// references `geoip:!private`) is skipped when `geoip.dat` isn't present.

/// A config to validate: profile + the settings/rules it's built with. `needs_geo`
/// marks a case whose emitted config references geoip/geosite data not staged by
/// `fetch-binaries.sh` — it's validated only when that data is available.
struct Case {
    name: String,
    profile: Profile,
    settings: AdvancedSettings,
    rules: Vec<RoutingRule>,
    needs_geo: bool,
}

/// A couple of plain (non-geo) routing rules: a domain → direct and an IP →
/// direct. These exercise Rules-mode rule emission without needing geo data.
fn plain_rules() -> Vec<RoutingRule> {
    vec![
        RoutingRule {
            id: "d".into(),
            remarks: "direct-domain".into(),
            enabled: true,
            outbound_tag: "direct".into(),
            domain: Some(vec!["example.com".into()]),
            ip: None,
            port: None,
            network: None,
            protocol: None,
        },
        RoutingRule {
            id: "i".into(),
            remarks: "direct-ip".into(),
            enabled: true,
            outbound_tag: "direct".into(),
            domain: None,
            ip: Some(vec!["10.0.0.0/8".into()]),
            port: None,
            network: None,
            protocol: None,
        },
    ]
}

/// Rules exercising the port / network / protocol match fields (both builders
/// emit these into routing rule objects).
fn match_field_rules() -> Vec<RoutingRule> {
    vec![RoutingRule {
        id: "pnp".into(),
        remarks: "port-network-protocol".into(),
        enabled: true,
        outbound_tag: "direct".into(),
        domain: Some(vec!["cdn.example".into()]),
        ip: None,
        port: Some("80,443,8080-8090".into()),
        network: Some(kasumi_core::state::RuleNetwork::Tcp),
        protocol: Some(vec!["http".into()]),
    }]
}

/// Named settings/rules variants, each exercising a distinct builder branch. The
/// trailing bool is `needs_geo` — true when the emitted config references geoip/
/// geosite data (xray fake-dns pulls `geoip:!private` into the DNS block).
fn settings_variants() -> Vec<(&'static str, AdvancedSettings, Vec<RoutingRule>, bool)> {
    // Each variant is a single (or couple of) field override(s) on the defaults —
    // written with struct-update syntax rather than `mut … = default()` so the
    // intent (which branch is exercised) reads off the field name.
    vec![
        (
            "global",
            AdvancedSettings {
                routing_mode: RoutingMode::Global,
                ..Default::default()
            },
            vec![],
            false,
        ),
        (
            "rules-empty",
            AdvancedSettings {
                routing_mode: RoutingMode::Rules,
                ..Default::default()
            },
            vec![],
            false,
        ),
        // Rules mode with plain (non-geo) rules + sniffing/routeOnly toggled.
        (
            "rules-sniff-routonly",
            AdvancedSettings {
                routing_mode: RoutingMode::Rules,
                domain_sniffing: true,
                route_only: true,
                ..Default::default()
            },
            plain_rules(),
            false,
        ),
        // Rules mode with port + network + protocol match fields.
        (
            "rules-match-fields",
            AdvancedSettings {
                routing_mode: RoutingMode::Rules,
                ..Default::default()
            },
            match_field_rules(),
            false,
        ),
        // Every domain strategy the builder branches on.
        (
            "ds-asis",
            AdvancedSettings {
                domain_strategy: DomainStrategy::AsIs,
                ..Default::default()
            },
            vec![],
            false,
        ),
        (
            "ds-ipondemand",
            AdvancedSettings {
                domain_strategy: DomainStrategy::IpOnDemand,
                ..Default::default()
            },
            vec![],
            false,
        ),
        // xray outbound features.
        (
            "fragment",
            AdvancedSettings {
                fragment: true,
                ..Default::default()
            },
            vec![],
            false,
        ),
        // xray fragment with explicit sub-settings (packets + length + delay).
        (
            "fragment-subs",
            AdvancedSettings {
                fragment: true,
                fragment_packets: "tlshello".into(),
                fragment_length: Some("50-100".into()),
                fragment_delay: Some("10-20".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        (
            "mux",
            AdvancedSettings {
                mux: true,
                ..Default::default()
            },
            vec![],
            false,
        ),
        // xray mux with xudp sub-settings (xudpConcurrency + xudpProxyUDP443).
        (
            "mux-xudp",
            AdvancedSettings {
                mux: true,
                mux_xudp_concurrency: Some(8),
                mux_xudp443: Some(MuxXudp443::Reject),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // Local-inbound auth (both fields required to engage).
        (
            "socks-auth",
            AdvancedSettings {
                socks_username: Some("u".into()),
                socks_password: Some("p".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // DNS branches. fake-dns emits `geoip:!private` on xray → needs geoip.dat.
        (
            "fake-dns",
            AdvancedSettings {
                fake_dns: true,
                ..Default::default()
            },
            vec![],
            true,
        ),
        (
            "dns-direct",
            AdvancedSettings {
                dns_via_proxy: false,
                ..Default::default()
            },
            vec![],
            false,
        ),
        // DoH/DoT via a URL scheme in the address field — both an IP endpoint and a
        // domain endpoint (the latter exercises the bootstrap `domain_resolver`).
        (
            "dns-doh-ip",
            AdvancedSettings {
                remote_dns: Some("https://1.1.1.1/dns-query".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        (
            "dns-doh-domain",
            AdvancedSettings {
                remote_dns: Some("https://cloudflare-dns.com/dns-query".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // DoT via the tls:// scheme — a different DNS server type the builder emits.
        (
            "dns-dot",
            AdvancedSettings {
                remote_dns: Some("tls://1.1.1.1:853".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // DNS hosts (the `hosts` block both builders parse from the text field).
        (
            "dns-hosts",
            AdvancedSettings {
                dns_hosts: Some("example.com=1.2.3.4".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // Domestic DNS — sing-box emits it as the `local` server.
        (
            "domestic-dns",
            AdvancedSettings {
                domestic_dns: Some("223.5.5.5".into()),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // IPv6 enabled — changes DNS query strategy (UseIP vs UseIPv4) and the
        // tun address list (sing-box).
        (
            "ipv6",
            AdvancedSettings {
                ipv6_enabled: Some(true),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // Log level override.
        (
            "log-debug",
            AdvancedSettings {
                log_level: Some(LogLevel::Debug),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // sing-box strict_route.
        (
            "strict-route",
            AdvancedSettings {
                strict_route: true,
                ..Default::default()
            },
            vec![],
            false,
        ),
        // Custom local ports — exercises the port derivation logic.
        (
            "custom-ports",
            AdvancedSettings {
                local_socks_port: Some(10800),
                local_http_port: Some(10801),
                ..Default::default()
            },
            vec![],
            false,
        ),
        // LAN-facing listen address (0.0.0.0).
        (
            "allow-lan",
            AdvancedSettings {
                allow_non_localhost: true,
                ..Default::default()
            },
            vec![],
            false,
        ),
    ]
}

/// Settings cases: a representative profile × every variant × both engines.
fn settings_cases() -> Vec<Case> {
    let vless = make(Protocol::Vless, Some(Network::Tcp), Security::Tls, "vless")
        .expect("representative vless builds");
    let mut cases = Vec::new();
    for (label, mut settings, rules, needs_geo) in settings_variants() {
        for engine in [CoreEngine::Xray, CoreEngine::SingBox] {
            settings.core_by_protocol.insert(Protocol::Vless, engine);
            cases.push(Case {
                name: format!("settings/{label}/{}", wire(&engine)),
                profile: vless.clone(),
                settings: settings.clone(),
                rules: rules.clone(),
                needs_geo,
            });
        }
    }
    cases
}

// ── core invocation ──

fn binaries_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../src-tauri/binaries")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src-tauri/binaries"))
}

fn find_core(env_var: &str, prefix: &str) -> Option<PathBuf> {
    if let Ok(p) = std::env::var(env_var) {
        let path = PathBuf::from(p);
        return path.is_file().then_some(path);
    }
    let dir = binaries_dir();
    for e in std::fs::read_dir(&dir).ok()?.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && !name.ends_with(".dll") {
            return Some(e.path());
        }
    }
    None
}

fn write_config(
    profile: &Profile,
    settings: &AdvancedSettings,
    rules: &[RoutingRule],
    srs_dir: &Path,
) -> Option<(tempfile::TempDir, PathBuf, CoreEngine)> {
    let built = build_core_config(
        profile,
        settings,
        rules,
        std::slice::from_ref(profile),
        &srs_dir.to_string_lossy(),
    )
    .ok()?;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, serde_json::to_string_pretty(&built.config).unwrap()).unwrap();
    Some((dir, path, built.engine))
}

fn validate(engine: CoreEngine, bin: &Path, cfg: &Path, asset_dir: &Path) -> (bool, String) {
    let mut cmd = Command::new(bin);
    match engine {
        CoreEngine::Xray => {
            cmd.args(["run", "-test", "-c"]).arg(cfg);
            cmd.env("XRAY_LOCATION_ASSET", asset_dir);
        }
        CoreEngine::SingBox => {
            cmd.args(["check", "-c"]).arg(cfg);
        }
    }
    let out = cmd.output().expect("spawn core");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

/// Build + run every case against the staged cores. Shared by the protocol and
/// settings sweeps. Skips wholesale when no cores are staged (plain CI).
fn validate_all(cases: Vec<Case>) {
    let xray = find_core("KASUMI_XRAY_BIN", "xray");
    let singbox = find_core("KASUMI_SINGBOX_BIN", "sing-box");
    if xray.is_none() && singbox.is_none() {
        eprintln!(
            "skipping core validation: no staged binaries in {} (run scripts/fetch-binaries.sh desktop)",
            binaries_dir().display()
        );
        return;
    }

    let asset_dir = binaries_dir();
    let srs_dir = tempfile::tempdir().unwrap();
    // geoip.dat isn't staged by fetch-binaries.sh (the app downloads it to its
    // datadir at runtime), so a config that references geoip/geosite data can't be
    // validated where cores are staged without it. Skip those cases with a count
    // rather than failing them for missing data.
    let has_geo = asset_dir.join("geoip.dat").is_file();

    let mut failures = Vec::new();
    let mut checked = 0;
    let mut skipped_geo = 0;
    for Case {
        name,
        profile,
        settings,
        rules,
        needs_geo,
    } in cases
    {
        if needs_geo && !has_geo {
            skipped_geo += 1;
            continue;
        }
        let Some((_keep, cfg, engine)) = write_config(&profile, &settings, &rules, srs_dir.path())
        else {
            continue; // our builder declined this combo — not a core problem.
        };
        let bin = match engine {
            CoreEngine::Xray => xray.as_deref(),
            CoreEngine::SingBox => singbox.as_deref(),
        };
        let Some(bin) = bin else { continue };
        let (ok, output) = validate(engine, bin, &cfg, asset_dir.as_path());
        checked += 1;
        if !ok {
            failures.push(format!("[{name}] {engine:?} rejected:\n{}", output.trim()));
        }
    }

    eprintln!(
        "core validation: {}/{checked} configs accepted{}",
        checked - failures.len(),
        if skipped_geo > 0 {
            format!(
                ", {skipped_geo} geo-dependent skipped (no geoip.dat in {})",
                asset_dir.display()
            )
        } else {
            String::new()
        }
    );
    assert!(
        failures.is_empty(),
        "{}/{} configs rejected by their core:\n\n{}",
        failures.len(),
        checked,
        failures.join("\n---\n")
    );
    assert!(
        checked > 0,
        "no cases validated — staged binaries unreadable?"
    );
}

#[test]
fn protocol_matrix_validates_against_real_cores() {
    let cases = generate()
        .into_iter()
        .map(|(name, profile)| Case {
            name,
            settings: AdvancedSettings::default(),
            rules: vec![],
            needs_geo: false,
            profile,
        })
        .collect();
    validate_all(cases);
}

#[test]
fn settings_matrix_validates_against_real_cores() {
    validate_all(settings_cases());
}
