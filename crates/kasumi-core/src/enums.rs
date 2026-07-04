//! Fixed value sets shared across the domain. Each enum maps to an exact wire
//! string so persisted JSON and share links round-trip unchanged.

use serde::{Deserialize, Serialize};

/// An actual proxy core. Wire values: `"xray"`, `"sing-box"`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "kebab-case")]
pub enum CoreEngine {
    Xray,
    SingBox,
}

/// Which engine bridges the TUN device to the proxy core. `SingboxTun` means
/// "use sing-box's own native TUN stack" (sing-box core only); `Tun2socks` is an
/// external userspace tun→socks process in front of a socks-only core. Further
/// engines plug in as new variants. Wire values: `"singbox-tun"`, `"tun2socks"`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter, specta::Type,
)]
pub enum TunEngine {
    #[serde(rename = "singbox-tun")]
    SingboxTun,
    #[serde(rename = "tun2socks")]
    Tun2socks,
}

/// Stream transport.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Tcp,
    Ws,
    Grpc,
    Httpupgrade,
    Xhttp,
    H2,
    Kcp,
    Quic,
}

/// TLS security mode.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    None,
    #[default]
    Tls,
    Reality,
}

/// uTLS fingerprint. `""` means unset.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
#[specta(type = String)]
pub enum Fingerprint {
    #[serde(rename = "")]
    Empty,
    #[default]
    Chrome,
    Firefox,
    Safari,
    Ios,
    Android,
    Edge,
    #[serde(rename = "360")]
    N360,
    Qq,
    Random,
    Randomized,
}

/// VLESS/VMess UDP packet encoding. `""` means unset.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
#[specta(type = String)]
pub enum PacketEncoding {
    #[default]
    #[serde(rename = "")]
    Empty,
    Xudp,
    Packetaddr,
}

/// VLESS flow control. `""` means unset.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[specta(type = String)]
pub enum Flow {
    #[default]
    #[serde(rename = "")]
    Empty,
    #[serde(rename = "xtls-rprx-vision")]
    Vision,
    #[serde(rename = "xtls-rprx-vision-udp443")]
    VisionUdp443,
}

/// VMess cipher.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum VmessEnc {
    #[default]
    Auto,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    None,
    Zero,
}

/// Fake-packet header obfuscation (mKCP / QUIC).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum HeaderType {
    #[default]
    None,
    Http,
    Srtp,
    Utp,
    #[serde(rename = "wechat-video")]
    WechatVideo,
    Dtls,
    Wireguard,
    Dns,
}

/// Shadowsocks cipher (incl. the 2022 AEAD methods).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter, specta::Type,
)]
pub enum SsMethod {
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "xchacha20-poly1305")]
    Xchacha20Poly1305,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305,
}

/// TUIC / QUIC congestion control.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter, specta::Type,
)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    Bbr,
    Cubic,
    NewReno,
}

/// Hysteria2 obfuscation. `""` means none.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
#[specta(type = String)]
pub enum Hysteria2Obfs {
    #[default]
    #[serde(rename = "")]
    Empty,
    Salamander,
}

/// Wire-string values of an enum in declaration order, for UI dropdowns. Reads
/// each variant's `Serialize` output, so the lists never restate the values the
/// enums already define.
fn wire_values<T: strum::IntoEnumIterator + Serialize>() -> Vec<String> {
    T::iter()
        .map(|v| {
            serde_json::to_value(v)
                .ok()
                .and_then(|x| x.as_str().map(str::to_owned))
                .unwrap_or_default()
        })
        .collect()
}

/// Editor dropdown option lists, keyed by the generated TS const name. The
/// single source for the frontend's protocol/transport/security `<Select>`s
/// (emitted to `frontend/src/generated/defaults.ts`).
pub fn editor_option_lists() -> Vec<(&'static str, Vec<String>)> {
    use crate::profile::Protocol;
    vec![
        ("PROTOCOL_OPTS", wire_values::<Protocol>()),
        ("CORE_ENGINE_OPTS", wire_values::<CoreEngine>()),
        ("TUN_ENGINE_OPTS", wire_values::<TunEngine>()),
        ("NETWORK_OPTS", wire_values::<Network>()),
        ("SECURITY_OPTS", wire_values::<Security>()),
        ("HEADER_TYPE_OPTS", wire_values::<HeaderType>()),
        ("VMESS_ENC_OPTS", wire_values::<VmessEnc>()),
        ("SS_METHOD_OPTS", wire_values::<SsMethod>()),
        ("CONGESTION_OPTS", wire_values::<CongestionControl>()),
        ("FINGERPRINT_OPTS", wire_values::<Fingerprint>()),
        ("FLOW_OPTS", wire_values::<Flow>()),
        ("PACKET_ENCODING_OPTS", wire_values::<PacketEncoding>()),
        ("HYSTERIA2_OBFS_OPTS", wire_values::<Hysteria2Obfs>()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire<T: Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }

    #[test]
    fn engine_selection_values() {
        assert_eq!(wire(&CoreEngine::Xray), "\"xray\"");
        assert_eq!(wire(&CoreEngine::SingBox), "\"sing-box\"");
    }

    #[test]
    fn tun_engine_values() {
        assert_eq!(wire(&TunEngine::SingboxTun), "\"singbox-tun\"");
        assert_eq!(wire(&TunEngine::Tun2socks), "\"tun2socks\"");
    }

    #[test]
    fn network_and_security() {
        assert_eq!(wire(&Network::Httpupgrade), "\"httpupgrade\"");
        assert_eq!(wire(&Network::Xhttp), "\"xhttp\"");
        assert_eq!(wire(&Network::H2), "\"h2\"");
        assert_eq!(Network::default(), Network::Tcp);
        assert_eq!(wire(&Security::None), "\"none\"");
        assert_eq!(Security::default(), Security::Tls);
    }

    #[test]
    fn empty_and_digit_variants() {
        assert_eq!(wire(&Fingerprint::Empty), "\"\"");
        assert_eq!(wire(&Fingerprint::N360), "\"360\"");
        assert_eq!(wire(&Fingerprint::Chrome), "\"chrome\"");
        assert_eq!(Fingerprint::default(), Fingerprint::Chrome);
        assert_eq!(
            serde_json::from_str::<Fingerprint>("\"\"").unwrap(),
            Fingerprint::Empty
        );
        assert_eq!(wire(&PacketEncoding::Empty), "\"\"");
        assert_eq!(wire(&Hysteria2Obfs::Empty), "\"\"");
    }

    #[test]
    fn dashed_values() {
        assert_eq!(wire(&Flow::Vision), "\"xtls-rprx-vision\"");
        assert_eq!(wire(&Flow::VisionUdp443), "\"xtls-rprx-vision-udp443\"");
        assert_eq!(wire(&HeaderType::WechatVideo), "\"wechat-video\"");
        assert_eq!(wire(&VmessEnc::Aes128Gcm), "\"aes-128-gcm\"");
        assert_eq!(
            wire(&SsMethod::Blake3Chacha20Poly1305),
            "\"2022-blake3-chacha20-poly1305\""
        );
        assert_eq!(wire(&CongestionControl::NewReno), "\"new_reno\"");
    }
}
