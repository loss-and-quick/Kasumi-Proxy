//! The `Profile` discriminated union (13 protocols).
//!
//! Internally tagged on `"protocol"`; each variant nests the shared field groups
//! it uses ([`Meta`]/[`Endpoint`]/[`Transport`]/[`Tls`]) as sub-objects plus its
//! own protocol-specific fields. The on-disk JSON is correspondingly nested
//! (`endpoint`/`transport`/`tls` objects), upgraded from the older flat layout by
//! the state-read migration.

use serde::{Deserialize, Serialize};

use crate::enums::{CongestionControl, Flow, Hysteria2Obfs, PacketEncoding, SsMethod, VmessEnc};
use crate::mixins::{Endpoint, Meta, Tls, Transport};

// ---- non-trivial field defaults (match the Zod `.default(...)`) ----
fn enc_none() -> String {
    "none".into()
}
fn wg_local_address() -> String {
    "172.16.0.2/32".into()
}
fn wg_mtu() -> i64 {
    1420
}
fn shadowtls_version() -> i64 {
    3
}
fn ss_method_default() -> SsMethod {
    SsMethod::Aes256Gcm
}
fn congestion_bbr() -> CongestionControl {
    CongestionControl::Bbr
}

/// The set of supported protocols (the union's discriminant values).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    strum::EnumIter,
    specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Socks,
    Http,
    Wireguard,
    Hysteria2,
    Tuic,
    Anytls,
    Naive,
    Shadowtls,
    Custom,
}

/// A blank profile of the given protocol carrying the editor create-form
/// defaults (port 443, `"New profile"` remarks). The single source for the
/// frontend's `emptyProfile`, emitted to `frontend/src/generated/defaults.ts`;
/// `meta.id` / `meta.group_id` are filled in by the caller.
///
/// Built by deserializing a minimal seed so every `#[serde(default)]` field is
/// populated from its own definition — no default value is restated here. The
/// seed carries all blank required credentials; each variant ignores the keys
/// it doesn't use.
pub fn empty_profile(protocol: Protocol, group_id: &str) -> Profile {
    let seed = serde_json::json!({
        "protocol": protocol,
        "meta": { "id": "", "remarks": "New profile", "groupId": group_id },
        "endpoint": { "address": "", "port": 443 },
        "uuid": "",
        "password": "",
        "secretKey": "",
        "peerPublicKey": "",
    });
    serde_json::from_value(seed).expect("empty profile seed deserializes")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Vless {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls: Tls,
    pub uuid: String,
    #[serde(default)]
    pub flow: Flow,
    #[serde(default = "enc_none")]
    pub encryption: String,
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
    #[serde(default)]
    pub mux_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Vmess {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls: Tls,
    pub uuid: String,
    #[serde(default)]
    pub alter_id: i64,
    #[serde(default)]
    pub encryption: VmessEnc,
    #[serde(default)]
    pub packet_encoding: PacketEncoding,
    #[serde(default)]
    pub vmess_global_padding: bool,
    #[serde(default)]
    pub vmess_authenticated_length: bool,
    #[serde(default)]
    pub mux_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Trojan {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls: Tls,
    pub password: String,
    #[serde(default)]
    pub flow: Flow,
    #[serde(default)]
    pub mux_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Shadowsocks {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub tls: Tls,
    pub password: String,
    #[serde(default = "ss_method_default")]
    pub method: SsMethod,
    #[serde(default)]
    pub mux_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Socks {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Http {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Wireguard {
    pub meta: Meta,
    pub endpoint: Endpoint,
    pub secret_key: String,
    pub peer_public_key: String,
    #[serde(default)]
    pub pre_shared_key: String,
    /// WireGuard reserved bytes (3 by spec); empty means none.
    #[serde(default)]
    pub reserved: Vec<u8>,
    #[serde(default = "wg_local_address")]
    pub local_address: String,
    #[serde(default = "wg_mtu")]
    pub mtu: i64,
    #[serde(default)]
    pub workers: i64,
    #[serde(default)]
    pub persistent_keepalive: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Hysteria2 {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub tls: Tls,
    pub password: String,
    #[serde(default)]
    pub obfs_type: Hysteria2Obfs,
    #[serde(default)]
    pub obfs_password: String,
    #[serde(default)]
    pub ports: String,
    #[serde(default)]
    pub hop_interval: String,
    #[serde(default)]
    pub up_mbps: i64,
    #[serde(default)]
    pub down_mbps: i64,
    #[serde(default)]
    pub pin_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Tuic {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub tls: Tls,
    pub uuid: String,
    pub password: String,
    #[serde(default = "congestion_bbr")]
    pub congestion_control: CongestionControl,
    #[serde(default)]
    pub udp_relay_mode: String,
    #[serde(default)]
    pub zero_rtt: bool,
    #[serde(default)]
    pub udp_over_stream: bool,
    #[serde(default)]
    pub heartbeat: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Anytls {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub tls: Tls,
    pub password: String,
    #[serde(default)]
    pub idle_session_check_interval: String,
    #[serde(default)]
    pub idle_session_timeout: String,
    #[serde(default)]
    pub min_idle_session: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Naive {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub naive_quic: bool,
    #[serde(default = "congestion_bbr")]
    pub congestion_control: CongestionControl,
    #[serde(default)]
    pub insecure_concurrency: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Shadowtls {
    pub meta: Meta,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default = "shadowtls_version")]
    pub version: i64,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Custom {
    pub meta: Meta,
    #[serde(default)]
    pub raw: String,
}

/// A proxy profile — the persisted unit, tagged by `protocol`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum Profile {
    Vless(Vless),
    Vmess(Vmess),
    Trojan(Trojan),
    Shadowsocks(Shadowsocks),
    Socks(Socks),
    Http(Http),
    Wireguard(Wireguard),
    Hysteria2(Hysteria2),
    Tuic(Tuic),
    Anytls(Anytls),
    Naive(Naive),
    Shadowtls(Shadowtls),
    Custom(Custom),
}

impl Profile {
    /// The protocol discriminant of this profile.
    pub fn protocol(&self) -> Protocol {
        match self {
            Profile::Vless(_) => Protocol::Vless,
            Profile::Vmess(_) => Protocol::Vmess,
            Profile::Trojan(_) => Protocol::Trojan,
            Profile::Shadowsocks(_) => Protocol::Shadowsocks,
            Profile::Socks(_) => Protocol::Socks,
            Profile::Http(_) => Protocol::Http,
            Profile::Wireguard(_) => Protocol::Wireguard,
            Profile::Hysteria2(_) => Protocol::Hysteria2,
            Profile::Tuic(_) => Protocol::Tuic,
            Profile::Anytls(_) => Protocol::Anytls,
            Profile::Naive(_) => Protocol::Naive,
            Profile::Shadowtls(_) => Protocol::Shadowtls,
            Profile::Custom(_) => Protocol::Custom,
        }
    }

    /// The stream-transport settings, for the protocols that carry them
    /// (vless/vmess/trojan/shadowsocks).
    pub fn transport(&self) -> Option<&Transport> {
        match self {
            Profile::Vless(p) => Some(&p.transport),
            Profile::Vmess(p) => Some(&p.transport),
            Profile::Trojan(p) => Some(&p.transport),
            Profile::Shadowsocks(p) => Some(&p.transport),
            _ => None,
        }
    }

    /// Whether outbound multiplexing is requested (the transport-carrying
    /// protocols only).
    pub fn mux_enabled(&self) -> bool {
        match self {
            Profile::Vless(p) => p.mux_enabled,
            Profile::Vmess(p) => p.mux_enabled,
            Profile::Trojan(p) => p.mux_enabled,
            Profile::Shadowsocks(p) => p.mux_enabled,
            _ => false,
        }
    }

    /// The TLS/Reality settings, for the protocols that carry them.
    pub fn tls(&self) -> Option<&Tls> {
        match self {
            Profile::Vless(p) => Some(&p.tls),
            Profile::Vmess(p) => Some(&p.tls),
            Profile::Trojan(p) => Some(&p.tls),
            Profile::Shadowsocks(p) => Some(&p.tls),
            Profile::Http(p) => Some(&p.tls),
            Profile::Hysteria2(p) => Some(&p.tls),
            Profile::Tuic(p) => Some(&p.tls),
            Profile::Anytls(p) => Some(&p.tls),
            Profile::Naive(p) => Some(&p.tls),
            Profile::Shadowtls(p) => Some(&p.tls),
            _ => None,
        }
    }

    /// The server endpoint, for the protocols that carry one (all but custom).
    pub fn endpoint(&self) -> Option<&Endpoint> {
        match self {
            Profile::Vless(p) => Some(&p.endpoint),
            Profile::Vmess(p) => Some(&p.endpoint),
            Profile::Trojan(p) => Some(&p.endpoint),
            Profile::Shadowsocks(p) => Some(&p.endpoint),
            Profile::Socks(p) => Some(&p.endpoint),
            Profile::Http(p) => Some(&p.endpoint),
            Profile::Wireguard(p) => Some(&p.endpoint),
            Profile::Hysteria2(p) => Some(&p.endpoint),
            Profile::Tuic(p) => Some(&p.endpoint),
            Profile::Anytls(p) => Some(&p.endpoint),
            Profile::Naive(p) => Some(&p.endpoint),
            Profile::Shadowtls(p) => Some(&p.endpoint),
            Profile::Custom(_) => None,
        }
    }

    /// The shared identity/bookkeeping fields, regardless of protocol.
    pub fn meta(&self) -> &Meta {
        match self {
            Profile::Vless(p) => &p.meta,
            Profile::Vmess(p) => &p.meta,
            Profile::Trojan(p) => &p.meta,
            Profile::Shadowsocks(p) => &p.meta,
            Profile::Socks(p) => &p.meta,
            Profile::Http(p) => &p.meta,
            Profile::Wireguard(p) => &p.meta,
            Profile::Hysteria2(p) => &p.meta,
            Profile::Tuic(p) => &p.meta,
            Profile::Anytls(p) => &p.meta,
            Profile::Naive(p) => &p.meta,
            Profile::Shadowtls(p) => &p.meta,
            Profile::Custom(p) => &p.meta,
        }
    }

    /// Mutable access to the shared identity fields (for sub-apply re-tagging).
    pub fn meta_mut(&mut self) -> &mut Meta {
        match self {
            Profile::Vless(p) => &mut p.meta,
            Profile::Vmess(p) => &mut p.meta,
            Profile::Trojan(p) => &mut p.meta,
            Profile::Shadowsocks(p) => &mut p.meta,
            Profile::Socks(p) => &mut p.meta,
            Profile::Http(p) => &mut p.meta,
            Profile::Wireguard(p) => &mut p.meta,
            Profile::Hysteria2(p) => &mut p.meta,
            Profile::Tuic(p) => &mut p.meta,
            Profile::Anytls(p) => &mut p.meta,
            Profile::Naive(p) => &mut p.meta,
            Profile::Shadowtls(p) => &mut p.meta,
            Profile::Custom(p) => &mut p.meta,
        }
    }

    /// Server address (empty for `custom`).
    pub fn address(&self) -> &str {
        self.endpoint().map(|e| e.address.as_str()).unwrap_or("")
    }

    /// Server port (`None` for `custom`).
    pub fn port(&self) -> Option<u16> {
        self.endpoint().map(|e| e.port)
    }

    /// The credential the dedup/filter treats as the profile's `uuid` field.
    pub fn uuid(&self) -> Option<&str> {
        match self {
            Profile::Vless(p) => Some(&p.uuid),
            Profile::Vmess(p) => Some(&p.uuid),
            Profile::Tuic(p) => Some(&p.uuid),
            _ => None,
        }
    }

    /// The credential the dedup/filter treats as the profile's `password` field.
    pub fn password(&self) -> Option<&str> {
        match self {
            Profile::Trojan(p) => Some(&p.password),
            Profile::Shadowsocks(p) => Some(&p.password),
            Profile::Socks(p) => Some(&p.password),
            Profile::Http(p) => Some(&p.password),
            Profile::Hysteria2(p) => Some(&p.password),
            Profile::Tuic(p) => Some(&p.password),
            Profile::Anytls(p) => Some(&p.password),
            Profile::Naive(p) => Some(&p.password),
            Profile::Shadowtls(p) => Some(&p.password),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::{Network, Security};

    #[test]
    fn vless_full_round_trip_and_tag() {
        // A realistic vless profile with every nested group present.
        let json = serde_json::json!({
            "protocol": "vless",
            "meta": { "id": "p1", "remarks": "Home", "groupId": "g-main",
                "subId": null, "coreType": null },
            "endpoint": { "address": "ex.com", "port": 443 },
            "transport": { "kind": "ws", "host": "ex.com", "path": "/v" },
            "tls": { "security": "reality", "sni": "ex.com", "fingerprint": "chrome",
                "publicKey": "PK", "shortId": "ab" },
            "uuid": "11111111-2222-3333-4444-555555555555",
            "flow": "xtls-rprx-vision", "encryption": "none", "packetEncoding": "xudp"
        });
        let p: Profile = serde_json::from_value(json).unwrap();
        assert_eq!(p.protocol(), Protocol::Vless);
        assert_eq!(p.meta().id, "p1");
        assert_eq!(p.meta().sub_id, None);
        let Profile::Vless(v) = &p else {
            panic!("not vless")
        };
        assert_eq!(v.transport.network(), Network::Ws);
        assert_eq!(v.tls.security, Security::Reality);
        assert_eq!(v.flow, Flow::Vision);
        assert_eq!(v.uuid, "11111111-2222-3333-4444-555555555555");

        // Round-trips losslessly through the nested wire format, with the shared
        // field groups serialized as sub-objects (not flattened to the top level).
        let wire = serde_json::to_value(&p).unwrap();
        assert_eq!(wire["transport"]["kind"], "ws");
        assert_eq!(wire["endpoint"]["address"], "ex.com");
        assert!(wire["meta"]["coreType"].is_null());
        assert!(
            wire.get("network").is_none(),
            "transport must not be flattened"
        );
        let reparsed: Profile = serde_json::from_value(wire).unwrap();
        assert_eq!(reparsed, p);
    }

    #[test]
    fn partial_fills_defaults() {
        // Only the discriminant + required fields; transport/tls default wholesale.
        let json = serde_json::json!({
            "protocol": "vless",
            "meta": { "id": "p2", "remarks": "x", "groupId": "g-main" },
            "endpoint": { "address": "a", "port": 443 },
            "uuid": "11111111-2222-3333-4444-555555555555"
        });
        let p: Profile = serde_json::from_value(json).unwrap();
        let Profile::Vless(v) = &p else { panic!() };
        assert_eq!(v.transport.network(), Network::Tcp); // transport default
        assert_eq!(v.tls.security, Security::Tls); // tls default
        assert_eq!(v.tls.fingerprint, crate::enums::Fingerprint::Chrome);
        assert_eq!(v.encryption, "none"); // field default
        assert_eq!(v.flow, Flow::Empty);
        assert_eq!(v.meta.core_type, None);
        assert_eq!(v.meta.sub_id, None);
    }

    #[test]
    fn custom_minimal_and_wireguard_defaults() {
        let c: Profile = serde_json::from_value(serde_json::json!({
            "protocol":"custom","meta":{"id":"c","remarks":"r","groupId":"g-main"}
        }))
        .unwrap();
        assert_eq!(c.protocol(), Protocol::Custom);
        let Profile::Custom(cc) = &c else { panic!() };
        assert_eq!(cc.raw, "");

        let w: Profile = serde_json::from_value(serde_json::json!({
            "protocol":"wireguard","meta":{"id":"w","remarks":"r","groupId":"g-main"},
            "endpoint":{"address":"a","port":51820},"secretKey":"sk","peerPublicKey":"pk"
        }))
        .unwrap();
        let Profile::Wireguard(wg) = &w else { panic!() };
        assert_eq!(wg.local_address, "172.16.0.2/32");
        assert_eq!(wg.mtu, 1420);
    }
}
