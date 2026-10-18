//! The `Profile` discriminated union (13 protocols).
//!
//! Internally tagged on `"protocol"`; each variant nests the shared field groups
//! it uses ([`Meta`]/[`Endpoint`]/[`Transport`]/[`Tls`]) as sub-objects plus its
//! own protocol-specific fields. The on-disk JSON is correspondingly nested
//! (`endpoint`/`transport`/`tls` objects), upgraded from the older flat layout by
//! the state-read migration.

use serde::{Deserialize, Serialize};

use crate::enums::{
    CongestionControl, Flow, Hysteria2Obfs, PacketEncoding, Security, SsMethod, VmessEnc,
};
use crate::mixins::{Endpoint, Meta, Tls, Transport};

// ---- non-trivial field defaults (match the Zod `.default(...)`) ----
fn enc_none() -> String {
    "none".into()
}

/// Default WireGuard tunnel address for a profile that leaves it blank.
pub const WG_DEFAULT_LOCAL_ADDRESS: &str = "172.16.0.2/32";

fn wg_local_address() -> String {
    WG_DEFAULT_LOCAL_ADDRESS.into()
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
/// it doesn't use. The one create-form choice on top is TLS, see
/// [`starts_without_tls`].
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
    let mut p: Profile = serde_json::from_value(seed).expect("empty profile seed deserializes");
    if starts_without_tls(protocol)
        && let Some(tls) = p.tls_mut()
    {
        tls.security = Security::None;
    }
    p
}

/// Whether a new profile of this protocol starts with TLS off, as in v2rayN and
/// NekoBox: TLS is optional for these, while Trojan's spec requires it and the
/// QUIC-based and TLS-wrapping protocols can't run without it. A stored profile
/// with no `tls` object still deserializes to the serde default.
fn starts_without_tls(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Vless | Protocol::Vmess | Protocol::Shadowsocks | Protocol::Http
    )
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
    /// Shadowsocks has no TLS of its own: this is v2ray-plugin's `tls` option,
    /// so it stays off unless the plugin asks for it.
    #[serde(default = "Tls::off")]
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
    #[serde(default)]
    pub origin: CustomOrigin,
}

/// Who wrote a custom profile's raw config: a provider's runs only after sanitising.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum CustomOrigin {
    #[default]
    User,
    Provider,
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

    /// Mutable access to the stream-transport settings.
    pub fn transport_mut(&mut self) -> Option<&mut Transport> {
        match self {
            Profile::Vless(p) => Some(&mut p.transport),
            Profile::Vmess(p) => Some(&mut p.transport),
            Profile::Trojan(p) => Some(&mut p.transport),
            Profile::Shadowsocks(p) => Some(&mut p.transport),
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

    /// Mutable access to the TLS/Reality settings.
    pub fn tls_mut(&mut self) -> Option<&mut Tls> {
        match self {
            Profile::Vless(p) => Some(&mut p.tls),
            Profile::Vmess(p) => Some(&mut p.tls),
            Profile::Trojan(p) => Some(&mut p.tls),
            Profile::Shadowsocks(p) => Some(&mut p.tls),
            Profile::Http(p) => Some(&mut p.tls),
            Profile::Hysteria2(p) => Some(&mut p.tls),
            Profile::Tuic(p) => Some(&mut p.tls),
            Profile::Anytls(p) => Some(&mut p.tls),
            Profile::Naive(p) => Some(&mut p.tls),
            Profile::Shadowtls(p) => Some(&mut p.tls),
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

    /// Mutable access to the server endpoint, for the protocols that carry one.
    pub fn endpoint_mut(&mut self) -> Option<&mut Endpoint> {
        match self {
            Profile::Vless(p) => Some(&mut p.endpoint),
            Profile::Vmess(p) => Some(&mut p.endpoint),
            Profile::Trojan(p) => Some(&mut p.endpoint),
            Profile::Shadowsocks(p) => Some(&mut p.endpoint),
            Profile::Socks(p) => Some(&mut p.endpoint),
            Profile::Http(p) => Some(&mut p.endpoint),
            Profile::Wireguard(p) => Some(&mut p.endpoint),
            Profile::Hysteria2(p) => Some(&mut p.endpoint),
            Profile::Tuic(p) => Some(&mut p.endpoint),
            Profile::Anytls(p) => Some(&mut p.endpoint),
            Profile::Naive(p) => Some(&mut p.endpoint),
            Profile::Shadowtls(p) => Some(&mut p.endpoint),
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

/// A specific validation problem with a profile field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum ProfileValidationIssue {
    RemarksRequired,
    AddressRequired,
    PortOutOfRange,
    UuidRequired,
    PasswordRequired,
    SecretKeyRequired,
    PeerPublicKeyRequired,
    PathRequired,
    RealitySniRequired,
    PublicKeyRequired,
    RawConfigRequired,
}

/// A validation issue associated with a specific profile field name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProfileFieldIssue {
    pub field: String,
    pub issue: ProfileValidationIssue,
}

/// Validate protocol-specific required fields, endpoint ranges, credentials,
/// transport paths, Reality TLS settings, and custom configs.
pub fn validate_profile(p: &Profile) -> Vec<ProfileFieldIssue> {
    let mut issues = Vec::new();

    if p.meta().remarks.trim().is_empty() {
        issues.push(ProfileFieldIssue {
            field: "remarks".into(),
            issue: ProfileValidationIssue::RemarksRequired,
        });
    }

    if let Some(endpoint) = p.endpoint() {
        if endpoint.address.trim().is_empty() {
            issues.push(ProfileFieldIssue {
                field: "address".into(),
                issue: ProfileValidationIssue::AddressRequired,
            });
        }
        if endpoint.port == 0 {
            issues.push(ProfileFieldIssue {
                field: "port".into(),
                issue: ProfileValidationIssue::PortOutOfRange,
            });
        }
    }

    if let Some(uuid) = p.uuid()
        && uuid.trim().is_empty()
    {
        issues.push(ProfileFieldIssue {
            field: "uuid".into(),
            issue: ProfileValidationIssue::UuidRequired,
        });
    }

    let password_needed = match p {
        Profile::Trojan(t) => t.password.trim().is_empty(),
        Profile::Shadowsocks(ss) => ss.password.trim().is_empty(),
        Profile::Hysteria2(h2) => h2.password.trim().is_empty(),
        Profile::Tuic(t) => t.password.trim().is_empty(),
        Profile::Anytls(a) => a.password.trim().is_empty(),
        Profile::Shadowtls(st) => st.version != 1 && st.password.trim().is_empty(),
        _ => false,
    };
    if password_needed {
        issues.push(ProfileFieldIssue {
            field: "password".into(),
            issue: ProfileValidationIssue::PasswordRequired,
        });
    }

    if let Profile::Wireguard(wg) = p {
        if wg.secret_key.trim().is_empty() {
            issues.push(ProfileFieldIssue {
                field: "secretKey".into(),
                issue: ProfileValidationIssue::SecretKeyRequired,
            });
        }
        if wg.peer_public_key.trim().is_empty() {
            issues.push(ProfileFieldIssue {
                field: "peerPublicKey".into(),
                issue: ProfileValidationIssue::PeerPublicKeyRequired,
            });
        }
    }

    if let Some(transport) = p.transport() {
        let path_needed = match transport {
            Transport::Ws(t) => t.path.trim().is_empty(),
            Transport::Httpupgrade(t) => t.path.trim().is_empty(),
            Transport::Xhttp(t) => t.path.trim().is_empty(),
            _ => false,
        };
        if path_needed {
            issues.push(ProfileFieldIssue {
                field: "path".into(),
                issue: ProfileValidationIssue::PathRequired,
            });
        }
    }

    if let Some(tls) = p.tls()
        && tls.security == Security::Reality
    {
        if tls.sni.trim().is_empty() {
            issues.push(ProfileFieldIssue {
                field: "sni".into(),
                issue: ProfileValidationIssue::RealitySniRequired,
            });
        }
        if tls.public_key.trim().is_empty() {
            issues.push(ProfileFieldIssue {
                field: "publicKey".into(),
                issue: ProfileValidationIssue::PublicKeyRequired,
            });
        }
    }

    if let Profile::Custom(c) = p
        && c.raw.trim().is_empty()
    {
        issues.push(ProfileFieldIssue {
            field: "raw".into(),
            issue: ProfileValidationIssue::RawConfigRequired,
        });
    }

    issues
}

/// The profile after switching its protocol: a fresh per-protocol skeleton that
/// carries over the identity, the endpoint/tls/transport sub-objects, and any
/// overlapping root credential fields. The TLS mode carries over, except that
/// Shadowsocks starts with it off (there TLS is a v2ray-plugin option) and a
/// protocol that needs TLS gets its template's mode when the draft had none.
pub fn switch_protocol(cur: &Profile, next_proto: Protocol) -> Profile {
    let mut next = empty_profile(next_proto, &cur.meta().group_id);
    let cur_meta = cur.meta();
    let next_meta = next.meta_mut();
    next_meta.id = cur_meta.id.clone();
    next_meta.remarks = cur_meta.remarks.clone();
    next_meta.sub_id = cur_meta.sub_id.clone();
    next_meta.core_type = cur_meta.core_type;
    next_meta.via = cur_meta.via.clone();

    if let (Some(cur_ep), Some(next_ep)) = (cur.endpoint(), next.endpoint_mut()) {
        *next_ep = cur_ep.clone();
    }

    if let (Some(cur_tls), Some(next_tls)) = (cur.tls(), next.tls_mut()) {
        let security = if next_proto == Protocol::Shadowsocks {
            Security::None
        } else if cur_tls.security == Security::None {
            next_tls.security
        } else {
            cur_tls.security
        };
        let mut new_tls = cur_tls.clone();
        new_tls.security = security;
        *next_tls = new_tls;
    }

    if let (Some(cur_tr), Some(next_tr)) = (cur.transport(), next.transport_mut()) {
        *next_tr = cur_tr.clone();
    }

    if let Some(uuid) = cur.uuid() {
        match &mut next {
            Profile::Vless(p) => p.uuid = uuid.to_string(),
            Profile::Vmess(p) => p.uuid = uuid.to_string(),
            Profile::Tuic(p) => p.uuid = uuid.to_string(),
            _ => {}
        }
    }

    if let Some(password) = cur.password() {
        match &mut next {
            Profile::Trojan(p) => p.password = password.to_string(),
            Profile::Shadowsocks(p) => p.password = password.to_string(),
            Profile::Socks(p) => p.password = password.to_string(),
            Profile::Http(p) => p.password = password.to_string(),
            Profile::Hysteria2(p) => p.password = password.to_string(),
            Profile::Tuic(p) => p.password = password.to_string(),
            Profile::Anytls(p) => p.password = password.to_string(),
            Profile::Naive(p) => p.password = password.to_string(),
            Profile::Shadowtls(p) => p.password = password.to_string(),
            _ => {}
        }
    }

    let cur_username = match cur {
        Profile::Socks(p) => Some(&p.username),
        Profile::Http(p) => Some(&p.username),
        Profile::Naive(p) => Some(&p.username),
        _ => None,
    };
    if let Some(username) = cur_username {
        match &mut next {
            Profile::Socks(p) => p.username = username.clone(),
            Profile::Http(p) => p.username = username.clone(),
            Profile::Naive(p) => p.username = username.clone(),
            _ => {}
        }
    }

    let cur_flow = match cur {
        Profile::Vless(p) => Some(p.flow),
        Profile::Trojan(p) => Some(p.flow),
        _ => None,
    };
    if let Some(flow) = cur_flow {
        match &mut next {
            Profile::Vless(p) => p.flow = flow,
            Profile::Trojan(p) => p.flow = flow,
            _ => {}
        }
    }

    let cur_pe = match cur {
        Profile::Vless(p) => Some(p.packet_encoding),
        Profile::Vmess(p) => Some(p.packet_encoding),
        _ => None,
    };
    if let Some(pe) = cur_pe {
        match &mut next {
            Profile::Vless(p) => p.packet_encoding = pe,
            Profile::Vmess(p) => p.packet_encoding = pe,
            _ => {}
        }
    }

    let cur_cc = match cur {
        Profile::Tuic(p) => Some(p.congestion_control),
        Profile::Naive(p) => Some(p.congestion_control),
        _ => None,
    };
    if let Some(cc) = cur_cc {
        match &mut next {
            Profile::Tuic(p) => p.congestion_control = cc,
            Profile::Naive(p) => p.congestion_control = cc,
            _ => {}
        }
    }

    match &mut next {
        Profile::Vless(p) => p.mux_enabled = cur.mux_enabled(),
        Profile::Vmess(p) => p.mux_enabled = cur.mux_enabled(),
        Profile::Trojan(p) => p.mux_enabled = cur.mux_enabled(),
        Profile::Shadowsocks(p) => p.mux_enabled = cur.mux_enabled(),
        _ => {}
    }

    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::Network;

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
        // Custom profiles stored before origins existed were all typed by the user.
        assert_eq!(cc.origin, CustomOrigin::User);

        let w: Profile = serde_json::from_value(serde_json::json!({
            "protocol":"wireguard","meta":{"id":"w","remarks":"r","groupId":"g-main"},
            "endpoint":{"address":"a","port":51820},"secretKey":"sk","peerPublicKey":"pk"
        }))
        .unwrap();
        let Profile::Wireguard(wg) = &w else { panic!() };
        assert_eq!(wg.local_address, "172.16.0.2/32");
        assert_eq!(wg.mtu, 1420);
    }

    #[test]
    fn blank_shadowsocks_profile_starts_without_tls() {
        // Shadowsocks TLS only exists as v2ray-plugin's `tls` option, so a new
        // profile must not opt into it.
        let Profile::Shadowsocks(ss) = empty_profile(Protocol::Shadowsocks, "g-main") else {
            panic!("not shadowsocks")
        };
        assert_eq!(ss.tls.security, Security::None);
    }

    #[test]
    fn new_profiles_start_with_tls_only_where_the_protocol_needs_it() {
        use strum::IntoEnumIterator;
        for proto in Protocol::iter() {
            let p = empty_profile(proto, "g-main");
            let Some(tls) = p.tls() else { continue };
            let want = match proto {
                Protocol::Vless | Protocol::Vmess | Protocol::Shadowsocks | Protocol::Http => {
                    Security::None
                }
                _ => Security::Tls,
            };
            assert_eq!(tls.security, want, "{proto:?}");
        }
    }

    #[test]
    fn stored_profiles_without_a_tls_object_keep_tls_on() {
        // Only the editor's blank profile changed; a stored profile that omits
        // `tls` still reads as the serde default.
        for proto in ["vless", "vmess", "http"] {
            let p: Profile = serde_json::from_value(serde_json::json!({
                "protocol": proto,
                "meta": { "id": "x", "remarks": "r", "groupId": "g-main" },
                "endpoint": { "address": "e.example", "port": 443 },
                "uuid": "11111111-1111-1111-1111-111111111111",
            }))
            .unwrap();
            assert_eq!(p.tls().unwrap().security, Security::Tls, "{proto}");
        }
    }

    #[test]
    fn validate_blank_profile_reports_issues() {
        let mut p = empty_profile(Protocol::Vless, "g-main");
        p.meta_mut().remarks = "".into();
        p.endpoint_mut().unwrap().port = 0;
        let issues = validate_profile(&p);
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        assert!(fields.contains(&"remarks"));
        assert!(fields.contains(&"address"));
        assert!(fields.contains(&"port"));
        assert!(fields.contains(&"uuid"));
        assert_eq!(
            issues.iter().find(|i| i.field == "remarks").unwrap().issue,
            ProfileValidationIssue::RemarksRequired
        );
        assert_eq!(
            issues.iter().find(|i| i.field == "address").unwrap().issue,
            ProfileValidationIssue::AddressRequired
        );
        assert_eq!(
            issues.iter().find(|i| i.field == "port").unwrap().issue,
            ProfileValidationIssue::PortOutOfRange
        );
        assert_eq!(
            issues.iter().find(|i| i.field == "uuid").unwrap().issue,
            ProfileValidationIssue::UuidRequired
        );
    }

    #[test]
    fn validate_filled_trojan_has_no_issues() {
        let mut p = empty_profile(Protocol::Trojan, "g-main");
        p.meta_mut().remarks = "Home".into();
        let ep = p.endpoint_mut().unwrap();
        ep.address = "example.com".into();
        ep.port = 443;
        let Profile::Trojan(t) = &mut p else { panic!() };
        t.password = "secret".into();
        let issues = validate_profile(&p);
        assert!(issues.is_empty(), "expected no issues, got: {issues:?}");
    }

    #[test]
    fn validate_shadowtls_v1_no_password_v2_needs_password() {
        let mut p = empty_profile(Protocol::Shadowtls, "g-main");
        p.meta_mut().remarks = "ST".into();
        let ep = p.endpoint_mut().unwrap();
        ep.address = "example.com".into();
        ep.port = 443;

        let Profile::Shadowtls(st) = &mut p else {
            panic!()
        };
        st.version = 1;
        st.password = "".into();
        let issues = validate_profile(&p);
        assert!(!issues.iter().any(|i| i.field == "password"));

        let Profile::Shadowtls(st) = &mut p else {
            panic!()
        };
        st.version = 2;
        let issues = validate_profile(&p);
        assert_eq!(
            issues.iter().find(|i| i.field == "password").unwrap().issue,
            ProfileValidationIssue::PasswordRequired
        );
    }

    #[test]
    fn validate_wireguard_keys() {
        let mut p = empty_profile(Protocol::Wireguard, "g-main");
        p.meta_mut().remarks = "WG".into();
        p.endpoint_mut().unwrap().address = "wg.example".into();
        p.endpoint_mut().unwrap().port = 51820;

        let issues = validate_profile(&p);
        assert_eq!(
            issues
                .iter()
                .find(|i| i.field == "secretKey")
                .unwrap()
                .issue,
            ProfileValidationIssue::SecretKeyRequired
        );
        assert_eq!(
            issues
                .iter()
                .find(|i| i.field == "peerPublicKey")
                .unwrap()
                .issue,
            ProfileValidationIssue::PeerPublicKeyRequired
        );

        let Profile::Wireguard(wg) = &mut p else {
            panic!()
        };
        wg.secret_key = "sk".into();
        wg.peer_public_key = "pk".into();
        assert!(validate_profile(&p).is_empty());
    }

    #[test]
    fn validate_transport_path_requirement() {
        let mut p = empty_profile(Protocol::Vless, "g-main");
        p.meta_mut().remarks = "WS".into();
        p.endpoint_mut().unwrap().address = "example.com".into();
        let Profile::Vless(v) = &mut p else { panic!() };
        v.uuid = "11111111-2222-3333-4444-555555555555".into();
        v.transport = Transport::Ws(crate::mixins::WsTransport {
            path: "".into(),
            ..Default::default()
        });

        let issues = validate_profile(&p);
        assert_eq!(
            issues.iter().find(|i| i.field == "path").unwrap().issue,
            ProfileValidationIssue::PathRequired
        );

        let Profile::Vless(v) = &mut p else { panic!() };
        v.transport = Transport::Ws(crate::mixins::WsTransport {
            path: "/ws".into(),
            ..Default::default()
        });
        assert!(validate_profile(&p).is_empty());
    }

    #[test]
    fn validate_reality_tls_fields() {
        let mut p = empty_profile(Protocol::Vless, "g-main");
        p.meta_mut().remarks = "Reality".into();
        p.endpoint_mut().unwrap().address = "example.com".into();
        let Profile::Vless(v) = &mut p else { panic!() };
        v.uuid = "11111111-2222-3333-4444-555555555555".into();
        v.tls.security = Security::Reality;
        v.tls.sni = "".into();
        v.tls.public_key = "".into();

        let issues = validate_profile(&p);
        assert_eq!(
            issues.iter().find(|i| i.field == "sni").unwrap().issue,
            ProfileValidationIssue::RealitySniRequired
        );
        assert_eq!(
            issues
                .iter()
                .find(|i| i.field == "publicKey")
                .unwrap()
                .issue,
            ProfileValidationIssue::PublicKeyRequired
        );

        let Profile::Vless(v) = &mut p else { panic!() };
        v.tls.sni = "example.com".into();
        v.tls.public_key = "pk".into();
        assert!(validate_profile(&p).is_empty());
    }

    #[test]
    fn validate_custom_raw_config() {
        let mut p = empty_profile(Protocol::Custom, "g-main");
        p.meta_mut().remarks = "Custom".into();
        let issues = validate_profile(&p);
        assert_eq!(
            issues.iter().find(|i| i.field == "raw").unwrap().issue,
            ProfileValidationIssue::RawConfigRequired
        );

        let Profile::Custom(c) = &mut p else { panic!() };
        c.raw = "{\"outbounds\": []}".into();
        assert!(validate_profile(&p).is_empty());
    }

    #[test]
    fn switch_protocol_preserves_meta_and_endpoint() {
        let mut vless = empty_profile(Protocol::Vless, "g-other");
        vless.meta_mut().id = "p-custom".into();
        vless.meta_mut().remarks = "My Server".into();
        vless.meta_mut().sub_id = Some("sub-1".into());
        vless.meta_mut().via = Some("hop-1".into());
        let ep = vless.endpoint_mut().unwrap();
        ep.address = "server.example".into();
        ep.port = 8443;
        let Profile::Vless(v) = &mut vless else {
            panic!()
        };
        v.uuid = "uuid-1234".into();

        let switched = switch_protocol(&vless, Protocol::Trojan);
        assert_eq!(switched.protocol(), Protocol::Trojan);
        assert_eq!(switched.meta().id, "p-custom");
        assert_eq!(switched.meta().remarks, "My Server");
        assert_eq!(switched.meta().group_id, "g-other");
        assert_eq!(switched.meta().sub_id.as_deref(), Some("sub-1"));
        assert_eq!(switched.meta().via.as_deref(), Some("hop-1"));
        assert_eq!(switched.address(), "server.example");
        assert_eq!(switched.port(), Some(8443));
    }

    #[test]
    fn switch_protocol_tls_and_shadowsocks_rules() {
        let fresh_vless = empty_profile(Protocol::Vless, "g-main");
        assert_eq!(
            switch_protocol(&fresh_vless, Protocol::Trojan)
                .tls()
                .unwrap()
                .security,
            Security::Tls
        );
        assert_eq!(
            switch_protocol(&fresh_vless, Protocol::Vmess)
                .tls()
                .unwrap()
                .security,
            Security::None
        );
        assert_eq!(
            switch_protocol(&fresh_vless, Protocol::Http)
                .tls()
                .unwrap()
                .security,
            Security::None
        );

        let mut vless_with_tls = empty_profile(Protocol::Vless, "g-main");
        vless_with_tls.tls_mut().unwrap().security = Security::Tls;
        vless_with_tls.tls_mut().unwrap().sni = "s.example".into();

        let vmess = switch_protocol(&vless_with_tls, Protocol::Vmess);
        assert_eq!(vmess.tls().unwrap().security, Security::Tls);
        assert_eq!(vmess.tls().unwrap().sni, "s.example");

        let ss = switch_protocol(&vless_with_tls, Protocol::Shadowsocks);
        assert_eq!(ss.tls().unwrap().security, Security::None);
        assert_eq!(ss.tls().unwrap().sni, "s.example");

        let mut vless_reality = empty_profile(Protocol::Vless, "g-main");
        vless_reality.tls_mut().unwrap().security = Security::Reality;
        vless_reality.tls_mut().unwrap().sni = "r.example".into();
        let trojan = switch_protocol(&vless_reality, Protocol::Trojan);
        assert_eq!(trojan.tls().unwrap().security, Security::Reality);
        assert_eq!(trojan.tls().unwrap().sni, "r.example");
    }

    #[test]
    fn switch_protocol_carries_overlapping_credentials() {
        let mut vless = empty_profile(Protocol::Vless, "g-main");
        let Profile::Vless(v) = &mut vless else {
            panic!()
        };
        v.uuid = "my-uuid".into();

        let vmess = switch_protocol(&vless, Protocol::Vmess);
        assert_eq!(vmess.uuid(), Some("my-uuid"));

        let tuic = switch_protocol(&vless, Protocol::Tuic);
        assert_eq!(tuic.uuid(), Some("my-uuid"));

        let mut trojan = empty_profile(Protocol::Trojan, "g-main");
        let Profile::Trojan(t) = &mut trojan else {
            panic!()
        };
        t.password = "my-password".into();

        let ss = switch_protocol(&trojan, Protocol::Shadowsocks);
        assert_eq!(ss.password(), Some("my-password"));

        let h2 = switch_protocol(&trojan, Protocol::Hysteria2);
        assert_eq!(h2.password(), Some("my-password"));
    }
}
