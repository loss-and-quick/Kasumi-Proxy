//! Shared field groups composed into each per-protocol profile object. Field
//! names are camelCase on the wire; struct-level `#[serde(default)]` fills any
//! omitted field from its `Default`, so a partially-specified profile loads.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::{CoreEngine, Fingerprint, HeaderType, Network, Security};

/// Identity / bookkeeping fields every profile carries (`metaShape`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub id: String,
    pub remarks: String,
    pub group_id: String,
    /// Owning subscription id, or `null` for a manually added profile.
    #[serde(default)]
    pub sub_id: Option<String>,
    /// Latency in ms, or `null` if never tested.
    #[serde(default)]
    pub ping: Option<i64>,
    /// Throughput in bytes/sec; `-1` = failed, `null` = never tested.
    #[serde(default)]
    pub speed: Option<i64>,
    /// Per-profile core override; `None` resolves by protocol/settings.
    #[serde(default)]
    pub core_type: Option<CoreEngine>,
}

/// Server endpoint (`endpointShape`). Both fields are required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
}

/// Plain TCP, optionally wearing the HTTP fake-header obfuscation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct TcpTransport {
    pub header_type: HeaderType,
    pub host: String,
    pub path: String,
}

/// WebSocket transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct WsTransport {
    pub host: String,
    pub path: String,
    pub early_data: i64,
    pub early_data_header: String,
    pub heartbeat_period: i64,
    pub headers: BTreeMap<String, String>,
    pub accept_proxy_protocol: bool,
}

/// gRPC transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct GrpcTransport {
    pub service_name: String,
    pub authority: String,
    pub mode: String,
    pub idle_timeout: i64,
    pub health_check_timeout: i64,
    pub ping_timeout: i64,
    pub permit_without_stream: bool,
    pub initial_window_size: i64,
    pub user_agent: String,
}

/// HTTP/2 transport (sing-box only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct H2Transport {
    pub host: String,
    pub path: String,
    pub idle_timeout: i64,
    pub ping_timeout: i64,
}

/// HTTPUpgrade transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpUpgradeTransport {
    pub host: String,
    pub path: String,
    pub early_data: i64,
    pub headers: BTreeMap<String, String>,
    pub accept_proxy_protocol: bool,
}

/// XHTTP transport (Xray only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct XhttpTransport {
    pub host: String,
    pub path: String,
    pub mode: String,
    pub extra: String,
}

/// mKCP transport (Xray only).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct KcpTransport {
    pub header_type: HeaderType,
    pub seed: String,
    pub mtu: i64,
    pub tti: i64,
    pub uplink: i64,
    pub downlink: i64,
    pub cwnd_multiplier: i64,
    pub max_sending_window: i64,
}

/// Raw QUIC transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct QuicTransport {
    pub header_type: HeaderType,
}

/// Stream transport, tagged on `kind` — each variant carries only the knobs its
/// network actually uses (instead of one flat struct with ~28 mostly-unused
/// fields). Mux is an outbound concern, so it lives on the protocol, not here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Transport {
    Tcp(TcpTransport),
    Ws(WsTransport),
    Grpc(GrpcTransport),
    H2(H2Transport),
    Httpupgrade(HttpUpgradeTransport),
    Xhttp(XhttpTransport),
    Kcp(KcpTransport),
    Quic(QuicTransport),
}

impl Default for Transport {
    fn default() -> Self {
        Transport::Tcp(TcpTransport::default())
    }
}

impl Transport {
    /// The transport's network discriminant.
    pub fn network(&self) -> Network {
        match self {
            Transport::Tcp(_) => Network::Tcp,
            Transport::Ws(_) => Network::Ws,
            Transport::Grpc(_) => Network::Grpc,
            Transport::H2(_) => Network::H2,
            Transport::Httpupgrade(_) => Network::Httpupgrade,
            Transport::Xhttp(_) => Network::Xhttp,
            Transport::Kcp(_) => Network::Kcp,
            Transport::Quic(_) => Network::Quic,
        }
    }

    /// HTTP host header / SNI fallback source, for the variants that carry one.
    pub fn host(&self) -> &str {
        match self {
            Transport::Tcp(t) => &t.host,
            Transport::Ws(t) => &t.host,
            Transport::H2(t) => &t.host,
            Transport::Httpupgrade(t) => &t.host,
            Transport::Xhttp(t) => &t.host,
            Transport::Grpc(_) | Transport::Kcp(_) | Transport::Quic(_) => "",
        }
    }

    /// Stream path / endpoint, for the variants that carry one.
    pub fn path(&self) -> &str {
        match self {
            Transport::Tcp(t) => &t.path,
            Transport::Ws(t) => &t.path,
            Transport::H2(t) => &t.path,
            Transport::Httpupgrade(t) => &t.path,
            Transport::Xhttp(t) => &t.path,
            Transport::Grpc(t) => &t.service_name,
            Transport::Kcp(_) | Transport::Quic(_) => "",
        }
    }

    /// gRPC authority (empty for every other transport).
    pub fn authority(&self) -> &str {
        match self {
            Transport::Grpc(t) => &t.authority,
            _ => "",
        }
    }

    /// Fake-header obfuscation, for the variants that carry one (else `None`).
    pub fn header_type(&self) -> HeaderType {
        match self {
            Transport::Tcp(t) => t.header_type,
            Transport::Kcp(t) => t.header_type,
            Transport::Quic(t) => t.header_type,
            _ => HeaderType::None,
        }
    }
}

/// TLS / Reality knobs shared by all protocols (`tlsShape`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct Tls {
    pub security: Security,
    pub sni: String,
    pub disable_sni: bool,
    pub fingerprint: Fingerprint,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub tls_min_version: String,
    pub tls_max_version: String,
    pub tls_cipher_suites: Vec<String>,
    pub tls_curve_preferences: Vec<String>,
    pub cert: String,
    pub disable_system_root: bool,
    pub reject_unknown_sni: bool,
    pub enable_session_resumption: bool,
    pub public_key: String,
    pub short_id: String,
    pub spider_x: String,
    pub ech: String,
    pub vcn: String,
    pub pcs: String,
    pub pqv: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_default_is_tcp() {
        // The bare default transport is plain TCP, tagged on `kind`.
        let t = Transport::default();
        assert_eq!(t.network(), Network::Tcp);
        assert_eq!(t.header_type(), HeaderType::None);
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["kind"], "tcp");
        assert_eq!(v["headerType"], "none");
        assert!(v.get("network").is_none(), "kind, not network");
    }

    #[test]
    fn transport_variants_round_trip_on_kind() {
        // A ws transport keeps only the ws knobs and re-parses to the same value.
        let ws: Transport = serde_json::from_value(serde_json::json!({
            "kind": "ws", "host": "cdn.ex", "path": "/w", "earlyData": 2048,
            "earlyDataHeader": "Sec-WebSocket-Protocol"
        }))
        .unwrap();
        let Transport::Ws(w) = &ws else { panic!() };
        assert_eq!(w.host, "cdn.ex");
        assert_eq!(w.early_data, 2048);
        assert_eq!(ws.host(), "cdn.ex");
        let v = serde_json::to_value(&ws).unwrap();
        assert_eq!(v["kind"], "ws");
        assert!(v.get("serviceName").is_none(), "no grpc fields on ws");
        assert_eq!(serde_json::from_value::<Transport>(v).unwrap(), ws);

        // gRPC fixes the historical `grpcInitialWindowsSize` typo.
        let grpc: Transport = serde_json::from_value(serde_json::json!({
            "kind": "grpc", "serviceName": "svc", "initialWindowSize": 65536
        }))
        .unwrap();
        let v = serde_json::to_value(&grpc).unwrap();
        assert_eq!(v["initialWindowSize"], 65536);
        assert_eq!(grpc.authority(), "");
    }

    #[test]
    fn tls_defaults_match_zod() {
        let t: Tls = serde_json::from_str("{}").unwrap();
        assert_eq!(t.security, Security::Tls);
        assert_eq!(t.fingerprint, Fingerprint::Chrome);
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["security"], "tls");
        assert_eq!(v["fingerprint"], "chrome");
        assert_eq!(v["spiderX"], "");
        assert_eq!(v["disableSni"], false);
    }

    #[test]
    fn meta_camel_case_and_nullable() {
        let m: Meta =
            serde_json::from_str(r#"{"id":"a","remarks":"Home","groupId":"g-main"}"#).unwrap();
        assert_eq!(m.sub_id, None);
        assert_eq!(m.ping, None);
        assert_eq!(m.core_type, None);
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["groupId"], "g-main");
        assert!(v["coreType"].is_null());
        assert!(v["subId"].is_null());
        assert!(v["ping"].is_null());
    }

    #[test]
    fn endpoint_round_trip() {
        let e: Endpoint = serde_json::from_str(r#"{"address":"ex.com","port":443}"#).unwrap();
        assert_eq!(e.port, 443);
        assert_eq!(serde_json::to_value(&e).unwrap()["address"], "ex.com");
    }
}
