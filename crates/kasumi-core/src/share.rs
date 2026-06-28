//! Parse and build share links across every supported scheme: the URL-based
//! protocols (vless / trojan / socks / http / wireguard), the base64 ones
//! (vmess / ss) and the QUIC family, plus the scheme dispatch.
//!
//! `parse_share_link` is pinned against committed reference fixtures
//! (`tests/fixtures/share_parse.json`) for byte-exact parity.

// Transport/Tls carry ~28/21 fields of which a parser sets only a handful, most
// gated on the chosen network — `Default::default()` then conditional assignment
// reads far clearer than struct-update syntax laced with `if` expressions.
#![allow(clippy::field_reassign_with_default)]

use std::collections::HashMap;
use std::sync::LazyLock;

use base64::Engine;
use fancy_regex::Regex as FancyRegex;
use percent_encoding::percent_decode_str;
use url::Url;

use std::collections::BTreeMap;

use crate::config_shared::{parse_ws_early_data, split_csv};
use crate::enums::{
    CongestionControl, Fingerprint, Flow, HeaderType, Hysteria2Obfs, Network, PacketEncoding,
    Security, SsMethod, VmessEnc,
};
use crate::mixins::{
    Endpoint, GrpcTransport, H2Transport, HttpUpgradeTransport, KcpTransport, Meta, QuicTransport,
    TcpTransport, Tls, Transport, WsTransport, XhttpTransport,
};
use crate::profile::{
    Anytls, Http, Hysteria2, Naive, Profile, Shadowsocks, Shadowtls, Socks, Trojan, Tuic, Vless,
    Vmess, Wireguard,
};
use crate::uid::uid;

/// `decodeURIComponent` for a single component (username/password/fragment).
fn pct(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Parse a `wsHeaders` JSON-object string into a header map (string values only).
fn parse_ws_headers(raw: &str) -> BTreeMap<String, String> {
    if raw.trim().is_empty() {
        return BTreeMap::new();
    }
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(o)) => o
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// Serialize a header map back to the `wsHeaders` JSON string (`""` when empty).
fn build_ws_headers(h: &BTreeMap<String, String>) -> String {
    if h.is_empty() {
        String::new()
    } else {
        serde_json::to_string(h).unwrap_or_default()
    }
}

/// Unicode-safe, lenient base64 decode (URL-safe chars + missing padding).
fn b64decode(s: &str) -> Option<String> {
    let mut t = s.trim().replace('-', "+").replace('_', "/");
    while !t.len().is_multiple_of(4) {
        t.push('=');
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(t.as_bytes())
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn split_first(s: &str, sep: char) -> (String, String) {
    match s.find(sep) {
        Some(i) => (s[..i].to_string(), s[i + sep.len_utf8()..].to_string()),
        None => (s.to_string(), String::new()),
    }
}
fn split_last(s: &str, sep: char) -> (String, String) {
    match s.rfind(sep) {
        Some(i) => (s[..i].to_string(), s[i + sep.len_utf8()..].to_string()),
        None => (s.to_string(), String::new()),
    }
}
fn parse_host_port(hp: &str) -> (String, u16) {
    let (h, p) = split_last(hp, ':');
    let port = p.parse().ok().filter(|n| *n != 0).unwrap_or(443);
    (h, port)
}

/// `?key=1|true` truthiness over several aliases.
fn query_truthy(q: &HashMap<String, String>, keys: &[&str]) -> bool {
    keys.iter()
        .any(|k| matches!(q.get(*k).map(String::as_str), Some("1") | Some("true")))
}

/// Collect query params, first value winning (matches `URLSearchParams.get`).
fn query_map(u: &Url) -> HashMap<String, String> {
    let mut q = HashMap::new();
    for (k, v) in u.query_pairs() {
        q.entry(k.into_owned()).or_insert_with(|| v.into_owned());
    }
    q
}

fn as_network(v: Option<&str>) -> Network {
    match v.unwrap_or("") {
        "ws" => Network::Ws,
        "grpc" => Network::Grpc,
        "httpupgrade" => Network::Httpupgrade,
        "xhttp" => Network::Xhttp,
        "h2" => Network::H2,
        "kcp" => Network::Kcp,
        "quic" => Network::Quic,
        _ => Network::Tcp,
    }
}

fn as_security(v: Option<&str>) -> Security {
    match v {
        Some("tls") => Security::Tls,
        Some("reality") => Security::Reality,
        _ => Security::None,
    }
}

fn as_fingerprint(v: Option<&str>) -> Fingerprint {
    match v.unwrap_or("") {
        "firefox" => Fingerprint::Firefox,
        "safari" => Fingerprint::Safari,
        "ios" => Fingerprint::Ios,
        "android" => Fingerprint::Android,
        "edge" => Fingerprint::Edge,
        "360" => Fingerprint::N360,
        "qq" => Fingerprint::Qq,
        "random" => Fingerprint::Random,
        "randomized" => Fingerprint::Randomized,
        // "chrome" and any unknown coerce to chrome (the default fingerprint).
        _ => Fingerprint::Chrome,
    }
}

fn as_flow(v: Option<&String>) -> Flow {
    match v.map(String::as_str) {
        Some("xtls-rprx-vision") => Flow::Vision,
        Some("xtls-rprx-vision-udp443") => Flow::VisionUdp443,
        _ => Flow::Empty,
    }
}

fn meta(remarks: String, group_id: Option<&str>) -> Meta {
    Meta {
        id: uid(),
        remarks,
        group_id: group_id.unwrap_or("g-main").to_string(),
        sub_id: None,
        core_type: None,
    }
}

/// Fragment (`#...`) decoded, or the host as a fallback remark.
fn remarks_or_host(u: &Url) -> String {
    match u.fragment() {
        Some(f) => pct(f),
        None => u.host_str().unwrap_or("").to_string(),
    }
}

/// vless / trojan (`scheme://cred@host:port?query#frag`).
enum UrlProto {
    Vless,
    Trojan,
}

fn parse_url_based(uri: &str, proto: UrlProto, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    let cred = pct(u.username());
    let net = as_network(q.get("type").map(String::as_str));
    let header_type = if q.get("headerType").map(String::as_str) == Some("http") {
        HeaderType::Http
    } else {
        HeaderType::None
    };
    let accept_proxy = q.get("acceptProxyProtocol").map(String::as_str) == Some("1");

    let t = match net {
        Network::Tcp => Transport::Tcp(TcpTransport {
            header_type,
            host: get("host"),
            path: get("path"),
        }),
        Network::Ws => {
            let w = parse_ws_early_data(&get("path"));
            Transport::Ws(WsTransport {
                host: get("host"),
                path: w.path,
                early_data: w.ws_early_data,
                early_data_header: w.ws_early_data_header,
                heartbeat_period: 0,
                headers: parse_ws_headers(&get("wsHeaders")),
                accept_proxy_protocol: accept_proxy,
            })
        }
        Network::Grpc => Transport::Grpc(GrpcTransport {
            service_name: q
                .get("serviceName")
                .or_else(|| q.get("path"))
                .cloned()
                .unwrap_or_default(),
            authority: q
                .get("authority")
                .or_else(|| q.get("host"))
                .cloned()
                .unwrap_or_default(),
            mode: get("mode"),
            ..Default::default()
        }),
        Network::H2 => Transport::H2(H2Transport {
            host: get("host"),
            path: get("path"),
            ..Default::default()
        }),
        // The HTTPUpgrade `ed` query param has historically been ignored here.
        Network::Httpupgrade => Transport::Httpupgrade(HttpUpgradeTransport {
            host: get("host"),
            path: get("path"),
            early_data: 0,
            headers: parse_ws_headers(&get("wsHeaders")),
            accept_proxy_protocol: accept_proxy,
        }),
        Network::Xhttp => Transport::Xhttp(XhttpTransport {
            host: get("host"),
            path: get("path"),
            mode: get("mode"),
            extra: get("extra"),
        }),
        Network::Kcp => Transport::Kcp(KcpTransport {
            header_type,
            cwnd_multiplier: q
                .get("kcpCwndMultiplier")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            max_sending_window: q
                .get("kcpMaxSendingWindow")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            ..Default::default()
        }),
        Network::Quic => Transport::Quic(QuicTransport { header_type }),
    };

    let mut tls = Tls::default();
    tls.security = as_security(q.get("security").map(String::as_str));
    tls.sni = get("sni");
    tls.alpn = split_csv(&get("alpn")).unwrap_or_default();
    tls.fingerprint = as_fingerprint(q.get("fp").map(String::as_str));
    tls.allow_insecure = q.get("allowInsecure").map(String::as_str) == Some("1");
    tls.public_key = get("pbk");
    tls.short_id = get("sid");
    tls.spider_x = get("spx");
    tls.ech = get("ech");
    tls.vcn = get("vcn");
    tls.pcs = get("pcs");
    tls.pqv = get("pqv");

    let m = meta(remarks_or_host(&u), group_id);
    let endpoint = Endpoint {
        address: u.host_str().unwrap_or("").to_string(),
        port: u.port().unwrap_or(443),
    };

    match proto {
        UrlProto::Vless => Some(Profile::Vless(Vless {
            meta: m,
            endpoint,
            transport: t,
            tls,
            uuid: cred,
            flow: as_flow(q.get("flow")),
            encryption: q
                .get("encryption")
                .cloned()
                .unwrap_or_else(|| "none".into()),
            packet_encoding: PacketEncoding::Empty,
            mux_enabled: false,
        })),
        UrlProto::Trojan => Some(Profile::Trojan(Trojan {
            meta: m,
            endpoint,
            transport: t,
            tls,
            password: cred,
            flow: as_flow(q.get("flow")),
            mux_enabled: false,
        })),
    }
}

/// socks(5) / http(s) proxy links.
enum SockHttp {
    Socks,
    Http,
}

fn parse_socks_or_http(uri: &str, proto: SockHttp, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let host = u.host_str().unwrap_or("").to_string();
    let https = u.scheme() == "https";
    let default_port = if https {
        443
    } else if matches!(proto, SockHttp::Http) {
        80
    } else {
        1080
    };
    let username = pct(u.username());
    let password = pct(u.password().unwrap_or(""));
    let m = meta(remarks_or_host(&u), group_id);
    let endpoint = Endpoint {
        address: host,
        port: u.port().unwrap_or(default_port),
    };

    match proto {
        SockHttp::Socks => Some(Profile::Socks(Socks {
            meta: m,
            endpoint,
            username,
            password,
        })),
        SockHttp::Http => {
            let mut tls = Tls::default();
            tls.security = match q
                .get("security")
                .filter(|s| !s.is_empty())
                .map(String::as_str)
            {
                Some(s) => as_security(Some(s)),
                None => {
                    if https {
                        Security::Tls
                    } else {
                        Security::None
                    }
                }
            };
            tls.sni = q.get("sni").cloned().unwrap_or_default();
            Some(Profile::Http(Http {
                meta: m,
                endpoint,
                tls,
                username,
                password,
            }))
        }
    }
}

fn parse_wireguard(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let secret_key = pct(u.username());
    if secret_key.is_empty() {
        return None;
    }
    let get = |k: &str, dflt: &str| q.get(k).cloned().unwrap_or_else(|| dflt.to_string());
    Some(Profile::Wireguard(Wireguard {
        meta: meta(remarks_or_host(&u), group_id),
        endpoint: Endpoint {
            address: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(51820),
        },
        secret_key,
        peer_public_key: get("publickey", ""),
        pre_shared_key: get("presharedkey", ""),
        reserved: split_csv(&get("reserved", ""))
            .unwrap_or_default()
            .iter()
            .filter_map(|s| s.trim().parse::<u8>().ok())
            .collect(),
        local_address: get("address", "172.16.0.2/32"),
        mtu: q.get("mtu").and_then(|s| s.parse().ok()).unwrap_or(1420),
        workers: 0,
        persistent_keepalive: 0,
    }))
}

fn as_ss_method(v: &str) -> SsMethod {
    match v {
        "aes-128-gcm" => SsMethod::Aes128Gcm,
        "chacha20-poly1305" => SsMethod::Chacha20Poly1305,
        "chacha20-ietf-poly1305" => SsMethod::Chacha20IetfPoly1305,
        "xchacha20-poly1305" => SsMethod::Xchacha20Poly1305,
        "none" => SsMethod::None,
        "plain" => SsMethod::Plain,
        "2022-blake3-aes-128-gcm" => SsMethod::Blake3Aes128Gcm,
        "2022-blake3-aes-256-gcm" => SsMethod::Blake3Aes256Gcm,
        "2022-blake3-chacha20-poly1305" => SsMethod::Blake3Chacha20Poly1305,
        _ => SsMethod::Aes256Gcm,
    }
}

fn as_cc(v: Option<&str>) -> CongestionControl {
    match v {
        Some("cubic") => CongestionControl::Cubic,
        Some("new_reno") => CongestionControl::NewReno,
        _ => CongestionControl::Bbr,
    }
}

/// vmess — base64-wrapped JSON payload.
fn parse_vmess(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let json = b64decode(&uri["vmess://".len()..])?;
    let c: serde_json::Value = serde_json::from_str(&json).ok()?;
    // Helpers reading string-or-number JSON fields, coercing either to a string.
    let s = |k: &str| -> String {
        match c.get(k) {
            Some(serde_json::Value::String(v)) => v.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    };
    let num = |k: &str| -> i64 {
        match c.get(k) {
            Some(serde_json::Value::String(v)) => v.parse().unwrap_or(0),
            Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0),
            _ => 0,
        }
    };
    let truthy = |k: &str| -> bool {
        matches!(c.get(k), Some(serde_json::Value::Bool(true)))
            || matches!(c.get(k), Some(serde_json::Value::Number(n)) if n.as_i64() == Some(1))
            || matches!(c.get(k).and_then(|v| v.as_str()), Some("1") | Some("true"))
    };

    // String field as Option, treating "" as absent (for enum coercers).
    let opt = |k: &str| -> Option<String> {
        let v = s(k);
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    let net = as_network(opt("net").as_deref());
    let raw_path = s("path");
    let vmess_header_type = if s("type") == "http" {
        HeaderType::Http
    } else {
        HeaderType::None
    };

    let remarks = {
        let ps = s("ps");
        if !ps.is_empty() {
            ps
        } else if !s("add").is_empty() {
            s("add")
        } else {
            "VMess".to_string()
        }
    };
    let scy = s("scy");
    let encryption = match scy.as_str() {
        "auto" => VmessEnc::Auto,
        "aes-128-gcm" => VmessEnc::Aes128Gcm,
        "chacha20-poly1305" => VmessEnc::Chacha20Poly1305,
        "none" => VmessEnc::None,
        "zero" => VmessEnc::Zero,
        _ => VmessEnc::Auto,
    };

    let t = match net {
        Network::Tcp => Transport::Tcp(TcpTransport {
            header_type: vmess_header_type,
            host: s("host"),
            path: raw_path.clone(),
        }),
        Network::Ws => {
            let w = parse_ws_early_data(&raw_path);
            Transport::Ws(WsTransport {
                host: s("host"),
                path: w.path,
                early_data: w.ws_early_data,
                early_data_header: w.ws_early_data_header,
                heartbeat_period: 0,
                headers: parse_ws_headers(&s("wsHeaders")),
                accept_proxy_protocol: truthy("acceptProxyProtocol"),
            })
        }
        Network::Grpc => Transport::Grpc(GrpcTransport {
            service_name: s("path"),
            authority: s("host"),
            mode: s("type"),
            ..Default::default()
        }),
        Network::H2 => Transport::H2(H2Transport {
            host: s("host"),
            path: raw_path.clone(),
            ..Default::default()
        }),
        Network::Httpupgrade => Transport::Httpupgrade(HttpUpgradeTransport {
            host: s("host"),
            path: raw_path.clone(),
            early_data: 0,
            headers: parse_ws_headers(&s("wsHeaders")),
            accept_proxy_protocol: truthy("acceptProxyProtocol"),
        }),
        Network::Xhttp => Transport::Xhttp(XhttpTransport {
            host: s("host"),
            path: raw_path.clone(),
            ..Default::default()
        }),
        Network::Kcp => Transport::Kcp(KcpTransport {
            header_type: vmess_header_type,
            cwnd_multiplier: num("kcpCwndMultiplier"),
            max_sending_window: num("kcpMaxSendingWindow"),
            ..Default::default()
        }),
        Network::Quic => Transport::Quic(QuicTransport {
            header_type: vmess_header_type,
        }),
    };

    let mut tls = Tls::default();
    tls.security = if s("tls").is_empty() {
        Security::None
    } else {
        as_security(Some(&s("tls")))
    };
    tls.sni = s("sni");
    tls.alpn = split_csv(&s("alpn")).unwrap_or_default();
    tls.fingerprint = as_fingerprint(opt("fp").as_deref());
    tls.allow_insecure = truthy("allowInsecure") || truthy("insecure");

    let port = u16::try_from(num("port"))
        .ok()
        .filter(|n| *n != 0)
        .unwrap_or(443);

    Some(Profile::Vmess(Vmess {
        meta: meta(remarks, group_id),
        endpoint: Endpoint {
            address: s("add"),
            port,
        },
        transport: t,
        tls,
        uuid: s("id"),
        alter_id: num("aid"),
        encryption,
        packet_encoding: PacketEncoding::Empty,
        vmess_global_padding: false,
        vmess_authenticated_length: false,
        mux_enabled: false,
    }))
}

/// shadowsocks — SIP002 (`ss://b64(method:pw)@host:port?plugin=...#tag`) and
/// the legacy fully-base64 form, plus obfs-local / v2ray-plugin handling.
fn parse_ss(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let mut body = uri["ss://".len()..].to_string();
    let mut tag = String::new();
    if let Some(h) = body.find('#') {
        tag = pct(&body[h + 1..]);
        body = body[..h].to_string();
    }
    let mut plugin = String::new();
    if let Some(qi) = body.find('?') {
        let qs = body[qi + 1..].to_string();
        for (k, v) in url::form_urlencoded::parse(qs.as_bytes()) {
            if k == "plugin" {
                plugin = v.into_owned();
                break;
            }
        }
        body = body[..qi].to_string();
    }

    let (method, password, host, port);
    if body.contains('@') {
        let (userinfo, hostport) = split_last(&body, '@');
        let mut creds = userinfo.clone();
        if let Some(dec) = b64decode(&userinfo) {
            if dec.contains(':') {
                creds = dec;
            }
        }
        let (m, p) = split_first(&creds, ':');
        method = m;
        password = p;
        let (h, pt) = parse_host_port(&hostport);
        host = h;
        port = pt;
    } else {
        let dec = b64decode(&body)?;
        if !dec.contains('@') {
            return None;
        }
        let (creds, hostport) = split_last(&dec, '@');
        let (m, p) = split_first(&creds, ':');
        method = m;
        password = p;
        let (h, pt) = parse_host_port(&hostport);
        host = h;
        port = pt;
    }
    if host.is_empty() {
        return None;
    }

    let mut p = Shadowsocks {
        meta: meta(if tag.is_empty() { host.clone() } else { tag }, group_id),
        endpoint: Endpoint {
            address: host,
            port,
        },
        transport: Transport::default(),
        tls: Tls::default(),
        password,
        method: as_ss_method(&method),
        mux_enabled: false,
    };

    if !plugin.is_empty() {
        let parts: Vec<&str> = plugin.split(';').filter(|s| !s.is_empty()).collect();
        let mut name = parts.first().copied().unwrap_or("");
        if name == "simple-obfs" {
            name = "obfs-local";
        }
        let field = |prefix: &str| -> Option<String> {
            parts
                .iter()
                .find(|p| p.starts_with(prefix))
                .map(|p| p[prefix.len()..].to_string())
        };
        if name == "obfs-local" {
            if parts.contains(&"obfs=http") {
                p.transport = Transport::Tcp(TcpTransport {
                    header_type: HeaderType::Http,
                    host: field("obfs-host=").unwrap_or_default(),
                    path: field("path=").unwrap_or_default(),
                });
            }
        } else if name == "v2ray-plugin" {
            let mode = field("mode=").unwrap_or_else(|| "websocket".into());
            let host_part = field("host=").unwrap_or_default();
            let path_part = field("path=");
            let tls = parts.contains(&"tls");
            // The host is only carried on the ws transport; track it so the SNI
            // fallback below matches the old read of `transport.host`.
            let mut stored_host = String::new();
            if mode == "websocket" {
                stored_host = host_part.clone();
                p.transport = Transport::Ws(WsTransport {
                    host: host_part,
                    path: path_part
                        .unwrap_or_default()
                        .replace("\\=", "=")
                        .replace("\\,", ",")
                        .replace("\\\\", "\\"),
                    ..Default::default()
                });
            } else if mode == "quic" {
                p.transport = Transport::Quic(QuicTransport::default());
            }
            if tls {
                p.tls.security = Security::Tls;
                if !stored_host.is_empty() && p.tls.sni.is_empty() {
                    p.tls.sni = stored_host;
                }
            }
        }
    }

    Some(Profile::Shadowsocks(p))
}

fn parse_hysteria2(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    // Normalise the hy2:// alias so the URL parser keeps a stable scheme.
    let normalised = if let Some(rest) = uri.strip_prefix("hy2://") {
        format!("hysteria2://{rest}")
    } else {
        uri.to_string()
    };
    let u = Url::parse(&normalised).ok()?;
    let q = query_map(&u);
    let mut tls = Tls::default();
    tls.security = Security::Tls;
    tls.sni = q.get("sni").cloned().unwrap_or_default();
    tls.alpn = split_csv(&q.get("alpn").cloned().unwrap_or_default()).unwrap_or_default();
    tls.allow_insecure = q.get("insecure").map(String::as_str) == Some("1");
    Some(Profile::Hysteria2(Hysteria2 {
        meta: meta(remarks_or_host(&u), group_id),
        endpoint: Endpoint {
            address: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(443),
        },
        tls,
        password: pct(u.username()),
        obfs_type: if q.get("obfs").map(String::as_str) == Some("salamander") {
            Hysteria2Obfs::Salamander
        } else {
            Hysteria2Obfs::Empty
        },
        obfs_password: q.get("obfs-password").cloned().unwrap_or_default(),
        ports: q.get("mport").cloned().unwrap_or_default(),
        hop_interval: String::new(),
        up_mbps: 0,
        down_mbps: 0,
        pin_sha256: q.get("pinSHA256").cloned().unwrap_or_default(),
    }))
}

fn parse_tuic(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let mut tls = Tls::default();
    tls.security = Security::Tls;
    tls.sni = q.get("sni").cloned().unwrap_or_default();
    tls.alpn = split_csv(&q.get("alpn").cloned().unwrap_or_default()).unwrap_or_default();
    tls.allow_insecure = query_truthy(&q, &["allow_insecure", "allowInsecure", "insecure"]);
    Some(Profile::Tuic(Tuic {
        meta: meta(remarks_or_host(&u), group_id),
        endpoint: Endpoint {
            address: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(443),
        },
        tls,
        uuid: pct(u.username()),
        password: pct(u.password().unwrap_or("")),
        congestion_control: as_cc(q.get("congestion_control").map(String::as_str)),
        udp_relay_mode: q.get("udp_relay_mode").cloned().unwrap_or_default(),
        zero_rtt: query_truthy(&q, &["zero_rtt_handshake"]),
        udp_over_stream: false,
        heartbeat: String::new(),
    }))
}

fn parse_anytls(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let cred = {
        let un = pct(u.username());
        if un.is_empty() {
            pct(u.password().unwrap_or(""))
        } else {
            un
        }
    };
    let mut tls = Tls::default();
    tls.security = Security::Tls;
    tls.sni = q.get("sni").cloned().unwrap_or_default();
    tls.alpn = split_csv(&q.get("alpn").cloned().unwrap_or_default()).unwrap_or_default();
    tls.fingerprint = as_fingerprint(q.get("fp").map(String::as_str));
    tls.allow_insecure = query_truthy(&q, &["allowInsecure", "allow_insecure", "insecure"]);
    tls.ech = q.get("ech").cloned().unwrap_or_default();
    tls.pcs = q.get("pcs").cloned().unwrap_or_default();
    Some(Profile::Anytls(Anytls {
        meta: meta(remarks_or_host(&u), group_id),
        endpoint: Endpoint {
            address: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(443),
        },
        tls,
        password: cred,
        idle_session_check_interval: String::new(),
        idle_session_timeout: String::new(),
        min_idle_session: 0,
    }))
}

fn parse_naive(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let mut tls = Tls::default();
    tls.security = Security::Tls;
    tls.sni = q.get("sni").cloned().unwrap_or_default();
    tls.alpn = split_csv(&q.get("alpn").cloned().unwrap_or_default()).unwrap_or_default();
    tls.fingerprint = as_fingerprint(q.get("fp").map(String::as_str));
    tls.allow_insecure = query_truthy(&q, &["allowInsecure", "allow_insecure", "insecure"]);
    tls.ech = q.get("ech").cloned().unwrap_or_default();
    tls.pcs = q.get("pcs").cloned().unwrap_or_default();
    Some(Profile::Naive(Naive {
        meta: meta(remarks_or_host(&u), group_id),
        endpoint: Endpoint {
            address: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(443),
        },
        tls,
        username: pct(u.username()),
        password: pct(u.password().unwrap_or("")),
        naive_quic: u.scheme().starts_with("naive+quic"),
        congestion_control: as_cc(q.get("congestion_control").map(String::as_str)),
        insecure_concurrency: q
            .get("insecure-concurrency")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    }))
}

fn parse_shadowtls(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let u = Url::parse(uri).ok()?;
    let q = query_map(&u);
    let ver = q
        .get("version")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n != 0)
        .unwrap_or(3)
        .clamp(1, 3);
    let mut tls = Tls::default();
    tls.security = Security::Tls;
    tls.sni = q.get("sni").cloned().unwrap_or_default();
    tls.fingerprint = as_fingerprint(q.get("fp").map(String::as_str));
    let cred = {
        let un = pct(u.username());
        if un.is_empty() {
            pct(u.password().unwrap_or(""))
        } else {
            un
        }
    };
    Some(Profile::Shadowtls(Shadowtls {
        meta: meta(remarks_or_host(&u), group_id),
        endpoint: Endpoint {
            address: u.host_str().unwrap_or("").to_string(),
            port: u.port().unwrap_or(443),
        },
        tls,
        version: ver,
        password: cred,
    }))
}

/// Parse a single share link into a [`Profile`], or `None` if unsupported.
pub fn parse_share_link(uri: &str, group_id: Option<&str>) -> Option<Profile> {
    let s = uri.trim();
    if s.starts_with("vmess://") {
        return parse_vmess(s, group_id);
    }
    if s.starts_with("vless://") {
        return parse_url_based(s, UrlProto::Vless, group_id);
    }
    if s.starts_with("trojan://") {
        return parse_url_based(s, UrlProto::Trojan, group_id);
    }
    if s.starts_with("ss://") {
        return parse_ss(s, group_id);
    }
    if s.starts_with("hysteria2://") || s.starts_with("hy2://") {
        return parse_hysteria2(s, group_id);
    }
    if s.starts_with("tuic://") {
        return parse_tuic(s, group_id);
    }
    if s.starts_with("anytls://") {
        return parse_anytls(s, group_id);
    }
    if s.starts_with("naive+https://") || s.starts_with("naive+quic://") {
        return parse_naive(s, group_id);
    }
    if s.starts_with("shadowtls://") {
        return parse_shadowtls(s, group_id);
    }
    if s.starts_with("wireguard://") {
        return parse_wireguard(s, group_id);
    }
    if s.starts_with("socks://") || s.starts_with("socks5://") {
        return parse_socks_or_http(s, SockHttp::Socks, group_id);
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        return parse_socks_or_http(s, SockHttp::Http, group_id);
    }
    None
}

// ======================= build =======================

/// `encodeURIComponent`: percent-encode everything but the JS "unreserved" set.
const COMPONENT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, COMPONENT).to_string()
}

/// The wire string of a serde enum (e.g. `Network::Ws` → `"ws"`).
fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn b64encode(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// Minimal ordered query string (URLSearchParams-compatible form encoding).
#[derive(Default)]
struct Query(Vec<(String, String)>);
impl Query {
    fn set(&mut self, k: &str, v: impl Into<String>) {
        self.0.push((k.to_string(), v.into()));
    }
    fn finish(&self) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(self.0.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .finish()
    }
}

fn frag(remarks: &str) -> String {
    if remarks.is_empty() {
        String::new()
    } else {
        format!("#{}", enc(remarks))
    }
}

fn userinfo(username: &str, password: &str) -> String {
    if username.is_empty() {
        enc(password)
    } else {
        format!("{}:{}", enc(username), enc(password))
    }
}

fn build_vmess(p: &Vmess) -> String {
    let t = &p.transport;
    let mut c = serde_json::Map::new();
    let mut put = |k: &str, v: serde_json::Value| {
        c.insert(k.to_string(), v);
    };
    put("v", "2".into());
    put("ps", p.meta.remarks.clone().into());
    put("add", p.endpoint.address.clone().into());
    put("port", p.endpoint.port.to_string().into());
    put("id", p.uuid.clone().into());
    put("aid", p.alter_id.to_string().into());
    let scy = wire(&p.encryption);
    put(
        "scy",
        if scy.is_empty() {
            "auto".into()
        } else {
            scy.into()
        },
    );
    put("net", wire(&t.network()).into());
    put(
        "type",
        match t {
            Transport::Grpc(g) => {
                if g.mode.is_empty() {
                    "gun".into()
                } else {
                    g.mode.clone().into()
                }
            }
            _ => wire(&t.header_type()).into(),
        },
    );
    put(
        "host",
        match t {
            Transport::Grpc(g) => g.authority.clone().into(),
            _ => t.host().to_string().into(),
        },
    );
    put(
        "path",
        match t {
            Transport::Grpc(g) => g.service_name.clone(),
            Transport::Ws(w) => {
                crate::config_shared::build_ws_path(&w.path, w.early_data, &w.early_data_header)
            }
            other => other.path().to_string(),
        }
        .into(),
    );
    put(
        "tls",
        if p.tls.security == Security::None {
            "".into()
        } else {
            wire(&p.tls.security).into()
        },
    );
    put("sni", p.tls.sni.clone().into());
    put("alpn", p.tls.alpn.join(",").into());
    put("fp", wire(&p.tls.fingerprint).into());
    let ws_headers = match t {
        Transport::Ws(w) => build_ws_headers(&w.headers),
        Transport::Httpupgrade(h) => build_ws_headers(&h.headers),
        _ => String::new(),
    };
    put("wsHeaders", ws_headers.into());
    let accept_proxy = match t {
        Transport::Ws(w) => w.accept_proxy_protocol,
        Transport::Httpupgrade(h) => h.accept_proxy_protocol,
        _ => false,
    };
    if accept_proxy {
        put("acceptProxyProtocol", true.into());
    }
    if let Transport::Httpupgrade(h) = t {
        if h.early_data != 0 {
            put("ed", h.early_data.into());
        }
    }
    if p.vmess_global_padding {
        put("vmessGlobalPadding", true.into());
    }
    if p.vmess_authenticated_length {
        put("vmessAuthenticatedLength", true.into());
    }
    if let Transport::Kcp(k) = t {
        if k.cwnd_multiplier != 0 {
            put("kcpCwndMultiplier", k.cwnd_multiplier.into());
        }
        if k.max_sending_window != 0 {
            put("kcpMaxSendingWindow", k.max_sending_window.into());
        }
    }
    format!(
        "vmess://{}",
        b64encode(&serde_json::Value::Object(c).to_string())
    )
}

/// vless / trojan share URLs.
fn build_url_based(p: &Profile) -> String {
    let (proto, t, tls, cred, flow, encryption) = match p {
        Profile::Vless(v) => (
            "vless",
            &v.transport,
            &v.tls,
            v.uuid.as_str(),
            wire(&v.flow),
            Some(v.encryption.clone()),
        ),
        Profile::Trojan(tr) => (
            "trojan",
            &tr.transport,
            &tr.tls,
            tr.password.as_str(),
            wire(&tr.flow),
            None,
        ),
        _ => unreachable!("build_url_based on non vless/trojan"),
    };
    let mut q = Query::default();
    q.set("type", wire(&t.network()));
    q.set("security", wire(&tls.security));
    match t {
        Transport::Grpc(g) => {
            if !g.mode.is_empty() {
                q.set("mode", g.mode.clone());
            }
            if !g.authority.is_empty() {
                q.set("authority", g.authority.clone());
            }
            if !g.service_name.is_empty() {
                q.set("serviceName", g.service_name.clone());
            }
        }
        Transport::Xhttp(x) => {
            if !x.host.is_empty() {
                q.set("host", x.host.clone());
            }
            if !x.path.is_empty() {
                q.set("path", x.path.clone());
            }
            if !x.mode.is_empty() {
                q.set("mode", x.mode.clone());
            }
            if !x.extra.is_empty() {
                q.set("extra", x.extra.clone());
            }
        }
        other => {
            if !other.host().is_empty() {
                q.set("host", other.host().to_string());
            }
            let path = match other {
                Transport::Ws(w) => {
                    crate::config_shared::build_ws_path(&w.path, w.early_data, &w.early_data_header)
                }
                _ => other.path().to_string(),
            };
            if !path.is_empty() {
                q.set("path", path);
            }
            match other {
                Transport::Ws(w) => {
                    let headers = build_ws_headers(&w.headers);
                    if !headers.is_empty() {
                        q.set("wsHeaders", headers);
                    }
                    if w.accept_proxy_protocol {
                        q.set("acceptProxyProtocol", "1");
                    }
                }
                Transport::Httpupgrade(h) => {
                    let headers = build_ws_headers(&h.headers);
                    if !headers.is_empty() {
                        q.set("wsHeaders", headers);
                    }
                    if h.accept_proxy_protocol {
                        q.set("acceptProxyProtocol", "1");
                    }
                    if h.early_data > 0 {
                        q.set("ed", h.early_data.to_string());
                    }
                }
                Transport::Kcp(k) => {
                    if k.cwnd_multiplier != 0 {
                        q.set("kcpCwndMultiplier", k.cwnd_multiplier.to_string());
                    }
                    if k.max_sending_window != 0 {
                        q.set("kcpMaxSendingWindow", k.max_sending_window.to_string());
                    }
                }
                _ => {}
            }
        }
    }
    if !tls.sni.is_empty() {
        q.set("sni", tls.sni.clone());
    }
    if !tls.alpn.is_empty() {
        q.set("alpn", tls.alpn.join(","));
    }
    if tls.fingerprint != Fingerprint::Empty {
        q.set("fp", wire(&tls.fingerprint));
    }
    if tls.allow_insecure {
        q.set("allowInsecure", "1");
    }
    if tls.security == Security::Reality {
        if !tls.public_key.is_empty() {
            q.set("pbk", tls.public_key.clone());
        }
        if !tls.short_id.is_empty() {
            q.set("sid", tls.short_id.clone());
        }
        if !tls.spider_x.is_empty() {
            q.set("spx", tls.spider_x.clone());
        }
    }
    if !tls.ech.is_empty() {
        q.set("ech", tls.ech.clone());
    }
    if !tls.vcn.is_empty() {
        q.set("vcn", tls.vcn.clone());
    }
    if !tls.pcs.is_empty() {
        q.set("pcs", tls.pcs.clone());
    }
    if !tls.pqv.is_empty() {
        q.set("pqv", tls.pqv.clone());
    }
    if !flow.is_empty() {
        q.set("flow", flow);
    }
    if let Some(enc_v) = encryption {
        q.set(
            "encryption",
            if enc_v.is_empty() {
                "none".into()
            } else {
                enc_v
            },
        );
    }
    let m = p.meta();
    let ep = match p {
        Profile::Vless(v) => &v.endpoint,
        Profile::Trojan(tr) => &tr.endpoint,
        _ => unreachable!(),
    };
    format!(
        "{proto}://{}@{}:{}?{}{}",
        enc(cred),
        ep.address,
        ep.port,
        q.finish(),
        frag(&m.remarks)
    )
}

fn build_ss(p: &Shadowsocks) -> String {
    let info = b64encode(&format!("{}:{}", wire(&p.method), p.password));
    let mut q = Query::default();
    match &p.transport {
        Transport::Tcp(tc) if tc.header_type == HeaderType::Http => {
            let mut parts = vec!["obfs-local".to_string(), "obfs=http".to_string()];
            if !tc.host.is_empty() {
                parts.push(format!("obfs-host={}", tc.host));
            }
            if !tc.path.is_empty() {
                parts.push(format!("path={}", tc.path));
            }
            q.set("plugin", parts.join(";"));
        }
        other => {
            let is_ws = matches!(other, Transport::Ws(_));
            let is_quic = matches!(other, Transport::Quic(_));
            if is_ws || is_quic || p.tls.security == Security::Tls {
                let mut parts = vec!["v2ray-plugin".to_string()];
                if let Transport::Ws(w) = other {
                    parts.push("mode=websocket".into());
                    if !w.host.is_empty() {
                        parts.push(format!("host={}", w.host));
                    }
                    if !w.path.is_empty() {
                        let path = w
                            .path
                            .replace('\\', "\\\\")
                            .replace('=', "\\=")
                            .replace(',', "\\,");
                        parts.push(format!("path={path}"));
                    }
                } else if is_quic {
                    parts.push("mode=quic".into());
                }
                if p.tls.security == Security::Tls {
                    parts.push("tls".into());
                }
                parts.push("mux=0".into());
                q.set("plugin", parts.join(";"));
            }
        }
    }
    let qs = q.finish();
    let qs = if qs.is_empty() {
        String::new()
    } else {
        format!("?{qs}")
    };
    format!(
        "ss://{info}@{}:{}{qs}{}",
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

fn build_hysteria2(p: &Hysteria2) -> String {
    let mut q = Query::default();
    if !p.tls.sni.is_empty() {
        q.set("sni", p.tls.sni.clone());
    }
    if !p.tls.alpn.is_empty() {
        q.set("alpn", p.tls.alpn.join(","));
    }
    if p.tls.allow_insecure {
        q.set("insecure", "1");
    }
    if p.obfs_type == Hysteria2Obfs::Salamander && !p.obfs_password.is_empty() {
        q.set("obfs", "salamander");
        q.set("obfs-password", p.obfs_password.clone());
    }
    if !p.ports.is_empty() {
        q.set("mport", p.ports.replace(':', "-"));
    }
    if !p.pin_sha256.is_empty() {
        q.set("pinSHA256", p.pin_sha256.clone());
    }
    let qs = q.finish();
    let qs = if qs.is_empty() {
        String::new()
    } else {
        format!("?{qs}")
    };
    format!(
        "hysteria2://{}@{}:{}{qs}{}",
        enc(&p.password),
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

fn build_tuic(p: &Tuic) -> String {
    let mut q = Query::default();
    q.set("congestion_control", wire(&p.congestion_control));
    if !p.udp_relay_mode.is_empty() {
        q.set("udp_relay_mode", p.udp_relay_mode.clone());
    }
    if p.zero_rtt {
        q.set("zero_rtt_handshake", "1");
    }
    if !p.tls.sni.is_empty() {
        q.set("sni", p.tls.sni.clone());
    }
    if !p.tls.alpn.is_empty() {
        q.set("alpn", p.tls.alpn.join(","));
    }
    if p.tls.allow_insecure {
        q.set("allow_insecure", "1");
    }
    format!(
        "tuic://{}:{}@{}:{}?{}{}",
        enc(&p.uuid),
        enc(&p.password),
        p.endpoint.address,
        p.endpoint.port,
        q.finish(),
        frag(&p.meta.remarks)
    )
}

fn build_anytls(p: &Anytls) -> String {
    let mut q = Query::default();
    if !p.tls.sni.is_empty() {
        q.set("sni", p.tls.sni.clone());
    }
    if !p.tls.alpn.is_empty() {
        q.set("alpn", p.tls.alpn.join(","));
    }
    if p.tls.fingerprint != Fingerprint::Empty {
        q.set("fp", wire(&p.tls.fingerprint));
    }
    if p.tls.allow_insecure {
        q.set("allowInsecure", "1");
    }
    if !p.tls.ech.is_empty() {
        q.set("ech", p.tls.ech.clone());
    }
    if !p.tls.pcs.is_empty() {
        q.set("pcs", p.tls.pcs.clone());
    }
    let qs = q.finish();
    let qs = if qs.is_empty() {
        String::new()
    } else {
        format!("?{qs}")
    };
    format!(
        "anytls://{}@{}:{}{qs}{}",
        enc(&p.password),
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

fn build_naive(p: &Naive) -> String {
    let mut q = Query::default();
    q.set("congestion_control", wire(&p.congestion_control));
    if p.insecure_concurrency != 0 {
        q.set("insecure-concurrency", p.insecure_concurrency.to_string());
    }
    if !p.tls.sni.is_empty() {
        q.set("sni", p.tls.sni.clone());
    }
    if !p.tls.alpn.is_empty() {
        q.set("alpn", p.tls.alpn.join(","));
    }
    if p.tls.fingerprint != Fingerprint::Empty {
        q.set("fp", wire(&p.tls.fingerprint));
    }
    if p.tls.allow_insecure {
        q.set("allowInsecure", "1");
    }
    if !p.tls.ech.is_empty() {
        q.set("ech", p.tls.ech.clone());
    }
    if !p.tls.pcs.is_empty() {
        q.set("pcs", p.tls.pcs.clone());
    }
    let qs = q.finish();
    let qs = if qs.is_empty() {
        String::new()
    } else {
        format!("?{qs}")
    };
    let scheme = if p.naive_quic {
        "naive+quic"
    } else {
        "naive+https"
    };
    format!(
        "{scheme}://{}@{}:{}{qs}{}",
        userinfo(&p.username, &p.password),
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

fn build_shadowtls(p: &Shadowtls) -> String {
    let mut q = Query::default();
    q.set("version", p.version.to_string());
    if !p.tls.sni.is_empty() {
        q.set("sni", p.tls.sni.clone());
    }
    if p.tls.fingerprint != Fingerprint::Empty {
        q.set("fp", wire(&p.tls.fingerprint));
    }
    format!(
        "shadowtls://{}@{}:{}?{}{}",
        enc(&p.password),
        p.endpoint.address,
        p.endpoint.port,
        q.finish(),
        frag(&p.meta.remarks)
    )
}

fn build_wireguard(p: &Wireguard) -> String {
    let mut q = Query::default();
    if !p.peer_public_key.is_empty() {
        q.set("publickey", p.peer_public_key.clone());
    }
    if !p.pre_shared_key.is_empty() {
        q.set("presharedkey", p.pre_shared_key.clone());
    }
    if !p.reserved.is_empty() {
        let csv = p
            .reserved
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        q.set("reserved", csv);
    }
    if !p.local_address.is_empty() && p.local_address != "172.16.0.2/32" {
        q.set("address", p.local_address.clone());
    }
    if p.mtu != 0 && p.mtu != 1420 {
        q.set("mtu", p.mtu.to_string());
    }
    let qs = q.finish();
    let qs = if qs.is_empty() {
        String::new()
    } else {
        format!("?{qs}")
    };
    format!(
        "wireguard://{}@{}:{}{qs}{}",
        enc(&p.secret_key),
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

fn build_socks(p: &Socks) -> String {
    format!(
        "socks5://{}@{}:{}{}",
        userinfo(&p.username, &p.password),
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

fn build_http(p: &Http) -> String {
    let mut q = Query::default();
    if p.tls.security == Security::Tls && !p.tls.sni.is_empty() {
        q.set("sni", p.tls.sni.clone());
    }
    let scheme = if p.tls.security == Security::Tls {
        "https"
    } else {
        "http"
    };
    let qs = q.finish();
    let qs = if qs.is_empty() {
        String::new()
    } else {
        format!("?{qs}")
    };
    format!(
        "{scheme}://{}@{}:{}{qs}{}",
        userinfo(&p.username, &p.password),
        p.endpoint.address,
        p.endpoint.port,
        frag(&p.meta.remarks)
    )
}

// ======================= extract =======================

// Shareable schemes (S = the proxy schemes; SH adds http/https, which only count
// as links when they carry userinfo `@`). FRAG lazily captures a remarks fragment
// up to the next whitespace-separated scheme, a newline, or end (lookahead).
const SCHEMES: &str = r"vless|vmess|trojan|ss|hysteria2|hy2|tuic|anytls|naive\+https|naive\+quic|shadowtls|wireguard|socks5?";

static URI_RE: LazyLock<FancyRegex> = LazyLock::new(|| {
    let sh = format!("{SCHEMES}|https?");
    let frag = format!(r"(?:#[^\r\n]*?(?=\s+(?:{sh})://|[\r\n]|$))?");
    let pat = format!(r"(?:{sh})://[^\s@]*@[^\s#]*{frag}|(?:{SCHEMES})://[^\s#]*{frag}");
    FancyRegex::new(&pat).unwrap()
});

fn is_b64_candidate(s: &str) -> bool {
    s.len() > 8
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'))
}

/// Extract every share URI from arbitrary text, recursively decoding base64
/// subscription blobs (depth-capped). Order-preserving dedup.
pub fn extract_uris(text: &str) -> Vec<String> {
    fn go(text: &str, depth: u32, out: &mut Vec<String>) {
        for m in URI_RE.find_iter(text).flatten() {
            out.push(m.as_str().to_string());
        }
        if depth < 3 {
            let mut candidates: Vec<&str> = vec![text.trim()];
            candidates.extend(text.split('\n').map(str::trim));
            for cand in candidates {
                if cand.is_empty() || !is_b64_candidate(cand) {
                    continue;
                }
                if let Some(dec) = b64decode(cand) {
                    if URI_RE.is_match(&dec).unwrap_or(false) {
                        go(&dec, depth + 1, out);
                    }
                }
            }
        }
    }
    let mut raw = Vec::new();
    go(text, 0, &mut raw);
    // Order-preserving dedup: keep the first occurrence of each URI.
    let mut seen = std::collections::HashSet::new();
    raw.into_iter().filter(|u| seen.insert(u.clone())).collect()
}

/// Parse all share links found in arbitrary text into profiles.
pub fn parse_share_links(text: &str, group_id: Option<&str>) -> Vec<Profile> {
    extract_uris(text)
        .iter()
        .filter_map(|u| parse_share_link(u, group_id))
        .collect()
}

// ======================= build =======================

/// Build a share link from a [`Profile`] (`""` for `custom`, which has no URI).
pub fn build_share_link(p: &Profile) -> String {
    match p {
        Profile::Vmess(v) => build_vmess(v),
        Profile::Vless(_) | Profile::Trojan(_) => build_url_based(p),
        Profile::Shadowsocks(s) => build_ss(s),
        Profile::Hysteria2(h) => build_hysteria2(h),
        Profile::Tuic(t) => build_tuic(t),
        Profile::Anytls(a) => build_anytls(a),
        Profile::Naive(n) => build_naive(n),
        Profile::Shadowtls(s) => build_shadowtls(s),
        Profile::Wireguard(w) => build_wireguard(w),
        Profile::Socks(s) => build_socks(s),
        Profile::Http(h) => build_http(h),
        Profile::Custom(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const FIXTURES: &str = include_str!("../tests/fixtures/share_parse.json");
    const REFERENCE_FLAT: &str = include_str!("../tests/fixtures/share_reference.json");

    /// Branch-coverage parity: an independent flat parse of each URI, fed through
    /// the proven `migrate_profile` upgrade, must equal `parse_share_link` for
    /// every case. The flat reference is independent of the Rust model, so this
    /// pins the parser across every protocol × network × option branch without
    /// circularity.
    #[test]
    fn migrated_flat_reference_equals_parse_for_every_branch() {
        use serde_json::Value;
        let cases: Vec<Value> = serde_json::from_str(REFERENCE_FLAT).unwrap();
        for c in &cases {
            let uri = c["uri"].as_str().unwrap();
            let flat = &c["flat"];
            let got = parse_share_link(uri, None);

            if flat.is_null() {
                assert!(got.is_none(), "expected None for {uri}, got {got:?}");
                continue;
            }
            let mut migrated = flat.clone();
            crate::migrate::migrate_profile(&mut migrated);
            let expected: Profile = serde_json::from_value(migrated)
                .unwrap_or_else(|e| panic!("deserialize migrated flat for {uri}: {e}"));
            let mut want = serde_json::to_value(&expected).unwrap();
            let mut have =
                serde_json::to_value(got.unwrap_or_else(|| panic!("parse None for {uri}")))
                    .unwrap();
            want["meta"]["id"] = Value::String(String::new());
            have["meta"]["id"] = Value::String(String::new());
            assert_eq!(have, want, "parse vs migrated-reference mismatch for {uri}");
        }
        assert_eq!(cases.len(), 54);
    }

    #[test]
    fn parse_matches_reference_for_every_case() {
        let cases: Vec<Value> = serde_json::from_str(FIXTURES).unwrap();
        for c in &cases {
            let uri = c["uri"].as_str().unwrap();
            let expected = &c["profile"];
            let got = parse_share_link(uri, None);

            if expected.is_null() {
                assert!(got.is_none(), "expected None for {uri}, got {got:?}");
                continue;
            }
            let got = got.unwrap_or_else(|| panic!("parser returned None for {uri}"));
            let mut got_v = serde_json::to_value(&got).unwrap();
            got_v["meta"]["id"] = Value::String(String::new()); // normalise the random uid()
            assert_eq!(&got_v, expected, "mismatch for {uri}");
        }
        assert_eq!(cases.len(), 25);
    }

    #[test]
    fn build_then_parse_reaches_a_fixpoint() {
        // build∘parse is idempotent once any lossy fields settle (e.g. the vmess
        // builder intentionally omits allowInsecure, so the FIRST parse may carry
        // a field the builder drops). So assert the fixpoint from the SECOND parse
        // onward: parse→build→parse twice must agree. This pins the builders
        // against the reference-verified parser, and that the re-built URI is
        // stable, without needing build-output fixtures.
        let cases: Vec<Value> = serde_json::from_str(FIXTURES).unwrap();
        let norm = |p: &Profile| {
            let mut v = serde_json::to_value(p).unwrap();
            v["meta"]["id"] = Value::String(String::new());
            v
        };
        let mut checked = 0;
        for c in &cases {
            let uri = c["uri"].as_str().unwrap();
            let Some(first) = parse_share_link(uri, None) else {
                continue;
            };
            let s1 = build_share_link(&first);
            assert!(!s1.is_empty(), "empty build for {uri}");
            let second = parse_share_link(&s1, None)
                .unwrap_or_else(|| panic!("re-parse failed for {uri} → {s1}"));
            let s2 = build_share_link(&second);
            let third = parse_share_link(&s2, None).unwrap();
            assert_eq!(s1, s2, "build not idempotent for {uri}");
            assert_eq!(norm(&second), norm(&third), "round-trip drift for {uri}");
            checked += 1;
        }
        assert!(
            checked >= 20,
            "expected most cases parseable, got {checked}"
        );
    }

    #[test]
    fn extract_multiple_and_b64_wrapped() {
        let text = "vless://a@h:1?type=tcp#x\ntrojan://p@h:2#y\nnoise";
        assert_eq!(extract_uris(text).len(), 2);

        let inner = "vless://a@h:1?type=tcp#x\ntrojan://p@h:2#y";
        let wrapped = b64encode(inner);
        assert_eq!(parse_share_links(&wrapped, None).len(), 2);
    }

    #[test]
    fn fragment_with_spaces_does_not_bleed() {
        let text = "vless://u@a.com:443#🇩🇪 first name\ntrojan://p@b.com:443#🇷🇺 second name";
        let uris = extract_uris(text);
        assert_eq!(uris.len(), 2);
        assert!(uris[0].contains("first name"));
        assert!(uris[1].contains("second name"));
    }

    #[test]
    fn extract_picks_proxy_schemes_not_plain_urls() {
        let text =
            "http://user:pass@1.2.3.4:8080#proxy vless://u@v.ex:443#V https://example.com/page";
        let uris = extract_uris(text);
        assert!(uris.iter().any(|u| u.starts_with("http://user:")));
        assert!(!uris.iter().any(|u| u == "https://example.com/page"));
        assert!(uris.iter().any(|u| u.starts_with("vless://")));
    }
}
