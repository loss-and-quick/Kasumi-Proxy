//! A provider's sing-box config decomposed into typed profiles. The config never
//! runs as sent: each server outbound becomes the profile its share link would give,
//! with the share parser's defaults, and everything else (inbounds, route, dns, log,
//! experimental, selectors) is left out.

// Transport/Tls carry many fields of which an outbound sets a handful.
#![allow(clippy::field_reassign_with_default)]

use std::collections::{BTreeMap, HashMap};

use happ_sub::meta::{normalize_untrusted_text, single_line};
use serde_json::Value;

use crate::config_shared::parse_ws_early_data;
use crate::enums::{Flow, HeaderType, Hysteria2Obfs, PacketEncoding, Security, VmessEnc};
use crate::mixins::{
    Endpoint, GrpcTransport, H2Transport, HttpUpgradeTransport, Meta, QuicTransport, TcpTransport,
    Tls, Transport, WsTransport,
};
use crate::profile::{
    Anytls, Hysteria2, Naive, Profile, Shadowsocks, Shadowtls, Trojan, Tuic, Vless, Vmess,
    WG_DEFAULT_LOCAL_ADDRESS, Wireguard,
};
use crate::share::{apply_ss_plugin, as_cc, as_fingerprint, as_flow, as_ss_method, meta};

/// What a sing-box config yields.
#[derive(Debug, Default)]
pub struct SingboxImport {
    pub profiles: Vec<Profile>,
    /// Entries Kasumi can't import: unknown or unsupported types and unreadable
    /// servers. Routing outbounds such as `direct` or `selector` are not counted.
    pub skipped: u32,
}

/// Outbounds that route or group traffic instead of reaching a server. Nearly
/// every sing-box config has some, so leaving them out is not worth a warning.
const ROUTING_TYPES: [&str; 5] = ["direct", "block", "dns", "selector", "urltest"];

/// Map the server outbounds and WireGuard endpoints of a sing-box config to profiles.
pub fn import_singbox(config: &Value) -> SingboxImport {
    let entries = ["outbounds", "endpoints"]
        .into_iter()
        .filter_map(|k| config.get(k).and_then(Value::as_array))
        .flatten();
    let mut out = SingboxImport::default();
    let mut by_tag = HashMap::new();
    let mut detours = Vec::new();
    for entry in entries {
        let Some(profile) = server(entry) else {
            if !ROUTING_TYPES.contains(&text(entry, "type").as_str()) {
                out.skipped += 1;
            }
            continue;
        };
        let tag = text(entry, "tag");
        if !tag.is_empty() {
            by_tag.entry(tag).or_insert(profile.meta().id.clone());
        }
        detours.push(text(entry, "detour"));
        out.profiles.push(profile);
    }
    // `detour` dials through another outbound: Kasumi's chain, when that one is a
    // server here too.
    for (p, detour) in out.profiles.iter_mut().zip(detours) {
        let via = by_tag.get(&detour).filter(|id| **id != p.meta().id);
        p.meta_mut().via = via.cloned();
    }
    out
}

fn server(o: &Value) -> Option<Profile> {
    let address = text(o, "server");
    let tag = single_line(&normalize_untrusted_text(&text(o, "tag")));
    let remarks = if tag.is_empty() { address.clone() } else { tag };
    let m = meta(remarks, None);
    let mux_enabled = o.get("multiplex").is_some_and(|mx| flag(mx, "enabled"));
    let port = || port_of(o, "server_port");
    let profile = match text(o, "type").as_str() {
        "vless" => {
            let tls = tls(o, false);
            Profile::Vless(Vless {
                meta: m,
                endpoint: endpoint(address, port()?)?,
                transport: transport(o, tls.security != Security::None)?,
                tls,
                uuid: required(o, "uuid")?,
                flow: as_flow(Some(&text(o, "flow"))),
                encryption: "none".into(),
                // Kasumi sends xudp unless told otherwise.
                packet_encoding: match text(o, "packet_encoding").as_str() {
                    "packetaddr" => PacketEncoding::Packetaddr,
                    _ => PacketEncoding::Empty,
                },
                mux_enabled,
            })
        }
        "vmess" => {
            let tls = tls(o, false);
            Profile::Vmess(Vmess {
                meta: m,
                endpoint: endpoint(address, port()?)?,
                transport: transport(o, tls.security != Security::None)?,
                tls,
                uuid: required(o, "uuid")?,
                alter_id: number(o, "alter_id"),
                encryption: match text(o, "security").as_str() {
                    "aes-128-gcm" => VmessEnc::Aes128Gcm,
                    "chacha20-poly1305" => VmessEnc::Chacha20Poly1305,
                    "none" => VmessEnc::None,
                    "zero" => VmessEnc::Zero,
                    _ => VmessEnc::Auto,
                },
                packet_encoding: match text(o, "packet_encoding").as_str() {
                    "xudp" => PacketEncoding::Xudp,
                    "packetaddr" => PacketEncoding::Packetaddr,
                    _ => PacketEncoding::Empty,
                },
                vmess_global_padding: flag(o, "global_padding"),
                vmess_authenticated_length: flag(o, "authenticated_length"),
                mux_enabled,
            })
        }
        "trojan" => {
            let tls = tls(o, false);
            Profile::Trojan(Trojan {
                meta: m,
                endpoint: endpoint(address, port()?)?,
                transport: transport(o, tls.security != Security::None)?,
                tls,
                password: required(o, "password")?,
                flow: Flow::Empty,
                mux_enabled,
            })
        }
        "shadowsocks" => {
            let mut p = Shadowsocks {
                meta: m,
                endpoint: endpoint(address, port()?)?,
                transport: Transport::default(),
                tls: Tls::off(),
                password: text(o, "password"),
                method: as_ss_method(&text(o, "method")),
                mux_enabled,
            };
            let plugin = text(o, "plugin");
            if !plugin.is_empty() {
                apply_ss_plugin(&mut p, &format!("{plugin};{}", text(o, "plugin_opts")));
            }
            Profile::Shadowsocks(p)
        }
        "hysteria2" => {
            let ranges = strings(o, "server_ports");
            let first_port = ranges
                .first()
                .and_then(|r| r.split([':', '-']).next())
                .and_then(|p| p.trim().parse().ok());
            let obfs = o.get("obfs");
            let salamander = obfs.is_some_and(|x| text(x, "type") == "salamander");
            let tls = tls(o, true);
            Profile::Hysteria2(Hysteria2 {
                meta: m,
                endpoint: endpoint(address, port().or(first_port)?)?,
                password: text(o, "password"),
                obfs_type: if salamander {
                    Hysteria2Obfs::Salamander
                } else {
                    Hysteria2Obfs::Empty
                },
                obfs_password: obfs.map(|x| text(x, "password")).unwrap_or_default(),
                ports: ranges.join(",").replace(':', "-"),
                hop_interval: seconds(&text(o, "hop_interval")),
                up_mbps: number(o, "up_mbps"),
                down_mbps: number(o, "down_mbps"),
                pin_sha256: o
                    .get("tls")
                    .map(|t| strings(t, "certificate_public_key_sha256"))
                    .and_then(|pins| pins.into_iter().next())
                    .unwrap_or_default(),
                tls: Tls {
                    pcs: String::new(),
                    ..tls
                },
            })
        }
        "tuic" => Profile::Tuic(Tuic {
            meta: m,
            endpoint: endpoint(address, port()?)?,
            tls: tls(o, true),
            uuid: required(o, "uuid")?,
            password: text(o, "password"),
            congestion_control: as_cc(Some(&text(o, "congestion_control"))),
            udp_relay_mode: text(o, "udp_relay_mode"),
            zero_rtt: flag(o, "zero_rtt_handshake"),
            udp_over_stream: flag(o, "udp_over_stream"),
            heartbeat: text(o, "heartbeat"),
        }),
        "anytls" => Profile::Anytls(Anytls {
            meta: m,
            endpoint: endpoint(address, port()?)?,
            tls: tls(o, true),
            password: required(o, "password")?,
            idle_session_check_interval: text(o, "idle_session_check_interval"),
            idle_session_timeout: text(o, "idle_session_timeout"),
            min_idle_session: number(o, "min_idle_session"),
        }),
        "naive" => Profile::Naive(Naive {
            meta: m,
            endpoint: endpoint(address, port()?)?,
            tls: tls(o, true),
            username: text(o, "username"),
            password: text(o, "password"),
            naive_quic: flag(o, "quic"),
            congestion_control: as_cc(Some(&text(o, "quic_congestion_control"))),
            insecure_concurrency: number(o, "insecure_concurrency"),
        }),
        "shadowtls" => Profile::Shadowtls(Shadowtls {
            meta: m,
            endpoint: endpoint(address, port()?)?,
            tls: tls(o, true),
            version: Some(number(o, "version"))
                .filter(|v| *v != 0)
                .unwrap_or(3)
                .clamp(1, 3),
            password: text(o, "password"),
        }),
        "wireguard" => wireguard(o, m)?,
        _ => return None,
    };
    Some(profile)
}

/// The endpoint form (`endpoints[]`, a peer list) and the older outbound form.
fn wireguard(o: &Value, m: Meta) -> Option<Profile> {
    let peer = o
        .get("peers")
        .and_then(Value::as_array)
        .and_then(|p| p.first());
    let (peer, address, port, public_key) = match peer {
        Some(p) => (p, text(p, "address"), port_of(p, "port")?, "public_key"),
        None => (
            o,
            text(o, "server"),
            port_of(o, "server_port")?,
            "peer_public_key",
        ),
    };
    let local = match strings(o, "address") {
        a if !a.is_empty() => a,
        _ => strings(o, "local_address"),
    };
    let reserved = peer
        .get("reserved")
        .and_then(Value::as_array)
        .map(|r| {
            r.iter()
                .filter_map(|b| b.as_u64()?.try_into().ok())
                .collect()
        })
        .unwrap_or_default();
    Some(Profile::Wireguard(Wireguard {
        meta: Meta {
            remarks: if m.remarks.is_empty() {
                address.clone()
            } else {
                m.remarks
            },
            ..m
        },
        endpoint: endpoint(address, port)?,
        secret_key: required(o, "private_key")?,
        peer_public_key: required(peer, public_key)?,
        pre_shared_key: text(peer, "pre_shared_key"),
        reserved,
        local_address: if local.is_empty() {
            WG_DEFAULT_LOCAL_ADDRESS.into()
        } else {
            local.join(",")
        },
        mtu: Some(number(o, "mtu")).filter(|m| *m != 0).unwrap_or(1420),
        workers: number(o, "workers"),
        persistent_keepalive: number(peer, "persistent_keepalive_interval"),
    }))
}

/// `always` for the protocols whose share links are TLS-only.
fn tls(o: &Value, always: bool) -> Tls {
    let mut tls = Tls::default();
    let t = o.get("tls").filter(|t| flag(t, "enabled"));
    let reality = t
        .and_then(|t| t.get("reality"))
        .filter(|r| flag(r, "enabled"));
    tls.security = match (t, reality) {
        (_, Some(_)) => Security::Reality,
        (Some(_), None) => Security::Tls,
        (None, None) if always => Security::Tls,
        (None, None) => Security::None,
    };
    let Some(t) = t else {
        return tls;
    };
    tls.sni = text(t, "server_name");
    tls.disable_sni = flag(t, "disable_sni");
    tls.allow_insecure = flag(t, "insecure");
    tls.alpn = strings(t, "alpn");
    tls.tls_min_version = text(t, "min_version");
    tls.tls_max_version = text(t, "max_version");
    tls.tls_cipher_suites = strings(t, "cipher_suites");
    tls.tls_curve_preferences = strings(t, "curve_preferences");
    tls.cert = strings(t, "certificate").join("\n");
    tls.pcs = strings(t, "certificate_public_key_sha256")
        .into_iter()
        .next()
        .unwrap_or_default();
    if let Some(u) = t.get("utls").filter(|u| flag(u, "enabled")) {
        tls.fingerprint = as_fingerprint(Some(&text(u, "fingerprint")));
    }
    if let Some(r) = reality {
        tls.public_key = text(r, "public_key");
        tls.short_id = text(r, "short_id");
    }
    // Share links carry the bare base64 ECHConfigList; sing-box wraps it in PEM.
    if let Some(e) = t.get("ech").filter(|e| flag(e, "enabled")) {
        tls.ech = strings(e, "config")
            .iter()
            .flat_map(|l| l.lines())
            .map(str::trim)
            .filter(|l| !l.starts_with("-----"))
            .collect();
    }
    tls
}

/// `None` for a transport Kasumi has no profile field for.
fn transport(o: &Value, tls_on: bool) -> Option<Transport> {
    let Some(t) = o.get("transport") else {
        return Some(Transport::default());
    };
    let path = text(t, "path");
    Some(match text(t, "type").as_str() {
        "ws" => {
            let (host, headers) = host_and_headers(t);
            let early = parse_ws_early_data(&path);
            let max_early = number(t, "max_early_data");
            let header = text(t, "early_data_header_name");
            let (early_data, early_data_header) = if max_early > 0 {
                let header = if header.is_empty() {
                    "Sec-WebSocket-Protocol".into()
                } else {
                    header
                };
                (max_early, header)
            } else if !header.is_empty() {
                (early.ws_early_data, header)
            } else {
                (early.ws_early_data, early.ws_early_data_header)
            };
            Transport::Ws(WsTransport {
                host,
                path: early.path,
                early_data,
                early_data_header,
                heartbeat_period: 0,
                headers,
                accept_proxy_protocol: false,
            })
        }
        "grpc" => Transport::Grpc(GrpcTransport {
            service_name: text(t, "service_name"),
            ..Default::default()
        }),
        // sing-box speaks HTTP/2 over TLS and plain HTTP/1.1 otherwise, which is
        // what Kasumi's TCP HTTP header becomes in a sing-box config.
        "http" if tls_on => Transport::H2(H2Transport {
            host: strings(t, "host").join(","),
            path,
            ..Default::default()
        }),
        "http" => Transport::Tcp(TcpTransport {
            header_type: HeaderType::Http,
            host: strings(t, "host").join(","),
            path,
        }),
        "httpupgrade" => {
            let (header_host, headers) = host_and_headers(t);
            let host = text(t, "host");
            Transport::Httpupgrade(HttpUpgradeTransport {
                host: if host.is_empty() { header_host } else { host },
                path,
                early_data: 0,
                headers,
                accept_proxy_protocol: false,
            })
        }
        "quic" => Transport::Quic(QuicTransport::default()),
        _ => return None,
    })
}

/// The `Host` header apart from the others; sing-box allows a list per header.
fn host_and_headers(t: &Value) -> (String, BTreeMap<String, String>) {
    let mut host = String::new();
    let mut headers = BTreeMap::new();
    for (k, v) in t
        .get("headers")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let value = match v {
            Value::Array(a) => a.first().and_then(Value::as_str).unwrap_or_default(),
            v => v.as_str().unwrap_or_default(),
        };
        if k.eq_ignore_ascii_case("host") {
            host = value.to_owned();
        } else {
            headers.insert(k.clone(), value.to_owned());
        }
    }
    (host, headers)
}

fn endpoint(address: String, port: u16) -> Option<Endpoint> {
    (!address.is_empty()).then_some(Endpoint { address, port })
}

fn port_of(o: &Value, key: &str) -> Option<u16> {
    o.get(key)?.as_u64()?.try_into().ok().filter(|p| *p != 0)
}

fn required(o: &Value, key: &str) -> Option<String> {
    Some(text(o, key)).filter(|s| !s.is_empty())
}

fn text(o: &Value, key: &str) -> String {
    match o.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn number(o: &Value, key: &str) -> i64 {
    match o.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn flag(o: &Value, key: &str) -> bool {
    o.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A field sing-box accepts as one string or a list of them.
fn strings(o: &Value, key: &str) -> Vec<String> {
    match o.get(key) {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// A sing-box duration (`30s`, `1m`) as the whole seconds Kasumi stores.
fn seconds(d: &str) -> String {
    let d = d.trim();
    let (num, unit) = d.split_at(d.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(d.len()));
    let Ok(n) = num.parse::<f64>() else {
        return String::new();
    };
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        _ => return String::new(),
    };
    (secs.round() as i64).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::parse_share_link;
    use crate::sub_ingest::tests::http_fixture;
    use serde_json::json;

    fn fixture_json(name: &str) -> Value {
        let (_, body) = http_fixture(name);
        serde_json::from_slice(&body).unwrap()
    }

    /// `link`'s profile with `p`'s generated id.
    fn link_profile(link: &str, p: &Profile) -> Profile {
        let mut l = parse_share_link(link, None).unwrap_or_else(|| panic!("{link}"));
        l.meta_mut().id.clone_from(&p.meta().id);
        l
    }

    #[test]
    fn singbox_matches_share_links_for_same_nodes() {
        let decomposed = import_singbox(&fixture_json("07-sing-box")).profiles;
        let (headers, body) = http_fixture("01-happ-full");
        let links = crate::sub_ingest::ingest(&crate::sub_ingest::IngestInput {
            url: "https://sub.example.org/s",
            headers: &headers,
            body: &body,
            stored: None,
            merge: happ_sub::MergeMode::Full,
            allow_provider_configs: false,
            title: "",
        })
        .unwrap()
        .profiles;
        let mut matched = 0;
        for p in &decomposed {
            let same_node =
                |l: &&Profile| l.meta().remarks == p.meta().remarks && l.endpoint() == p.endpoint();
            let Some(l) = links.iter().find(same_node) else {
                panic!("no link for {}", p.meta().remarks);
            };
            let mut l = l.clone();
            l.meta_mut().id.clone_from(&p.meta().id);
            // The provider draws a REALITY sni and sid from a pool on every request.
            if let (Some(lt), Some(pt)) = (l.tls_mut(), p.tls())
                && lt.security == Security::Reality
            {
                lt.sni.clone_from(&pt.sni);
                lt.short_id.clone_from(&pt.short_id);
            }
            assert_eq!(&l, p);
            matched += 1;
        }
        assert_eq!(matched, 29);
    }

    const UUID: &str = "11111111-1111-1111-1111-111111111111";

    fn vmess_link(fields: Value) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(fields.to_string());
        format!("vmess://{b64}")
    }

    #[test]
    fn each_type_equals_its_share_link() {
        let cases = [
            (
                json!({ "type": "vmess", "tag": "VM", "server": "vm.example", "server_port": 443,
                    "uuid": UUID, "security": "auto", "alter_id": 0,
                    "transport": { "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example" },
                        "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol" },
                    "tls": { "enabled": true, "server_name": "cdn.example",
                        "utls": { "enabled": true, "fingerprint": "chrome" } } }),
                vmess_link(json!({ "v": "2", "ps": "VM", "add": "vm.example", "port": "443",
                    "id": UUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
                    "host": "cdn.example", "path": "/ws?ed=2048", "tls": "tls",
                    "sni": "cdn.example", "fp": "chrome" })),
            ),
            (
                json!({ "type": "trojan", "tag": "TR", "server": "tr.example", "server_port": 443,
                    "password": "pw", "transport": { "type": "grpc", "service_name": "svc" },
                    "tls": { "enabled": true, "server_name": "tr.example", "alpn": "h2",
                        "utls": { "enabled": true, "fingerprint": "firefox" } } }),
                "trojan://pw@tr.example:443?security=tls&sni=tr.example&alpn=h2&type=grpc&serviceName=svc&fp=firefox#TR".into(),
            ),
            (
                json!({ "type": "vless", "tag": "VL", "server": "vl.example", "server_port": 8443,
                    "uuid": UUID, "transport": { "type": "httpupgrade", "host": "up.example", "path": "/up" } }),
                format!("vless://{UUID}@vl.example:8443?type=httpupgrade&host=up.example&path=%2Fup#VL"),
            ),
            (
                json!({ "type": "shadowsocks", "tag": "SS", "server": "ss.example", "server_port": 8388,
                    "method": "aes-256-gcm", "password": "pw",
                    "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=cdn.example" }),
                "ss://YWVzLTI1Ni1nY206cHc=@ss.example:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example#SS".into(),
            ),
            (
                json!({ "type": "hysteria2", "tag": "HY", "server": "hy.example", "server_port": 443,
                    "server_ports": ["20000:30000"], "password": "pw",
                    "obfs": { "type": "salamander", "password": "op" },
                    "tls": { "enabled": true, "server_name": "hy.example", "alpn": ["h3"] } }),
                "hysteria2://pw@hy.example:443?sni=hy.example&alpn=h3&obfs=salamander&obfs-password=op&mport=20000-30000#HY".into(),
            ),
            (
                json!({ "type": "tuic", "tag": "TU", "server": "tu.example", "server_port": 443,
                    "uuid": UUID, "password": "pw", "congestion_control": "cubic",
                    "udp_relay_mode": "native", "zero_rtt_handshake": true,
                    "tls": { "enabled": true, "server_name": "tu.example", "alpn": ["h3"] } }),
                format!("tuic://{UUID}:pw@tu.example:443?sni=tu.example&alpn=h3&congestion_control=cubic&udp_relay_mode=native&zero_rtt_handshake=1#TU"),
            ),
            (
                json!({ "type": "anytls", "tag": "AT", "server": "at.example", "server_port": 443,
                    "password": "pw", "tls": { "enabled": true, "server_name": "at.example",
                        "utls": { "enabled": true, "fingerprint": "chrome" } } }),
                "anytls://pw@at.example:443?sni=at.example&fp=chrome#AT".into(),
            ),
            (
                json!({ "type": "naive", "tag": "NV", "server": "nv.example", "server_port": 443,
                    "username": "user", "password": "pw", "quic": true,
                    "tls": { "enabled": true, "server_name": "nv.example" } }),
                "naive+quic://user:pw@nv.example:443?sni=nv.example#NV".into(),
            ),
            (
                json!({ "type": "shadowtls", "tag": "ST", "server": "st.example", "server_port": 443,
                    "version": 3, "password": "pw", "tls": { "enabled": true,
                        "server_name": "st.example", "utls": { "enabled": true, "fingerprint": "chrome" } } }),
                "shadowtls://pw@st.example:443?sni=st.example&version=3&fp=chrome#ST".into(),
            ),
            (
                json!({ "type": "wireguard", "tag": "WG", "mtu": 1280,
                    "address": ["172.16.0.2/32", "fd00::2/128"], "private_key": "privkey",
                    "peers": [{ "address": "wg.example", "port": 51820, "public_key": "pubkey",
                        "allowed_ips": ["0.0.0.0/0"], "reserved": [1, 2, 3] }] }),
                "wireguard://privkey@wg.example:51820?publickey=pubkey&address=172.16.0.2%2F32%2Cfd00%3A%3A2%2F128&reserved=1,2,3&mtu=1280#WG".into(),
            ),
        ];
        for (outbound, link) in cases {
            let key = if outbound["type"] == "wireguard" {
                "endpoints"
            } else {
                "outbounds"
            };
            let imported = import_singbox(&json!({ key: [outbound] }));
            assert_eq!(imported.skipped, 0, "{link}");
            let p = &imported.profiles[0];
            assert_eq!(*p, link_profile(&link, p), "{link}");
        }
    }

    #[test]
    fn multiplex_and_detour_become_mux_and_a_chain() {
        let imported = import_singbox(&json!({ "outbounds": [
            { "type": "vless", "tag": "exit", "server": "exit.example", "server_port": 443,
              "uuid": UUID, "detour": "entry", "multiplex": { "enabled": true, "protocol": "h2mux" } },
            { "type": "trojan", "tag": "entry", "server": "entry.example", "server_port": 443,
              "password": "pw", "tls": { "enabled": true }, "detour": "direct" },
            { "type": "direct", "tag": "direct" },
        ]}));
        let [exit, entry] = &imported.profiles[..] else {
            panic!("{:?}", imported.profiles);
        };
        assert!(matches!(exit, Profile::Vless(v) if v.mux_enabled));
        assert_eq!(exit.meta().via.as_deref(), Some(entry.meta().id.as_str()));
        assert_eq!(entry.meta().via, None);
    }

    #[test]
    fn only_servers_kasumi_cannot_import_are_counted() {
        let imported = import_singbox(&json!({
            "inbounds": [{ "type": "mixed", "listen": "0.0.0.0", "listen_port": 1080 }],
            "route": { "final": "direct" },
            "dns": { "servers": [] },
            "log": { "output": "/data/adb/kasumi-proxy/x.log" },
            "experimental": { "clash_api": { "external_controller": "0.0.0.0:9090" } },
            "outbounds": [
                { "type": "selector", "tag": "select", "outbounds": ["ok"] },
                { "type": "urltest", "tag": "auto", "outbounds": ["ok"] },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" },
                { "type": "dns", "tag": "dns" },
                { "type": "ssh", "tag": "ssh", "server": "ssh.example", "server_port": 22 },
                // A server with a transport Kasumi has no field for, and one without its id.
                { "type": "vless", "tag": "odd", "server": "o.example", "server_port": 443,
                  "uuid": UUID, "transport": { "type": "xhttp" } },
                { "type": "vless", "tag": "no-id", "server": "n.example", "server_port": 443 },
                { "type": "vless", "tag": "ok", "server": "ok.example", "server_port": 443, "uuid": UUID },
            ],
            "endpoints": [{ "type": "tailscale", "tag": "ts" }],
        }));
        assert_eq!(imported.profiles.len(), 1);
        assert_eq!(imported.profiles[0].meta().remarks, "ok");
        // ssh, the xhttp server, the one without its id, and tailscale.
        assert_eq!(imported.skipped, 4);
    }

    #[test]
    fn durations_become_seconds() {
        assert_eq!(seconds("30s"), "30");
        assert_eq!(seconds("1m"), "60");
        assert_eq!(seconds(""), "");
        assert_eq!(seconds("10ms"), "");
    }

    #[test]
    fn shadowsocks_outbound_gets_tls_only_from_v2ray_plugin_opts() {
        let import = |outbound: Value| {
            let imported = import_singbox(&json!({ "outbounds": [outbound] }));
            match &imported.profiles[..] {
                [Profile::Shadowsocks(ss)] => ss.clone(),
                other => panic!("{other:?}"),
            }
        };
        let plain = import(
            json!({ "type": "shadowsocks", "tag": "SS", "server": "ss.example",
            "server_port": 8388, "method": "aes-256-gcm", "password": "pw" }),
        );
        assert_eq!(plain.tls.security, Security::None);
        let link = Profile::Shadowsocks(plain.clone());
        assert_eq!(
            link,
            link_profile("ss://YWVzLTI1Ni1nY206cHc=@ss.example:8388#SS", &link)
        );

        let ws_tls = import(
            json!({ "type": "shadowsocks", "tag": "SS", "server": "ss.example",
            "server_port": 8388, "method": "aes-256-gcm", "password": "pw",
            "plugin": "v2ray-plugin", "plugin_opts": "mode=websocket;host=cdn.example;path=/ws;tls" }),
        );
        assert_eq!(ws_tls.tls.security, Security::Tls);
        assert_eq!(ws_tls.tls.sni, "cdn.example");

        let ws = import(
            json!({ "type": "shadowsocks", "tag": "SS", "server": "ss.example",
            "server_port": 8388, "method": "aes-256-gcm", "password": "pw",
            "plugin": "v2ray-plugin", "plugin_opts": "mode=websocket;host=cdn.example;path=/ws" }),
        );
        assert_eq!(ws.tls.security, Security::None);
    }
}
