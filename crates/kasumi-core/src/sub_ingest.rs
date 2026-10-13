//! Subscription response ingest: the Happ envelope (meta, body decryption, body
//! form) is decoded by `happ-sub`; the links it yields go through the share parser,
//! full Xray configs through the sanitiser and sing-box configs through
//! [`crate::singbox_import`]. Pure: the backend fetches and persists.

use std::collections::HashSet;

use happ_sub::meta::{normalize_untrusted_text, single_line};
use happ_sub::{
    BodyEncryption, Error as EnvelopeError, MergeMode, MetaMap, Payload, RoutingAction,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::custom_sanitize::sanitize_provider_xray;
use crate::profile::{Custom, CustomOrigin, Profile};
use crate::share::{meta as share_meta, parse_share_link, parse_share_links};
use crate::singbox_import::{SingboxImport, import_singbox};
use crate::sub_changes::host_of;
pub use crate::sub_meta_types::{ContentHint, PayloadKind, SubErrorKind, SubWarning};

/// Merge state a subscription carries between fetches. Persisted by the backend in
/// `sub-meta.json`, never in `AppState`: it is the raw provider map.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StoredSubMeta {
    /// `Subscription.url` as of the last successful ingest. A different URL means a
    /// re-import: the fragment is read again and nothing is merged.
    pub source_url: String,
    /// Happ keeps a subscription "encrypted" once a body decrypted, so a later tagged
    /// response is decrypted even without `?key=`.
    pub encrypted: bool,
    pub meta: MetaMap,
    /// The raw `Content-Disposition` header, a title source when `profile-title` is
    /// absent. Kept apart from `meta`: it is not a Happ key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_disposition: Option<String>,
}

pub struct IngestInput<'a> {
    /// `Subscription.url` verbatim, fragment included.
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// Already filtered by [`stored_for_url`].
    pub stored: Option<&'a StoredSubMeta>,
    pub merge: MergeMode,
    /// `Subscription.allow_provider_configs`: full Xray configs are imported only
    /// after the user agreed.
    pub allow_provider_configs: bool,
    /// The subscription's name, which numbered configs without `remarks` take.
    pub title: &'a str,
}

#[derive(Debug)]
pub struct Ingested {
    /// Not yet stamped with the subscription and group.
    pub profiles: Vec<Profile>,
    pub meta: MetaMap,
    pub routing: Vec<RoutingAction>,
    pub encrypted: bool,
    pub warnings: Vec<SubWarning>,
    pub used_legacy_parser: bool,
    pub content_disposition: Option<String>,
}

/// Why a response yields no profiles. Every case keeps the previous profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// The body was signalled as encrypted and did not decrypt. Happ would wipe the
    /// server list here.
    Decrypt {
        key_id: Option<String>,
    },
    EmptyBody,
    UnknownContent {
        hint: ContentHint,
    },
    UnsupportedPayload(PayloadKind),
    NoProfiles,
    Limit(String),
    /// A malformed envelope: invalid JSON configuration, routing or deeplink.
    Invalid(String),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Decrypt { key_id: Some(id) } => {
                write!(f, "subscription body could not be decrypted with {id}")
            }
            IngestError::Decrypt { key_id: None } => {
                write!(f, "subscription body could not be decrypted")
            }
            IngestError::EmptyBody => write!(f, "subscription body is empty"),
            IngestError::UnknownContent { hint } => match hint {
                ContentHint::Yaml => write!(f, "Clash YAML subscriptions are not supported"),
                ContentHint::Html => write!(f, "the subscription URL returned a web page"),
                ContentHint::Unknown => write!(f, "unknown subscription format"),
            },
            IngestError::UnsupportedPayload(kind) => {
                let what = match kind {
                    PayloadKind::XrayJson => "Xray JSON",
                    PayloadKind::JsonArray => "JSON array",
                    PayloadKind::SingBoxJson => "sing-box JSON",
                };
                write!(f, "{what} configs are not allowed for this subscription")
            }
            IngestError::NoProfiles => write!(f, "no profiles in subscription body"),
            IngestError::Limit(m) => write!(f, "subscription too large: {m}"),
            IngestError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for IngestError {}

impl IngestError {
    pub fn kind(&self) -> SubErrorKind {
        match self {
            IngestError::Decrypt { key_id } => SubErrorKind::Decrypt {
                key_id: key_id.clone(),
            },
            IngestError::EmptyBody => SubErrorKind::EmptyBody,
            IngestError::UnknownContent { hint } => SubErrorKind::UnknownContent { hint: *hint },
            IngestError::UnsupportedPayload(payload) => {
                SubErrorKind::UnsupportedPayload { payload: *payload }
            }
            IngestError::NoProfiles => SubErrorKind::NoProfiles,
            IngestError::Limit(_) => SubErrorKind::Limit,
            IngestError::Invalid(_) => SubErrorKind::Invalid,
        }
    }
}

/// The one place to tune the envelope bounds.
pub fn limits() -> happ_sub::Limits {
    happ_sub::Limits::default()
}

/// `stored` only when its `source_url` equals `url`; otherwise this fetch is an import.
pub fn stored_for_url<'a>(
    stored: Option<&'a StoredSubMeta>,
    url: &str,
) -> Option<&'a StoredSubMeta> {
    stored.filter(|s| s.source_url == url)
}

pub fn record_after(url: &str, ing: &Ingested) -> StoredSubMeta {
    StoredSubMeta {
        source_url: url.to_owned(),
        encrypted: ing.encrypted,
        meta: ing.meta.clone(),
        content_disposition: ing.content_disposition.clone(),
    }
}

pub fn ingest(input: &IngestInput) -> Result<Ingested, IngestError> {
    let mut ing = ingest_body(input)?;
    ing.content_disposition = header(input.headers, "content-disposition")
        .map(str::to_owned)
        .or_else(|| {
            // A background update keeps what a response omits, as it does meta keys.
            let partial = input.merge == MergeMode::Partial;
            input
                .stored
                .filter(|_| partial)
                .and_then(|s| s.content_disposition.clone())
        });
    Ok(ing)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn ingest_body(input: &IngestInput) -> Result<Ingested, IngestError> {
    let stored_encrypted = input.stored.is_some_and(|s| s.encrypted);
    let parsed = happ_sub::parse(&happ_sub::Input {
        url: input.url,
        headers: input.headers,
        body: input.body,
        stored: input.stored.map(|s| happ_sub::StoredState {
            encrypted: s.encrypted,
            meta: Some(&s.meta),
            merge: input.merge,
        }),
        limits: Some(limits()),
    });

    let parsed = match parsed {
        Ok(p) => p,
        Err(EnvelopeError::Decrypt { key_id, .. }) => return Err(IngestError::Decrypt { key_id }),
        Err(EnvelopeError::EmptyBody) => return Err(IngestError::EmptyBody),
        Err(EnvelopeError::LimitExceeded(m)) => return Err(IngestError::Limit(m)),
        Err(EnvelopeError::UnknownContentType | EnvelopeError::Utf8(_)) => {
            // An encrypted body that could not be read is not plain text to scan.
            if !decrypt_signalled(input, stored_encrypted) {
                let meta = legacy_meta(input)?;
                if let Some(ing) = legacy_fallback(input, meta, Vec::new(), stored_encrypted) {
                    return Ok(ing);
                }
            }
            return Err(IngestError::UnknownContent {
                hint: content_hint(input),
            });
        }
        Err(e) => return Err(IngestError::Invalid(e.to_string())),
    };

    let decrypted = matches!(parsed.body_encryption, BodyEncryption::Decrypted { .. });
    let encrypted = decrypted || stored_encrypted;
    let mut warnings = map_warnings(&parsed.warnings);

    let profiles = match parsed.payload {
        Payload::Links(links) => {
            let mut seen = HashSet::new();
            let mut unsupported = 0u32;
            let mut profiles = Vec::new();
            for link in links.iter().filter(|l| seen.insert(l.as_str())) {
                match parse_share_link(link, None).filter(|_| !is_web_page_link(link)) {
                    Some(p) => profiles.push(p),
                    None => unsupported += 1,
                }
            }
            if profiles.is_empty() {
                if parsed.body_encryption == BodyEncryption::None
                    && let Some(ing) =
                        legacy_fallback(input, parsed.meta, parsed.routing, encrypted)
                {
                    return Ok(ing);
                }
                return Err(IngestError::NoProfiles);
            }
            if unsupported > 0 {
                warnings.push(SubWarning::UnsupportedLinks { count: unsupported });
            }
            profiles
        }
        Payload::XrayJson(v) => {
            let kind = PayloadKind::XrayJson;
            xray_configs(input, &parsed.meta, &[v], kind, &mut warnings)?
        }
        Payload::JsonArray(a) => {
            let kind = PayloadKind::JsonArray;
            xray_configs(input, &parsed.meta, &a, kind, &mut warnings)?
        }
        Payload::SingBoxJson(v) => {
            let SingboxImport { profiles, skipped } = import_singbox(&v);
            if skipped > 0 {
                warnings.push(SubWarning::SkippedOutbounds { count: skipped });
            }
            if profiles.is_empty() {
                return Err(IngestError::NoProfiles);
            }
            profiles
        }
    };

    Ok(Ingested {
        profiles,
        meta: parsed.meta,
        routing: parsed.routing,
        encrypted,
        warnings,
        used_legacy_parser: false,
        content_disposition: None,
    })
}

/// Longest name a provider config gets from its `remarks`.
const CONFIG_NAME_MAX: usize = 128;

/// Each full Xray config, reduced by the sanitiser, as a provider Custom profile.
/// Configs the sanitiser refuses are counted, not imported.
fn xray_configs(
    input: &IngestInput,
    meta: &MetaMap,
    configs: &[Value],
    kind: PayloadKind,
    warnings: &mut Vec<SubWarning>,
) -> Result<Vec<Profile>, IngestError> {
    if !input.allow_provider_configs {
        return Err(IngestError::UnsupportedPayload(kind));
    }
    let title = [input.title, meta.profile_title().unwrap_or_default()]
        .into_iter()
        .map(|t| single_line(&normalize_untrusted_text(t)))
        .find(|t| !t.is_empty())
        .unwrap_or_else(|| host_of(input.url));
    let mut rejected = 0u32;
    let mut profiles = Vec::new();
    for (i, config) in configs.iter().enumerate() {
        let Ok(s) = sanitize_provider_xray(config) else {
            rejected += 1;
            continue;
        };
        let remarks = s
            .remarks
            .as_deref()
            .map(|r| {
                single_line(&normalize_untrusted_text(r))
                    .chars()
                    .take(CONFIG_NAME_MAX)
                    .collect::<String>()
            })
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| format!("{title} #{}", i + 1));
        let mut raw = Map::new();
        raw.insert("outbounds".into(), s.outbounds.into());
        if let Some(routing) = s.routing {
            raw.insert("routing".into(), routing);
        }
        profiles.push(Profile::Custom(Custom {
            meta: share_meta(remarks, None),
            raw: Value::Object(raw).to_string(),
            origin: CustomOrigin::Provider,
        }));
    }
    if rejected > 0 {
        warnings.push(SubWarning::RejectedConfigs { count: rejected });
    }
    if profiles.is_empty() {
        return Err(IngestError::NoProfiles);
    }
    Ok(profiles)
}

/// Happ tries to decrypt when `Encrypt-Tag` is set and the URL has `?key=` or the
/// subscription is stored as encrypted.
fn decrypt_signalled(input: &IngestInput, stored_encrypted: bool) -> bool {
    let tagged = input
        .headers
        .iter()
        .any(|(k, v)| k.trim().eq_ignore_ascii_case("encrypt-tag") && !v.trim().is_empty());
    let has_key = happ_sub::meta::fetch_url(input.url)
        .split_once('?')
        .is_some_and(|(_, q)| {
            q.split('&')
                .filter_map(|p| p.split_once('='))
                .any(|(k, v)| k.eq_ignore_ascii_case("key") && !v.is_empty())
        });
    tagged && (has_key || stored_encrypted)
}

/// A bare web address in a link list is a provider page, not an HTTP proxy; the
/// share-link extractor likewise takes http(s) only with credentials.
fn is_web_page_link(link: &str) -> bool {
    let Some(rest) = link
        .strip_prefix("http://")
        .or_else(|| link.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.contains('@')
}

/// Meta for a body the envelope parser rejected: headers (and, on import, the URL
/// fragment) merged the way `happ_sub::parse` would.
fn legacy_meta(input: &IngestInput) -> Result<MetaMap, IngestError> {
    let limits = limits();
    let envelope = |e: EnvelopeError| match e {
        EnvelopeError::LimitExceeded(m) => IngestError::Limit(m),
        e => IngestError::Invalid(e.to_string()),
    };
    let headers = happ_sub::meta::parse_headers(input.headers, &limits).map_err(envelope)?;
    Ok(match input.stored {
        Some(s) => happ_sub::meta::refresh_merge(&s.meta, &headers, input.merge),
        None => {
            let fragment = happ_sub::meta::parse_fragment(input.url, &limits).unwrap_or_default();
            happ_sub::meta::refresh_merge(&fragment, &headers, MergeMode::Partial)
        }
    })
}

/// The share-link extractor over the raw body, which tolerates bodies the envelope
/// parser rejects (links inside prose, deeper base64 nesting).
fn legacy_fallback(
    input: &IngestInput,
    meta: MetaMap,
    routing: Vec<RoutingAction>,
    encrypted: bool,
) -> Option<Ingested> {
    let profiles = parse_share_links(&String::from_utf8_lossy(input.body), None);
    if profiles.is_empty() {
        return None;
    }
    Some(Ingested {
        profiles,
        meta,
        routing,
        encrypted,
        warnings: vec![SubWarning::LegacyParser],
        used_legacy_parser: true,
        content_disposition: None,
    })
}

fn content_hint(input: &IngestInput) -> ContentHint {
    let content_type = header(input.headers, "content-type")
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&input.body[..input.body.len().min(64)]);
    let body = body.trim_start();
    if content_type.contains("yaml")
        || body.starts_with("proxies:")
        || body.starts_with("mixed-port:")
    {
        ContentHint::Yaml
    } else if content_type.contains("text/html") {
        ContentHint::Html
    } else {
        ContentHint::Unknown
    }
}

const SAMPLE_CHARS: usize = 80;

fn map_warnings(warnings: &[happ_sub::Warning]) -> Vec<SubWarning> {
    let mut out = Vec::new();
    let mut skipped = 0u32;
    let mut sample = None;
    for w in warnings {
        match w {
            happ_sub::Warning::SkippedLine(line) => {
                skipped += 1;
                // Shown to the user, so it gets the same cleaning as provider text.
                sample.get_or_insert_with(|| {
                    single_line(&normalize_untrusted_text(line))
                        .chars()
                        .take(SAMPLE_CHARS)
                        .collect()
                });
            }
            happ_sub::Warning::InvalidRouting(message) => out.push(SubWarning::InvalidRouting {
                message: message.clone(),
            }),
            happ_sub::Warning::InvalidFragment(_) => out.push(SubWarning::InvalidFragment),
            _ => {}
        }
    }
    if let Some(sample) = sample {
        out.insert(
            0,
            SubWarning::SkippedLines {
                count: skipped,
                sample,
            },
        );
    }
    out
}

/// Drop the ingested servers this device's cores can't run, so a subscription
/// doesn't fill a group with profiles that fail to start; the warning counts them.
pub fn withhold_unavailable_profiles(
    ingested: &mut Ingested,
    unavailable: &[crate::profile::Protocol],
) {
    let before = ingested.profiles.len();
    ingested
        .profiles
        .retain(|p| !unavailable.contains(&p.protocol()));
    let count = (before - ingested.profiles.len()) as u32;
    if count > 0 {
        ingested
            .warnings
            .push(SubWarning::UnavailableProtocols { count });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use happ_sub::body_crypt::encrypt_with_table;
    use happ_sub::keys::DEFAULT_TABLE;

    const URL: &str = "https://sub.example.org/s/abc";

    /// A captured response: headers up to the first blank line, then the body.
    pub(crate) fn http_fixture(name: &str) -> (Vec<(String, String)>, Vec<u8>) {
        let path = format!(
            "{}/tests/fixtures/happ/{name}.http",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header/body separator");
        let head = String::from_utf8(raw[..split].to_vec()).unwrap();
        let headers = head
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect();
        (headers, raw[split + 4..].to_vec())
    }

    fn input<'a>(url: &'a str, headers: &'a [(String, String)], body: &'a [u8]) -> IngestInput<'a> {
        IngestInput {
            url,
            headers,
            body,
            stored: None,
            merge: MergeMode::Full,
            allow_provider_configs: false,
            title: "Sub",
        }
    }

    fn count(profiles: &[Profile], protocol: &str) -> usize {
        profiles
            .iter()
            .filter(|p| serde_json::to_value(p).unwrap()["protocol"] == protocol)
            .count()
    }

    #[test]
    fn live_happ_body_yields_33_profiles() {
        let (headers, body) = http_fixture("01-happ-full");
        let ing = ingest(&input(URL, &headers, &body)).unwrap();
        assert_eq!(ing.profiles.len(), 33);
        assert_eq!(count(&ing.profiles, "vless"), 26);
        assert_eq!(count(&ing.profiles, "hysteria2"), 4);
        assert_eq!(count(&ing.profiles, "shadowsocks"), 3);
        let v6 = ing
            .profiles
            .iter()
            .find(|p| p.endpoint().unwrap().address == "2001:db8::4")
            .expect("the bare-IPv6 node is kept");
        assert_eq!(v6.endpoint().unwrap().port, 8443);
        assert_eq!(ing.meta.profile_title(), Some("Example VPN 🗽"));
        assert_eq!(ing.routing.len(), 1);
        assert!(!ing.encrypted && !ing.used_legacy_parser);
        assert!(ing.warnings.is_empty(), "{:?}", ing.warnings);
    }

    #[test]
    fn withholds_servers_the_device_cannot_run() {
        use crate::profile::Protocol;
        let body = b"vless://a@h.example:1#a\nnaive+https://u:p@n.example:443#n\n";
        let mut ing = ingest(&input(URL, &[], body)).unwrap();
        assert_eq!(ing.profiles.len(), 2);
        withhold_unavailable_profiles(&mut ing, &[Protocol::Naive]);
        assert_eq!(ing.profiles.len(), 1);
        assert_eq!(ing.profiles[0].protocol(), Protocol::Vless);
        assert_eq!(
            ing.warnings,
            [SubWarning::UnavailableProtocols { count: 1 }]
        );

        // Nothing unavailable: nothing dropped, no warning.
        let mut ing = ingest(&input(URL, &[], body)).unwrap();
        withhold_unavailable_profiles(&mut ing, &[]);
        assert_eq!(ing.profiles.len(), 2);
        assert_eq!(ing.warnings, []);
    }

    #[test]
    fn directive_lines_are_not_links() {
        let body = b"#profile-title: X\nvless://a@h.example:1#a\ntrojan://p@h.example:2#b\n";
        let ing = ingest(&input(URL, &[], body)).unwrap();
        assert_eq!(ing.profiles.len(), 2);
        assert_eq!(ing.meta.profile_title(), Some("X"));
    }

    #[test]
    fn duplicate_links_and_web_pages_are_not_profiles() {
        let body = b"vless://a@h.example:1#a\nvless://a@h.example:1#a\nhttps://t.me/provider\n";
        let ing = ingest(&input(URL, &[], body)).unwrap();
        assert_eq!(ing.profiles.len(), 1);
        assert_eq!(ing.warnings, [SubWarning::UnsupportedLinks { count: 1 }]);
    }

    #[test]
    fn clash_yaml_is_unknown_content_with_yaml_hint() {
        let (headers, body) = http_fixture("05-clash-verge");
        let err = ingest(&input(URL, &headers, &body)).unwrap_err();
        assert_eq!(
            err,
            IngestError::UnknownContent {
                hint: ContentHint::Yaml
            }
        );
    }

    #[test]
    fn singbox_fixture_decomposes_to_29_profiles() {
        // No consent needed: the result is typed profiles, not the provider's JSON.
        let (headers, body) = http_fixture("07-sing-box");
        let ing = ingest(&input(URL, &headers, &body)).unwrap();
        assert_eq!(ing.profiles.len(), 29);
        assert_eq!(count(&ing.profiles, "vless"), 25);
        assert_eq!(count(&ing.profiles, "hysteria2"), 4);
        // Its selector, urltest group and `direct` are no reason to warn.
        assert!(ing.warnings.is_empty(), "{:?}", ing.warnings);
        assert_eq!(ing.meta.profile_title(), Some("Example VPN 🗽"));
    }

    #[test]
    fn singbox_server_of_an_unknown_type_is_a_warning() {
        let body = serde_json::json!({ "outbounds": [
            { "type": "selector", "tag": "proxy", "outbounds": ["ok", "new"] },
            { "type": "vless", "tag": "ok", "server": "ok.example", "server_port": 443,
              "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811" },
            { "type": "brand-new", "tag": "new", "server": "new.example", "server_port": 443 },
            { "type": "direct", "tag": "direct" },
        ]});
        let body = serde_json::to_vec(&body).unwrap();
        let ing = ingest(&input(URL, &[], &body)).unwrap();
        assert_eq!(ing.profiles.len(), 1);
        assert_eq!(ing.warnings, [SubWarning::SkippedOutbounds { count: 1 }]);
    }

    fn encrypted(key_id: &str, plaintext: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
        let (body, tag) = encrypt_with_table(DEFAULT_TABLE, key_id, plaintext).unwrap();
        (vec![("Encrypt-Tag".into(), tag)], body.into_bytes())
    }

    #[test]
    fn encrypted_body_decrypts() {
        let (headers, body) = encrypted(
            "key02",
            b"#profile-title: Secret\nvless://a@h.example:1#x\n",
        );
        let url = "https://sub.example.org/s/abc?key=key02";
        let ing = ingest(&input(url, &headers, &body)).unwrap();
        assert_eq!(ing.profiles.len(), 1);
        assert_eq!(ing.meta.profile_title(), Some("Secret"));
        assert!(ing.encrypted);
        assert!(record_after(url, &ing).encrypted);
    }

    #[test]
    fn failed_decrypt_is_error_not_fallback() {
        let (headers, body) = encrypted("key02", b"vless://a@h.example:1#x\n");
        let url = "https://sub.example.org/s/abc?key=key03";
        assert_eq!(
            ingest(&input(url, &headers, &body)).unwrap_err(),
            IngestError::Decrypt {
                key_id: Some("key03".into())
            }
        );

        // A plaintext body that still carries a tag, on a subscription stored as
        // encrypted: Happ would import nothing, so the old profiles must stay.
        let headers = [(
            "Encrypt-Tag".to_owned(),
            "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
        )];
        let body = b"vless://a@h.example:1#x\n";
        let stored = StoredSubMeta {
            source_url: URL.into(),
            encrypted: true,
            ..Default::default()
        };
        let err = ingest(&IngestInput {
            stored: Some(&stored),
            ..input(URL, &headers, body)
        })
        .unwrap_err();
        assert_eq!(err, IngestError::Decrypt { key_id: None });
    }

    #[test]
    fn legacy_fallback_finds_links_in_prose() {
        let headers = [("profile-title".to_owned(), "T".to_owned())];
        let body = b"Nodes: vless://u@h.example:443?type=tcp#A and that is all";
        let ing = ingest(&input(URL, &headers, body)).unwrap();
        assert_eq!(ing.profiles.len(), 1);
        assert!(ing.used_legacy_parser);
        assert_eq!(ing.warnings, [SubWarning::LegacyParser]);
        assert_eq!(ing.meta.profile_title(), Some("T"));
    }

    #[test]
    fn fragment_meta_read_on_import_not_on_refresh() {
        let url = "https://sub.example.org/s/abc#Name?profile-title=FromFragment";
        let body = b"vless://a@h.example:1#x\n";
        let imported = ingest(&input(url, &[], body)).unwrap();
        assert_eq!(imported.meta.profile_title(), Some("FromFragment"));

        let stored = StoredSubMeta {
            source_url: url.into(),
            ..Default::default()
        };
        let refreshed = ingest(&IngestInput {
            stored: stored_for_url(Some(&stored), url),
            ..input(url, &[], body)
        })
        .unwrap();
        assert_eq!(refreshed.meta.profile_title(), None);
    }

    #[test]
    fn url_change_is_reimport() {
        let old_url = "https://sub.example.org/s/abc#Old?profile-title=Old";
        let new_url = "https://sub.example.org/s/abc#New?profile-title=New";
        let body = b"vless://a@h.example:1#x\n";
        let first = ingest(&input(old_url, &[], body)).unwrap();
        let stored = record_after(old_url, &first);

        assert!(stored_for_url(Some(&stored), old_url).is_some());
        let stored = stored_for_url(Some(&stored), new_url);
        assert!(stored.is_none());
        let again = ingest(&IngestInput {
            stored,
            ..input(new_url, &[], body)
        })
        .unwrap();
        assert_eq!(again.meta.profile_title(), Some("New"));
    }

    #[test]
    fn content_disposition_kept_by_background_update_only() {
        let cd = "attachment; filename=\"Panel.txt\"";
        let headers = [("Content-Disposition".to_owned(), cd.to_owned())];
        let body = b"vless://a@h.example:1#x\n";
        let first = ingest(&input(URL, &headers, body)).unwrap();
        assert_eq!(first.content_disposition.as_deref(), Some(cd));
        let stored = record_after(URL, &first);

        let refresh = |merge| {
            ingest(&IngestInput {
                stored: Some(&stored),
                merge,
                ..input(URL, &[], body)
            })
            .unwrap()
            .content_disposition
        };
        assert_eq!(refresh(MergeMode::Partial).as_deref(), Some(cd));
        assert_eq!(refresh(MergeMode::Full), None);
    }

    fn xray_config(remarks: Option<&str>, host: &str) -> serde_json::Value {
        let mut c = serde_json::json!({
            "log": { "loglevel": "debug", "access": "/data/adb/kasumi-proxy/a.log" },
            "inbounds": [{ "protocol": "socks", "listen": "0.0.0.0", "port": 1080 }],
            "outbounds": [
                { "tag": "proxy", "protocol": "trojan",
                  "settings": { "servers": [{ "address": host, "port": 443, "password": "pw" }] } },
                { "tag": "direct", "protocol": "freedom" },
            ],
            "routing": { "rules": [{ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }] },
        });
        if let Some(r) = remarks {
            c["remarks"] = r.into();
        }
        c
    }

    fn allowed<'a>(body: &'a [u8]) -> IngestInput<'a> {
        IngestInput {
            allow_provider_configs: true,
            ..input(URL, &[], body)
        }
    }

    fn custom(p: &Profile) -> &crate::profile::Custom {
        let Profile::Custom(c) = p else {
            panic!("{p:?}")
        };
        c
    }

    #[test]
    fn xray_array_imports_sanitised_customs() {
        let body = serde_json::json!([
            xray_config(Some("🇩🇪 Frankfurt\n\u{202e}fast"), "de.example"),
            xray_config(None, "nl.example"),
        ])
        .to_string();
        let ing = ingest(&allowed(body.as_bytes())).unwrap();
        assert!(ing.warnings.is_empty(), "{:?}", ing.warnings);
        let names: Vec<&str> = ing
            .profiles
            .iter()
            .map(|p| p.meta().remarks.as_str())
            .collect();
        assert_eq!(names, ["🇩🇪 Frankfurt fast", "Sub #2"]);
        for p in &ing.profiles {
            let c = custom(p);
            assert_eq!(c.origin, CustomOrigin::Provider);
            let raw: Value = serde_json::from_str(&c.raw).unwrap();
            assert_eq!(raw["outbounds"].as_array().unwrap().len(), 2);
            assert!(raw["routing"]["rules"].is_array());
            assert!(raw.get("log").is_none() && raw.get("inbounds").is_none());
            assert!(!c.raw.contains("/data/adb"));
        }
    }

    #[test]
    fn xray_object_needs_consent_first() {
        let body = xray_config(Some("A"), "a.example").to_string();
        assert_eq!(
            ingest(&input(URL, &[], body.as_bytes())).unwrap_err(),
            IngestError::UnsupportedPayload(PayloadKind::XrayJson)
        );
        let array = format!("[{body}]");
        assert_eq!(
            ingest(&input(URL, &[], array.as_bytes())).unwrap_err(),
            IngestError::UnsupportedPayload(PayloadKind::JsonArray)
        );
        let ing = ingest(&allowed(body.as_bytes())).unwrap();
        assert_eq!(ing.profiles.len(), 1);
        assert_eq!(ing.profiles[0].meta().remarks, "A");
    }

    #[test]
    fn rejected_configs_warning() {
        let only_direct = serde_json::json!({ "outbounds": [{ "protocol": "freedom" }] });
        let body = serde_json::json!([xray_config(None, "a.example"), only_direct]).to_string();
        let ing = ingest(&allowed(body.as_bytes())).unwrap();
        assert_eq!(ing.profiles.len(), 1);
        assert_eq!(ing.warnings, [SubWarning::RejectedConfigs { count: 1 }]);

        // Nothing usable: the previous profiles stay.
        let body = serde_json::json!([only_direct]).to_string();
        assert_eq!(
            ingest(&allowed(body.as_bytes())).unwrap_err(),
            IngestError::NoProfiles
        );
    }

    #[test]
    fn unnamed_configs_take_the_provider_title_then_the_host() {
        let body = format!(
            "#profile-title: Panel\n[{}]",
            xray_config(None, "a.example")
        );
        let titled = IngestInput {
            title: "",
            ..allowed(body.as_bytes())
        };
        assert_eq!(
            ingest(&titled).unwrap().profiles[0].meta().remarks,
            "Panel #1"
        );

        let body = format!("[{}]", xray_config(None, "a.example"));
        let bare = IngestInput {
            title: " ",
            ..allowed(body.as_bytes())
        };
        assert_eq!(
            ingest(&bare).unwrap().profiles[0].meta().remarks,
            "sub.example.org #1"
        );
    }

    #[test]
    fn errors_map_to_their_kind() {
        assert_eq!(
            IngestError::UnsupportedPayload(PayloadKind::XrayJson).kind(),
            SubErrorKind::UnsupportedPayload {
                payload: PayloadKind::XrayJson
            }
        );
        assert_eq!(IngestError::Limit("x".into()).kind(), SubErrorKind::Limit);
        assert_eq!(
            IngestError::Invalid("x".into()).kind(),
            SubErrorKind::Invalid
        );
    }
}
