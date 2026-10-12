//! Subscription response ingest: the Happ envelope (meta, body decryption, body
//! form) is decoded by `happ-sub`, and the links it yields go through the share
//! parser. Pure: the backend fetches and persists.

use std::collections::HashSet;

use happ_sub::{
    BodyEncryption, Error as EnvelopeError, MergeMode, MetaMap, Payload, RoutingAction,
};
use serde::{Deserialize, Serialize};

use crate::profile::Profile;
use crate::share::{parse_share_link, parse_share_links};

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
}

pub struct IngestInput<'a> {
    /// `Subscription.url` verbatim, fragment included.
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// Already filtered by [`stored_for_url`].
    pub stored: Option<&'a StoredSubMeta>,
    pub merge: MergeMode,
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
}

/// Something skipped while ingesting; the rest of the body was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubWarning {
    UnsupportedLinks { count: usize },
    SkippedLines { count: usize, sample: String },
    InvalidRouting { message: String },
    InvalidFragment { segment: String },
    LegacyParser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentHint {
    Yaml,
    Html,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    XrayJson,
    JsonArray,
    SingBoxJson,
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
                write!(f, "{what} subscriptions are not supported yet")
            }
            IngestError::NoProfiles => write!(f, "no profiles in subscription body"),
            IngestError::Limit(m) => write!(f, "subscription too large: {m}"),
            IngestError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for IngestError {}

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
    }
}

pub fn ingest(input: &IngestInput) -> Result<Ingested, IngestError> {
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

    let links = match parsed.payload {
        Payload::Links(links) => links,
        Payload::XrayJson(_) => return Err(IngestError::UnsupportedPayload(PayloadKind::XrayJson)),
        Payload::JsonArray(_) => {
            return Err(IngestError::UnsupportedPayload(PayloadKind::JsonArray));
        }
        Payload::SingBoxJson(_) => {
            return Err(IngestError::UnsupportedPayload(PayloadKind::SingBoxJson));
        }
    };

    let mut seen = HashSet::new();
    let mut unsupported = 0;
    let mut profiles = Vec::new();
    for link in links.iter().filter(|l| seen.insert(l.as_str())) {
        match parse_share_link(link, None).filter(|_| !is_web_page_link(link)) {
            Some(p) => profiles.push(p),
            None => unsupported += 1,
        }
    }
    if profiles.is_empty() {
        if parsed.body_encryption == BodyEncryption::None
            && let Some(ing) = legacy_fallback(input, parsed.meta, parsed.routing, encrypted)
        {
            return Ok(ing);
        }
        return Err(IngestError::NoProfiles);
    }
    if unsupported > 0 {
        warnings.push(SubWarning::UnsupportedLinks { count: unsupported });
    }

    Ok(Ingested {
        profiles,
        meta: parsed.meta,
        routing: parsed.routing,
        encrypted,
        warnings,
        used_legacy_parser: false,
    })
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
    })
}

fn content_hint(input: &IngestInput) -> ContentHint {
    let content_type = input
        .headers
        .iter()
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
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
    let mut skipped = 0;
    let mut sample = None;
    for w in warnings {
        match w {
            happ_sub::Warning::SkippedLine(line) => {
                skipped += 1;
                sample.get_or_insert_with(|| line.chars().take(SAMPLE_CHARS).collect());
            }
            happ_sub::Warning::InvalidRouting(message) => out.push(SubWarning::InvalidRouting {
                message: message.clone(),
            }),
            happ_sub::Warning::InvalidFragment(segment) => out.push(SubWarning::InvalidFragment {
                segment: segment.clone(),
            }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use happ_sub::body_crypt::encrypt_with_table;
    use happ_sub::keys::DEFAULT_TABLE;

    const URL: &str = "https://sub.example.org/s/abc";

    /// A captured response: headers up to the first blank line, then the body.
    fn http_fixture(name: &str) -> (Vec<(String, String)>, Vec<u8>) {
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
    fn sing_box_json_is_unsupported_payload() {
        let (headers, body) = http_fixture("07-sing-box");
        let err = ingest(&input(URL, &headers, &body)).unwrap_err();
        assert_eq!(
            err,
            IngestError::UnsupportedPayload(PayloadKind::SingBoxJson)
        );
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
            meta: MetaMap::new(),
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
}
