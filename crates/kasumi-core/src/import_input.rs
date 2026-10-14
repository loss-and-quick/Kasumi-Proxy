//! What pasted or scanned text holds: subscription URLs, Happ's `happ://` links,
//! Incy's `incy://crypt1/` links or share links. Pure; every shell asks this module
//! so they agree on the grammar.

use std::borrow::Cow;

use happ_sub::RoutingAction;
use happ_sub::deeplink::{Deeplink, parse_deeplink};
use happ_sub::incy_crypt::{self, IncyCryptError};
use happ_sub::url_crypt::{UrlCryptError, builtin_keyring, decrypt_url};
use serde::{Deserialize, Serialize};

use crate::profile::Protocol;
use crate::request_identity::RequestClient;
use crate::route::RoutePackage;
use crate::share::parse_share_link;
use crate::sub_changes::{routing_import, routing_package};
use crate::sub_meta_types::RoutingImport;
use crate::sub_policy::clean_title;

/// What one token of an import is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportInput {
    /// `url` is what the subscription stores: an encrypted link stays encrypted.
    /// `name` is the provider name an `incy://` link carries.
    SubscriptionUrl {
        url: String,
        encrypted: bool,
        name: Option<String>,
    },
    Routing(Box<RoutingAction>),
    /// Anything else, for the share-link parser.
    ShareLinks,
    Unsupported {
        kind: UnsupportedInput,
    },
}

/// Why a link in an import cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum UnsupportedInput {
    /// `toggle`, `connect`, `disconnect`, `open`, `close` and their `_without_ui`
    /// forms drive Happ's own tunnel and window.
    Control,
    /// A record pushed through Happ's iCloud sync.
    SendToDevice,
    /// Switches off the routing of the subscription that sent it; a pasted one has
    /// no subscription.
    RoutingOff,
    /// No built-in key opens the encrypted link.
    UrlDecrypt,
    /// A malformed `happ://` link, or one that does not lead to an http(s) URL.
    Invalid,
    /// A share link for a protocol this device's cores can't run (see
    /// [`withhold_unavailable`]).
    UnavailableProtocol,
}

/// Classify one token (a line without spaces).
pub fn resolve_import_input(text: &str) -> ImportInput {
    let text = text.trim();
    if incy_crypt::is_incy_link(text) {
        return encrypted_subscription(text);
    }
    let link = match parse_deeplink(text) {
        Ok(link) => link,
        Err(happ_sub::Error::InvalidDeeplink(_)) => {
            return if is_subscription_url(text) {
                plain_subscription(text)
            } else {
                ImportInput::ShareLinks
            };
        }
        Err(_) => return unsupported(UnsupportedInput::Invalid),
    };
    match link {
        Deeplink::Add(inner) => resolve_add(&inner),
        Deeplink::Crypt { .. } => encrypted_subscription(text),
        Deeplink::Routing(action) => match *action {
            RoutingAction::Off => unsupported(UnsupportedInput::RoutingOff),
            action => ImportInput::Routing(Box::new(action)),
        },
        Deeplink::SendToDevice(_) => unsupported(UnsupportedInput::SendToDevice),
        Deeplink::Toggle { .. }
        | Deeplink::Connect { .. }
        | Deeplink::Disconnect { .. }
        | Deeplink::Open { .. }
        | Deeplink::Close { .. } => unsupported(UnsupportedInput::Control),
    }
}

fn unsupported(kind: UnsupportedInput) -> ImportInput {
    ImportInput::Unsupported { kind }
}

fn plain_subscription(url: &str) -> ImportInput {
    ImportInput::SubscriptionUrl {
        url: url.to_owned(),
        encrypted: false,
        name: None,
    }
}

/// An encrypted link is checked here but stored as given.
fn encrypted_subscription(link: &str) -> ImportInput {
    match decrypt(link) {
        Ok(Decrypted { name, .. }) => ImportInput::SubscriptionUrl {
            url: link.to_owned(),
            encrypted: true,
            name,
        },
        Err(_) => unsupported(UnsupportedInput::UrlDecrypt),
    }
}

/// `happ://add/<url>`: the URL may arrive percent-encoded, and may itself be encrypted.
fn resolve_add(inner: &str) -> ImportInput {
    let inner = inner.trim();
    let decoded = percent_encoding::percent_decode_str(inner).decode_utf8_lossy();
    let url = if is_subscription_url(inner) || is_encrypted_url(inner) {
        inner
    } else {
        decoded.as_ref()
    };
    if is_encrypted_url(url) {
        return resolve_import_input(url);
    }
    if is_subscription_url(url) {
        return plain_subscription(url);
    }
    unsupported(UnsupportedInput::Invalid)
}

/// A plain http(s) URL. With a user part (`http://user:pass@host`) it is an HTTP
/// proxy share link instead.
fn is_subscription_url(text: &str) -> bool {
    let lower = text.get(..8).unwrap_or(text).to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }
    url::Url::parse(text).is_ok_and(|u| u.username().is_empty() && u.password().is_none())
}

/// Whether `url` is a `happ://crypt…crypt5` or `incy://crypt1` link.
pub fn is_encrypted_url(url: &str) -> bool {
    incy_crypt::is_incy_link(url) || matches!(parse_deeplink(url), Ok(Deeplink::Crypt { .. }))
}

/// Why an encrypted link gives no subscription URL.
#[derive(Debug)]
pub enum LinkDecryptError {
    Happ(UrlCryptError),
    Incy(IncyCryptError),
    NotHttp,
}

impl std::fmt::Display for LinkDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkDecryptError::Happ(e) => e.fmt(f),
            LinkDecryptError::Incy(e) => e.fmt(f),
            LinkDecryptError::NotHttp => f.write_str("the link does not hold an http(s) URL"),
        }
    }
}

impl std::error::Error for LinkDecryptError {}

struct Decrypted {
    url: String,
    name: Option<String>,
}

fn decrypt(link: &str) -> Result<Decrypted, LinkDecryptError> {
    let (url, name) = if incy_crypt::is_incy_link(link) {
        let l = incy_crypt::decrypt_link(link, incy_crypt::builtin_key())
            .map_err(LinkDecryptError::Incy)?;
        (l.url, l.name.as_deref().and_then(clean_title))
    } else {
        let url = decrypt_url(link, builtin_keyring()).map_err(LinkDecryptError::Happ)?;
        (url, None)
    };
    let url = url.trim();
    if !is_subscription_url(url) {
        return Err(LinkDecryptError::NotHttp);
    }
    Ok(Decrypted {
        url: url.to_owned(),
        name,
    })
}

/// The URL a subscription is fetched from: an encrypted link is decrypted on every
/// fetch, so keys added to happ-sub apply without the user re-adding it.
pub fn subscription_fetch_url(url: &str) -> Result<Cow<'_, str>, LinkDecryptError> {
    if is_encrypted_url(url) {
        decrypt(url.trim()).map(|d| Cow::Owned(d.url))
    } else {
        Ok(Cow::Borrowed(url))
    }
}

/// An import sorted by kind, for the add sheet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedImport {
    pub subscriptions: Vec<SubscriptionLink>,
    pub routing: Vec<RoutingLink>,
    pub unsupported: Vec<UnsupportedLink>,
    /// The lines left for the share-link parser.
    pub share_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionLink {
    pub url: String,
    pub encrypted: bool,
    /// The provider name an `incy://` link carries, for the new subscription.
    pub name: Option<String>,
    /// The client the new subscription fetches as: Incy for an `incy://` link.
    pub client: RequestClient,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RoutingLink {
    pub routing: RoutingImport,
    /// The same profile as a shared route, for the route import sheet.
    pub package: RoutePackage,
    /// `onadd` turns the route on; `add` only adds it.
    pub activate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedLink {
    pub text: String,
    pub kind: UnsupportedInput,
}

/// Sort a paste. Only a line made of nothing but links this module knows is taken
/// apart: share links can carry spaces in their `#name`.
pub fn resolve_import_text(text: &str) -> ResolvedImport {
    let mut out = ResolvedImport::default();
    let mut rest: Vec<&str> = Vec::new();
    for line in text.trim().lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let inputs: Vec<ImportInput> = tokens.iter().map(|t| resolve_import_input(t)).collect();
        if inputs.contains(&ImportInput::ShareLinks) {
            rest.push(line);
            continue;
        }
        for (token, input) in tokens.into_iter().zip(inputs) {
            match input {
                ImportInput::SubscriptionUrl {
                    url,
                    encrypted,
                    name,
                } => {
                    out.subscriptions.push(SubscriptionLink {
                        client: if incy_crypt::is_incy_link(&url) {
                            RequestClient::Incy
                        } else {
                            RequestClient::Happ
                        },
                        url,
                        encrypted,
                        name,
                    });
                }
                ImportInput::Routing(action) => {
                    if let Some(profile) = action.profile() {
                        let routing = routing_import(profile);
                        out.routing.push(RoutingLink {
                            package: routing_package(&routing),
                            routing,
                            activate: matches!(*action, RoutingAction::OnAdd(_)),
                        });
                    }
                }
                ImportInput::Unsupported { kind } => out.unsupported.push(UnsupportedLink {
                    text: token.to_owned(),
                    kind,
                }),
                ImportInput::ShareLinks => {}
            }
        }
    }
    out.share_text = rest.join("\n");
    out
}

/// Move the share links whose protocol this device can't run from `share_text` to
/// `unsupported`, so the add sheet says why instead of importing profiles that
/// can't start.
pub fn withhold_unavailable(resolved: &mut ResolvedImport, unavailable: &[Protocol]) {
    if unavailable.is_empty() {
        return;
    }
    let mut kept = Vec::new();
    for line in resolved.share_text.lines() {
        match parse_share_link(line.trim(), None) {
            Some(p) if unavailable.contains(&p.protocol()) => {
                resolved.unsupported.push(UnsupportedLink {
                    text: line.trim().to_owned(),
                    kind: UnsupportedInput::UnavailableProtocol,
                });
            }
            _ => kept.push(line),
        }
    }
    resolved.share_text = kept.join("\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    const VLESS: &str = "vless://11111111-1111-1111-1111-111111111111@e.example:443?type=tcp&security=tls&sni=s#Home";
    const NAIVE: &str = "naive+https://user:pass@n.example:443#Naive";

    #[test]
    fn withholds_share_links_the_device_cannot_run() {
        let mut r = resolve_import_text(&format!("{VLESS}\n{NAIVE}"));
        withhold_unavailable(&mut r, &[Protocol::Naive]);
        assert_eq!(r.share_text, VLESS);
        assert_eq!(
            r.unsupported,
            [UnsupportedLink {
                text: NAIVE.into(),
                kind: UnsupportedInput::UnavailableProtocol,
            }]
        );
    }

    #[test]
    fn keeps_every_share_link_where_all_protocols_run() {
        let text = format!("{VLESS}\n{NAIVE}");
        let mut r = resolve_import_text(&text);
        withhold_unavailable(&mut r, &[]);
        assert_eq!(r.share_text, text);
        assert!(r.unsupported.is_empty());
    }

    /// Vendor-issued `happ://crypt5` links, copied from happ-sub's fixtures, with the
    /// probe URLs they were made for.
    fn crypt5() -> Vec<(String, String)> {
        let raw = include_str!("../tests/fixtures/happ/crypt5-samples.json");
        let samples: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
        samples
            .iter()
            .map(|s| {
                let field = |k: &str| s[k].as_str().unwrap().to_owned();
                (field("encrypted_link"), field("expected_url"))
            })
            .collect()
    }

    fn routing_link(kind: &str) -> String {
        let json = r#"{"Name":"EXAMPLE-ROUTING","GlobalProxy":true,"DirectSites":["geosite:category-ru"],"DirectIp":["geoip:ru"],"BlockSites":["geosite:category-ads-all"],"RemoteDnsDomain":"https://dns.example/dns-query"}"#;
        format!("happ://routing/{kind}/{}", STANDARD.encode(json))
    }

    #[test]
    fn plain_urls_are_subscriptions_and_user_info_is_a_proxy_link() {
        assert_eq!(
            resolve_import_input(" https://sub.example.com/s/abc "),
            ImportInput::SubscriptionUrl {
                url: "https://sub.example.com/s/abc".into(),
                encrypted: false,
                name: None,
            }
        );
        assert_eq!(
            resolve_import_input("http://user:pass@1.2.3.4:8080"),
            ImportInput::ShareLinks
        );
        assert_eq!(
            resolve_import_input("vless://id@h:443#Name"),
            ImportInput::ShareLinks
        );
    }

    #[test]
    fn add_link_is_a_plain_subscription() {
        for link in [
            "happ://add/https://sub.example.com/s/abc?x=1#Title",
            "HAPP://Add/https%3A%2F%2Fsub.example.com%2Fs%2Fabc%3Fx%3D1%23Title",
        ] {
            assert_eq!(
                resolve_import_input(link),
                ImportInput::SubscriptionUrl {
                    url: "https://sub.example.com/s/abc?x=1#Title".into(),
                    encrypted: false,
                    name: None,
                },
                "{link}"
            );
        }
        for link in [
            "happ://add/",
            "happ://add/vless://id@h:443",
            "happ://add/ftp://h/x",
        ] {
            assert_eq!(
                resolve_import_input(link),
                unsupported(UnsupportedInput::Invalid),
                "{link}"
            );
        }
    }

    #[test]
    fn crypt5_vendor_samples_decrypt_to_their_targets() {
        let samples = crypt5();
        assert_eq!(samples.len(), 5);
        for (link, target) in &samples {
            assert_eq!(subscription_fetch_url(link).unwrap(), *target);
            assert_eq!(
                resolve_import_input(link),
                ImportInput::SubscriptionUrl {
                    url: link.trim().into(),
                    encrypted: true,
                    name: None,
                }
            );
        }
    }

    #[test]
    fn encrypted_link_inside_add_stays_encrypted() {
        let (link, _) = &crypt5()[0];
        assert_eq!(
            resolve_import_input(&format!("happ://add/{link}")),
            ImportInput::SubscriptionUrl {
                url: link.into(),
                encrypted: true,
                name: None,
            }
        );
    }

    /// The cross-platform vector pinned by Incy's reference encoder.
    const INCY_VECTOR: &str = "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg";

    fn incy_link(url: &str, name: Option<&str>) -> String {
        incy_crypt::encrypt_link(
            url,
            name,
            incy_crypt::builtin_key(),
            [7; incy_crypt::IV_LEN],
        )
    }

    #[test]
    fn incy_link_is_an_encrypted_subscription() {
        assert_eq!(
            subscription_fetch_url(INCY_VECTOR).unwrap(),
            "https://sub.example.com/test-vector"
        );
        assert_eq!(
            resolve_import_input(&format!(" {INCY_VECTOR} ")),
            ImportInput::SubscriptionUrl {
                url: INCY_VECTOR.into(),
                encrypted: true,
                name: None,
            }
        );
        assert!(is_encrypted_url(INCY_VECTOR));
        assert!(is_encrypted_url("INCY://Crypt1/x"));
    }

    #[test]
    fn incy_link_names_the_subscription() {
        let link = incy_link(
            "https://sub.example.com/s?t=1#Example",
            Some(" Example\u{202e} VPN\n"),
        );
        assert_eq!(
            resolve_import_input(&link),
            ImportInput::SubscriptionUrl {
                url: link.clone(),
                encrypted: true,
                name: Some("Example VPN".into()),
            }
        );
        assert_eq!(
            subscription_fetch_url(&link).unwrap(),
            "https://sub.example.com/s?t=1#Example"
        );
        let r = resolve_import_text(&format!("happ://add/{link}"));
        assert_eq!(r.subscriptions[0].name.as_deref(), Some("Example VPN"));
        assert_eq!(r.subscriptions[0].client, RequestClient::Incy);
        let r = resolve_import_text(&crypt5()[0].0);
        assert_eq!(r.subscriptions[0].client, RequestClient::Happ);
    }

    #[test]
    fn incy_link_without_a_subscription_url_is_reported() {
        for link in [
            incy_link("vless://id@h:443#Name", None),
            INCY_VECTOR.replacen("AAEC", "AAED", 1),
            "incy://crypt1/".into(),
        ] {
            assert_eq!(
                resolve_import_input(&link),
                unsupported(UnsupportedInput::UrlDecrypt),
                "{link}"
            );
            assert!(subscription_fetch_url(&link).is_err());
        }
    }

    #[test]
    fn undecryptable_link_is_reported() {
        let (link, _) = &crypt5()[0];
        // A marker no key is known for.
        let broken = link.replacen("fzvd", "zzzz", 1);
        assert_eq!(
            resolve_import_input(&broken),
            unsupported(UnsupportedInput::UrlDecrypt)
        );
        assert!(subscription_fetch_url(&broken).is_err());
        assert_eq!(
            resolve_import_input("happ://crypt5/"),
            unsupported(UnsupportedInput::UrlDecrypt)
        );
    }

    #[test]
    fn fetch_url_of_a_plain_url_is_unchanged() {
        let url = "https://sub.example.com/s#Name";
        assert!(matches!(subscription_fetch_url(url), Ok(Cow::Borrowed(u)) if u == url));
        assert!(!is_encrypted_url(url));
        assert!(is_encrypted_url(&crypt5()[0].0));
    }

    #[test]
    fn routing_links_carry_the_profile() {
        let ImportInput::Routing(action) = resolve_import_input(&routing_link("onadd")) else {
            panic!("not a routing link");
        };
        assert_eq!(action.profile().unwrap().name, "EXAMPLE-ROUTING");
        assert!(matches!(
            resolve_import_input(&routing_link("add")),
            ImportInput::Routing(a) if matches!(*a, RoutingAction::Add(_))
        ));
        assert_eq!(
            resolve_import_input("happ://routing/off"),
            unsupported(UnsupportedInput::RoutingOff)
        );
        assert_eq!(
            resolve_import_input("happ://routing/add/!!!"),
            unsupported(UnsupportedInput::Invalid)
        );
    }

    #[test]
    fn control_deeplinks_are_rejected() {
        for link in [
            "happ://toggle",
            "happ://connect",
            "happ://disconnect",
            "happ://open",
            "happ://close",
            "happ://toggle_without_ui",
            "happ://connect_without_ui",
            "happ://disconnect_without_ui",
            "happ://open_without_ui",
            "happ://close_without_ui",
        ] {
            assert_eq!(
                resolve_import_input(link),
                unsupported(UnsupportedInput::Control),
                "{link}"
            );
        }
        assert_eq!(
            resolve_import_input("happ://send_to_device/abc"),
            unsupported(UnsupportedInput::SendToDevice)
        );
        assert_eq!(
            resolve_import_input("happ://frobnicate"),
            unsupported(UnsupportedInput::Invalid)
        );
    }

    #[test]
    fn a_paste_is_sorted_by_kind() {
        let (crypt, _) = &crypt5()[0];
        let text = format!(
            "https://a.example/s https://b.example/s\n\
             vless://id@h:443?type=tcp#My server name\n\
             happ://add/https://c.example/s {crypt}\n\
             {}\n\
             happ://connect\n",
            routing_link("onadd")
        );
        let r = resolve_import_text(&text);
        let subs: Vec<(&str, bool)> = r
            .subscriptions
            .iter()
            .map(|s| (s.url.as_str(), s.encrypted))
            .collect();
        assert_eq!(
            subs,
            [
                ("https://a.example/s", false),
                ("https://b.example/s", false),
                ("https://c.example/s", false),
                (crypt.as_str(), true),
            ]
        );
        assert_eq!(r.routing.len(), 1);
        assert_eq!(r.routing[0].routing.name, "EXAMPLE-ROUTING");
        assert_eq!(
            r.routing[0].routing.block_sites,
            ["geosite:category-ads-all"]
        );
        assert_eq!(r.routing[0].routing.ignored_fields, ["RemoteDnsDomain"]);
        assert!(r.routing[0].activate);
        assert!(!resolve_import_text(&routing_link("add")).routing[0].activate);
        assert_eq!(
            r.unsupported,
            [UnsupportedLink {
                text: "happ://connect".into(),
                kind: UnsupportedInput::Control,
            }]
        );
        assert_eq!(r.share_text, "vless://id@h:443?type=tcp#My server name");
    }

    #[test]
    fn a_line_mixing_links_and_text_stays_text() {
        let r = resolve_import_text("https://a.example/s and some words");
        assert!(r.subscriptions.is_empty());
        assert_eq!(r.share_text, "https://a.example/s and some words");
        assert_eq!(resolve_import_text("  \n "), ResolvedImport::default());
    }
}
