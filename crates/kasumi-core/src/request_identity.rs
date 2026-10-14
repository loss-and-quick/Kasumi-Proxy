//! Who a subscription fetch says it is. happ-sub builds Happ's request (header order,
//! User-Agent, device headers, the provider's keys); this module feeds it the user's
//! settings and the detected device, and shapes the result for the UI.

use serde::{Deserialize, Serialize};

use happ_sub::MetaMap;
use happ_sub::happ_request::{
    ClientOs, DEFAULT_TIMEOUT, DeviceInfo, Identity, Locks, RequestProfile, build,
};
use happ_sub::incy_request;

use crate::state::Subscription;

pub use happ_sub::{HAPP_VERSION, INCY_VERSION};

/// Settings-wide request identity; each subscription may override any part of it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct RequestIdentityDefaults {
    /// Empty sends Happ's User-Agent.
    pub user_agent: String,
    pub send_hwid: bool,
    pub hwid_in_cookie: bool,
    /// Keep the cookies providers set, per host, across subscription fetches.
    pub cookie_jar: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Android user whose SSAID key derives the HWID; each user has its own.
    pub android_user: u32,
}

impl Default for RequestIdentityDefaults {
    fn default() -> Self {
        Self {
            user_agent: String::new(),
            send_hwid: true,
            hwid_in_cookie: false,
            cookie_jar: true,
            hwid: None,
            device_os: None,
            os_version: None,
            device_model: None,
            locale: None,
            android_user: 0,
        }
    }
}

/// One subscription's departures from [`RequestIdentityDefaults`]; its User-Agent is
/// `Subscription::user_agent`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct SubRequestOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_hwid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwid_in_cookie: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hwid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

impl SubRequestOverrides {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What the device reports about itself, before any override.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct DeviceFacts {
    pub os: String,
    pub os_version: String,
    pub model: String,
    pub locale: String,
    /// The `android.os.Build` values Incy hashes into its device id; empty off Android.
    #[serde(default)]
    pub build: AndroidBuild,
}

/// `android.os.Build` fields beyond the model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct AndroidBuild {
    pub manufacturer: String,
    pub brand: String,
    pub device: String,
    pub product: String,
    pub board: String,
    pub hardware: String,
}

/// Which client a subscription fetch presents itself as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum RequestClient {
    #[default]
    Happ,
    Incy,
}

impl RequestClient {
    pub fn is_happ(&self) -> bool {
        *self == RequestClient::Happ
    }
}

/// Where the HWID a request carries comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum HwidSource {
    /// Typed for this subscription.
    Subscription,
    /// Typed in Settings.
    Settings,
    /// The SSAID Android stored for an installed Happ.
    HappStored,
    /// The SSAID Android would give Happ, from the user's SSAID key.
    HappComputed,
    /// Derived from the host's machine id.
    HappMachineId,
    /// Random, kept in the data directory.
    HappDeviceId,
    /// Incy's id derived from the SSAID Android gives Incy and the build values.
    IncyDerived,
    /// Incy's id derived from a random seed kept in the data directory.
    IncySeed,
}

/// The automatic HWID: what is sent when nobody typed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoHwid {
    pub value: String,
    pub source: HwidSource,
}

/// The identity settings one fetch uses: the Settings defaults and the subscription's own.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInput {
    pub defaults: RequestIdentityDefaults,
    #[serde(default)]
    pub request: SubRequestOverrides,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub client: RequestClient,
}

impl IdentityInput {
    /// The stored settings for `sub`, or the Settings defaults alone.
    pub fn stored(defaults: &RequestIdentityDefaults, sub: Option<&Subscription>) -> Self {
        Self {
            defaults: defaults.clone(),
            request: sub.map(|s| s.request.clone()).unwrap_or_default(),
            user_agent: sub.map(|s| s.user_agent.clone()).unwrap_or_default(),
            client: sub.map(|s| s.client).unwrap_or_default(),
        }
    }
}

/// One request header, in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct HeaderPreview {
    pub name: String,
    pub value: String,
}

/// Switches the provider locks in Happ's UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLocks {
    pub user_agent: bool,
    pub send_hwid: bool,
    pub hwid_in_cookie: bool,
}

/// The request a subscription fetch sends, and where its values come from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedIdentity {
    pub hwid: String,
    pub hwid_source: HwidSource,
    pub auto_hwid: String,
    pub auto_hwid_source: HwidSource,
    /// Detected, before overrides.
    pub facts: DeviceFacts,
    pub headers: Vec<HeaderPreview>,
    pub cookie_jar: bool,
    pub locks: ProviderLocks,
    /// The provider's keys alone turn the device headers off.
    pub provider_hides_device: bool,
    /// The provider's keys alone move the HWID into a cookie.
    pub provider_hwid_cookie: bool,
}

/// A HWID that is safe to send: 1..=64 printable ASCII characters, no spaces.
pub fn is_valid_hwid(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| (b'!'..=b'~').contains(&b))
}

/// The OS for `X-Device-OS` and the User-Agent; blank keeps Happ's Android.
pub fn happ_client_os(name: &str) -> ClientOs {
    let name = name.trim();
    match name.to_ascii_lowercase().as_str() {
        "" | "android" => ClientOs::Android,
        "androidtv" => ClientOs::AndroidTv,
        "windows" => ClientOs::Windows,
        "linux" => ClientOs::Linux,
        "macos" => ClientOs::MacOs,
        "ios" => ClientOs::Ios,
        _ => ClientOs::Other(name.to_owned()),
    }
}

fn given(v: Option<&String>) -> Option<&str> {
    v.map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Happ's HWID to send and its source: the subscription's, the Settings one, else `auto`.
pub fn pick_happ_hwid(
    defaults: &RequestIdentityDefaults,
    request: &SubRequestOverrides,
    auto: &AutoHwid,
) -> (String, HwidSource) {
    let typed = |v: Option<&String>| given(v).filter(|h| is_valid_hwid(h)).map(str::to_owned);
    if let Some(h) = typed(request.hwid.as_ref()) {
        (h, HwidSource::Subscription)
    } else if let Some(h) = typed(defaults.hwid.as_ref()) {
        (h, HwidSource::Settings)
    } else {
        (auto.value.clone(), auto.source)
    }
}

/// happ-sub's identity for one subscription. A Settings switch left at Happ's default
/// lets the provider's keys decide; a changed one, or any per-subscription one, wins.
pub fn happ_identity(
    defaults: &RequestIdentityDefaults,
    sub_user_agent: &str,
    request: &SubRequestOverrides,
    facts: &DeviceFacts,
    hwid: &str,
) -> Identity {
    let pick = |sub: Option<&String>, global: Option<&String>, detected: &str| {
        given(sub).or(given(global)).unwrap_or(detected).to_owned()
    };
    let user_agent = [sub_user_agent, &defaults.user_agent]
        .into_iter()
        .map(str::trim)
        .find(|ua| !ua.is_empty())
        .map(str::to_owned);
    Identity {
        hwid: Some(hwid.to_owned()),
        device: DeviceInfo {
            os: happ_client_os(&pick(
                request.device_os.as_ref(),
                defaults.device_os.as_ref(),
                &facts.os,
            )),
            os_version: pick(
                request.os_version.as_ref(),
                defaults.os_version.as_ref(),
                &facts.os_version,
            ),
            model: pick(
                request.device_model.as_ref(),
                defaults.device_model.as_ref(),
                &facts.model,
            ),
            locale: pick(
                request.locale.as_ref(),
                defaults.locale.as_ref(),
                &facts.locale,
            ),
        },
        user_agent_override: user_agent,
        send_hwid_override: request.send_hwid.or((!defaults.send_hwid).then_some(false)),
        hwid_in_cookie_override: request
            .hwid_in_cookie
            .or(defaults.hwid_in_cookie.then_some(true)),
    }
}

/// The request plus what the UI shows about it.
pub struct Resolved {
    pub profile: RequestProfile,
    pub view: ResolvedIdentity,
}

/// Resolve the request a subscription with `meta` (its stored provider keys) sends.
/// `consented` lists the trust-boundary keys whose current value the user accepted.
pub fn resolve(
    input: &IdentityInput,
    facts: &DeviceFacts,
    auto: &AutoHwid,
    meta: Option<&MetaMap>,
    consented: &[String],
    unix_secs: u64,
) -> Resolved {
    match input.client {
        RequestClient::Happ => resolve_happ(input, facts, auto, meta, consented, unix_secs),
        RequestClient::Incy => resolve_incy(input, facts, auto),
    }
}

/// Happ's request, built by happ-sub from the user's settings and the provider's keys.
fn resolve_happ(
    input: &IdentityInput,
    facts: &DeviceFacts,
    auto: &AutoHwid,
    meta: Option<&MetaMap>,
    consented: &[String],
    unix_secs: u64,
) -> Resolved {
    let consent = |key: &str| consented.iter().any(|k| k == key);
    let (hwid, hwid_source) = pick_happ_hwid(&input.defaults, &input.request, auto);
    let mut id = happ_identity(
        &input.defaults,
        &input.user_agent,
        &input.request,
        facts,
        &hwid,
    );
    // An accepted provider User-Agent ranks below the subscription's own and above
    // the Settings one; happ-sub applies it when no override is given.
    let provider_ua = meta
        .and_then(|m| m.get("change-user-agent"))
        .is_some_and(|ua| !ua.trim().is_empty() && consent("change-user-agent"));
    if provider_ua && input.user_agent.trim().is_empty() {
        id.user_agent_override = None;
    }
    let profile = build(&id, meta, unix_secs, consent);
    // The same device with no user switches shows what the provider's keys do alone.
    let alone = build(
        &Identity {
            send_hwid_override: None,
            hwid_in_cookie_override: None,
            ..id
        },
        meta,
        unix_secs,
        consent,
    );
    let has = |p: &RequestProfile, name: &str| p.headers.iter().any(|(n, _)| n == name);
    let view = ResolvedIdentity {
        hwid,
        hwid_source,
        auto_hwid: auto.value.clone(),
        auto_hwid_source: auto.source,
        facts: facts.clone(),
        headers: profile
            .headers
            .iter()
            .map(|(name, value)| HeaderPreview {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        cookie_jar: input.defaults.cookie_jar && profile.use_cookie_jar,
        locks: ProviderLocks {
            user_agent: profile.locks.user_agent,
            send_hwid: profile.locks.send_hwid,
            hwid_in_cookie: profile.locks.hwid_in_cookie,
        },
        provider_hides_device: !has(&alone, "X-Device-OS"),
        provider_hwid_cookie: has(&alone, "Cookie"),
    };
    Resolved { profile, view }
}

/// Incy's request. Incy has no provider keys for its request, no cookie jar and no
/// retry, and its User-Agent and HWID are its own: the Settings ones, made for
/// Happ, don't apply, while the device fields and the HWID switch do.
fn resolve_incy(input: &IdentityInput, facts: &DeviceFacts, auto: &AutoHwid) -> Resolved {
    let (defaults, request) = (&input.defaults, &input.request);
    let (hwid, hwid_source) = match given(request.hwid.as_ref()).filter(|h| is_valid_hwid(h)) {
        Some(h) => (h.to_owned(), HwidSource::Subscription),
        None => (auto.value.clone(), auto.source),
    };
    let pick = |sub: Option<&String>, global: Option<&String>, detected: &str| {
        given(sub).or(given(global)).unwrap_or(detected).to_owned()
    };
    let os_version = pick(
        request.os_version.as_ref(),
        defaults.os_version.as_ref(),
        &facts.os_version,
    );
    let model = pick(
        request.device_model.as_ref(),
        defaults.device_model.as_ref(),
        &facts.model,
    );
    let tag = language_tag(&pick(
        request.locale.as_ref(),
        defaults.locale.as_ref(),
        &facts.locale,
    ));
    let java = java_locale(&tag);
    let b = &facts.build;
    let device = incy_request::DeviceFacts {
        android_id: None,
        manufacturer: &b.manufacturer,
        model: &model,
        brand: &b.brand,
        device: &b.device,
        product: &b.product,
        board: &b.board,
        hardware: &b.hardware,
        os_version: &os_version,
        locale: &java,
        language_tag: &tag,
    };
    let options = incy_request::RequestOptions {
        app_version: INCY_VERSION,
        vm_version: None,
        user_agent: Some(input.user_agent.trim()),
        hwid: None,
    };
    let send = request.send_hwid.unwrap_or(defaults.send_hwid);
    let headers = incy_request::build_headers(&options, &device, send.then_some(hwid.as_str()));
    let view = ResolvedIdentity {
        hwid,
        hwid_source,
        auto_hwid: auto.value.clone(),
        auto_hwid_source: auto.source,
        facts: facts.clone(),
        headers: headers
            .iter()
            .map(|(name, value)| HeaderPreview {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        cookie_jar: false,
        locks: ProviderLocks::default(),
        provider_hides_device: false,
        provider_hwid_cookie: false,
    };
    let profile = RequestProfile {
        headers,
        timeout: DEFAULT_TIMEOUT,
        retries: 0,
        use_cookie_jar: false,
        locks: Locks::default(),
    };
    Resolved { profile, view }
}

/// A BCP 47 tag; a typed `ru_RU` is read as `ru-RU`.
fn language_tag(locale: &str) -> String {
    let tag = locale.trim().replace('_', "-");
    if tag.is_empty() { "en-US".into() } else { tag }
}

/// Java's `Locale.toString()` for a tag: `ru-RU` is `ru_RU`, `zh-Hans-CN` is
/// `zh_CN_#Hans`.
fn java_locale(tag: &str) -> String {
    let mut parts = tag.split('-');
    let language = parts.next().unwrap_or_default().to_ascii_lowercase();
    let (mut script, mut region) = (None, None);
    for part in parts {
        if part.len() == 4 && part.bytes().all(|b| b.is_ascii_alphabetic()) && script.is_none() {
            let mut s = part.to_ascii_lowercase();
            s[..1].make_ascii_uppercase();
            script = Some(s);
        } else if (part.len() == 2 && part.bytes().all(|b| b.is_ascii_alphabetic()))
            || (part.len() == 3 && part.bytes().all(|b| b.is_ascii_digit()))
        {
            region.get_or_insert_with(|| part.to_ascii_uppercase());
        }
    }
    let mut out = language;
    if region.is_some() || script.is_some() {
        out.push('_');
        out.push_str(region.as_deref().unwrap_or_default());
    }
    if let Some(script) = script {
        out.push_str("_#");
        out.push_str(&script);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HWID: &str = "0123456789abcdef";
    // 2026-10-12, 00:00:00 UTC.
    const DAY: u64 = 1_791_763_200;

    fn facts() -> DeviceFacts {
        DeviceFacts {
            os: "Android".into(),
            os_version: "16".into(),
            model: "Pixel 9".into(),
            locale: "ru-RU".into(),
            build: AndroidBuild {
                manufacturer: "Google".into(),
                brand: "google".into(),
                device: "tokay".into(),
                product: "tokay".into(),
                board: "tokay".into(),
                hardware: "tokay".into(),
            },
        }
    }

    fn auto() -> AutoHwid {
        AutoHwid {
            value: HWID.into(),
            source: HwidSource::HappComputed,
        }
    }

    fn input() -> IdentityInput {
        IdentityInput::default()
    }

    fn meta(pairs: &[(&str, &str)]) -> MetaMap {
        let mut m = MetaMap::new();
        for (k, v) in pairs {
            m.insert(k, v);
        }
        m
    }

    fn headers(r: &Resolved) -> Vec<(&str, &str)> {
        r.view
            .headers
            .iter()
            .map(|h| (h.name.as_str(), h.value.as_str()))
            .collect()
    }

    fn header<'r>(r: &'r Resolved, name: &str) -> Option<&'r str> {
        headers(r)
            .into_iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v)
    }

    #[test]
    fn defaults_match_happ_header_set_and_order() {
        let r = resolve(&input(), &facts(), &auto(), None, &[], DAY);
        let names: Vec<&str> = headers(&r).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "Connection",
                "User-agent",
                "X-Device-Locale",
                "X-HWID",
                "X-Device-OS",
                "X-Ver-OS",
                "X-Device-model",
            ]
        );
        assert_eq!(
            header(&r, "User-agent"),
            Some(happ_sub::happ_request::user_agent("Android", 12).as_str())
        );
        assert_eq!(header(&r, "X-HWID"), Some(HWID));
        assert_eq!(header(&r, "X-Device-Locale"), Some("ru"));
        assert_eq!(r.view.hwid_source, HwidSource::HappComputed);
        assert!(r.view.cookie_jar);
    }

    #[test]
    fn legacy_user_agent_wins() {
        let mut d = input();
        d.defaults.user_agent = "Global/1".into();
        d.user_agent = "v2rayNG/1.10.16".into();
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "User-agent"), Some("v2rayNG/1.10.16"));
        d.user_agent = "  ".into();
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "User-agent"), Some("Global/1"));
    }

    #[test]
    fn sub_override_beats_provider_beats_settings() {
        let off = meta(&[("subscription-send-hwid-enabled", "false")]);
        // Settings at Happ's default: the provider decides.
        let r = resolve(&input(), &facts(), &auto(), Some(&off), &[], DAY);
        assert_eq!(header(&r, "X-Device-OS"), None);
        assert!(r.view.provider_hides_device);
        // A per-subscription switch wins over the provider.
        let mut d = input();
        d.request.send_hwid = Some(true);
        let r = resolve(&d, &facts(), &auto(), Some(&off), &[], DAY);
        assert_eq!(header(&r, "X-HWID"), Some(HWID));
        assert!(r.view.provider_hides_device);
        // Turned off in Settings: off everywhere, unless the subscription says on.
        let mut d = input();
        d.defaults.send_hwid = false;
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-HWID"), None);
        d.request.send_hwid = Some(true);
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-HWID"), Some(HWID));
    }

    #[test]
    fn hwid_in_cookie_replaces_the_header() {
        let mut d = input();
        d.defaults.hwid_in_cookie = true;
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-HWID"), None);
        assert_eq!(header(&r, "Cookie"), Some(HWID));
        assert!(!r.view.provider_hwid_cookie);

        let on = meta(&[("subscription-hwid-in-cookie-enable", "1")]);
        let r = resolve(&input(), &facts(), &auto(), Some(&on), &[], DAY);
        assert!(r.view.locks.hwid_in_cookie && r.view.provider_hwid_cookie);
    }

    #[test]
    fn typed_hwid_and_device_fields_win_in_order() {
        let mut d = input();
        d.defaults.hwid = Some("settings-hwid".into());
        d.defaults.device_model = Some("PC".into());
        d.request.locale = Some("en_US".into());
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-HWID"), Some("settings-hwid"));
        assert_eq!(r.view.hwid_source, HwidSource::Settings);
        assert_eq!(header(&r, "X-Device-model"), Some("PC"));
        assert_eq!(header(&r, "X-Device-Locale"), Some("en"));

        d.request.hwid = Some("sub-hwid".into());
        d.request.device_model = Some("  ".into());
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-HWID"), Some("sub-hwid"));
        assert_eq!(r.view.hwid_source, HwidSource::Subscription);
        assert_eq!(header(&r, "X-Device-model"), Some("PC"), "blank inherits");
    }

    #[test]
    fn hwid_with_crlf_rejected() {
        assert!(is_valid_hwid(HWID));
        for bad in ["", "a b", "a\r\nX-Evil: 1", "ключ", &"a".repeat(65)] {
            assert!(!is_valid_hwid(bad), "{bad:?}");
        }
        let mut d = input();
        d.request.hwid = Some("a\r\nX-Evil: 1".into());
        let r = resolve(&d, &facts(), &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-HWID"), Some(HWID));
        assert_eq!(r.view.hwid_source, HwidSource::HappComputed);
    }

    #[test]
    fn consent_withheld_until_review() {
        let m = meta(&[
            ("change-user-agent", "Provider/1"),
            ("manual-block-user-agent", "true"),
        ]);
        let r = resolve(&input(), &facts(), &auto(), Some(&m), &[], DAY);
        assert_ne!(header(&r, "User-agent"), Some("Provider/1"));
        assert!(!r.view.locks.user_agent);
    }

    #[test]
    fn accepted_user_agent_ranks_between_sub_and_settings() {
        let m = meta(&[
            ("change-user-agent", "Provider/1"),
            ("manual-block-user-agent", "true"),
        ]);
        let consented = [
            "change-user-agent".to_owned(),
            "manual-block-user-agent".to_owned(),
        ];
        let mut d = input();
        d.defaults.user_agent = "Global/1".into();
        let r = resolve(&d, &facts(), &auto(), Some(&m), &consented, DAY);
        assert_eq!(header(&r, "User-agent"), Some("Provider/1"));
        assert!(r.view.locks.user_agent);
        d.user_agent = "Mine/1".into();
        let r = resolve(&d, &facts(), &auto(), Some(&m), &consented, DAY);
        assert_eq!(header(&r, "User-agent"), Some("Mine/1"));
    }

    #[test]
    fn desktop_os_names_map_to_client_os() {
        assert_eq!(happ_client_os("Linux"), ClientOs::Linux);
        assert_eq!(happ_client_os(" windows "), ClientOs::Windows);
        assert_eq!(happ_client_os(""), ClientOs::Android);
        assert_eq!(happ_client_os("Haiku"), ClientOs::Other("Haiku".into()));
        let mut f = facts();
        f.os = "Linux".into();
        let r = resolve(&input(), &f, &auto(), None, &[], DAY);
        assert_eq!(header(&r, "X-Device-OS"), Some("Linux"));
        assert!(header(&r, "User-agent").unwrap().contains("/Linux/"));
    }

    fn incy() -> IdentityInput {
        IdentityInput {
            client: RequestClient::Incy,
            ..input()
        }
    }

    fn incy_auto() -> AutoHwid {
        AutoHwid {
            value: "0123ABCD-0000-1111-2222-333344445555".into(),
            source: HwidSource::IncyDerived,
        }
    }

    #[test]
    fn incy_sends_its_own_header_set_and_order() {
        let r = resolve(&incy(), &facts(), &incy_auto(), None, &[], DAY);
        assert_eq!(
            headers(&r),
            [
                ("User-Agent", "INCY/3.7.0/android Dalvik/2.1.0"),
                ("Accept", "*/*"),
                ("Accept-Language", "ru-RU"),
                ("x-hwid", "0123ABCD-0000-1111-2222-333344445555"),
                ("x-device-os", "Android"),
                ("x-ver-os", "16"),
                ("x-device-model", "Google Pixel 9"),
                ("x-app-version", INCY_VERSION),
                ("x-device-locale", "ru_RU"),
                ("x-client", "INCY"),
            ]
        );
        assert_eq!(r.view.hwid_source, HwidSource::IncyDerived);
        assert_eq!(r.profile.retries, 0);
        assert!(!r.profile.use_cookie_jar && !r.view.cookie_jar);
    }

    #[test]
    fn incy_takes_the_device_fields_but_not_happs_user_agent_or_hwid() {
        let mut d = incy();
        d.defaults.user_agent = "Global/1".into();
        d.defaults.hwid = Some("settingshwid0001".into());
        d.defaults.os_version = Some("15".into());
        d.request.locale = Some("en_GB".into());
        let r = resolve(&d, &facts(), &incy_auto(), None, &[], DAY);
        assert_eq!(
            header(&r, "User-Agent"),
            Some("INCY/3.7.0/android Dalvik/2.1.0")
        );
        assert_eq!(r.view.hwid, incy_auto().value);
        assert_eq!(header(&r, "x-ver-os"), Some("15"));
        assert_eq!(header(&r, "Accept-Language"), Some("en-GB"));
        assert_eq!(header(&r, "x-device-locale"), Some("en_GB"));

        d.user_agent = "Mine/1".into();
        d.request.hwid = Some("MY-ID".into());
        let r = resolve(&d, &facts(), &incy_auto(), None, &[], DAY);
        assert_eq!(header(&r, "User-Agent"), Some("Mine/1"));
        assert_eq!(header(&r, "x-hwid"), Some("MY-ID"));
        assert_eq!(r.view.hwid_source, HwidSource::Subscription);
    }

    #[test]
    fn incy_without_hwid_drops_the_device_block() {
        let mut d = incy();
        d.defaults.send_hwid = false;
        let r = resolve(&d, &facts(), &incy_auto(), None, &[], DAY);
        let names: Vec<&str> = headers(&r).into_iter().map(|(n, _)| n).collect();
        assert_eq!(
            names,
            [
                "User-Agent",
                "Accept",
                "Accept-Language",
                "x-app-version",
                "x-device-locale",
                "x-client",
            ]
        );
        d.request.send_hwid = Some(true);
        let r = resolve(&d, &facts(), &incy_auto(), None, &[], DAY);
        assert!(header(&r, "x-hwid").is_some());
    }

    #[test]
    fn incy_ignores_happs_provider_keys() {
        let m = meta(&[
            ("change-user-agent", "Provider/1"),
            ("subscription-always-hwid-enable", "true"),
        ]);
        let consented = ["change-user-agent".to_owned()];
        let r = resolve(&incy(), &facts(), &incy_auto(), Some(&m), &consented, DAY);
        assert_eq!(
            header(&r, "User-Agent"),
            Some("INCY/3.7.0/android Dalvik/2.1.0")
        );
        assert_eq!(r.view.locks, ProviderLocks::default());
    }

    #[test]
    fn java_locale_follows_locale_to_string() {
        assert_eq!(java_locale("ru-RU"), "ru_RU");
        assert_eq!(java_locale("zh-Hans-CN"), "zh_CN_#Hans");
        assert_eq!(java_locale("sr-Latn"), "sr__#Latn");
        assert_eq!(java_locale("es-419"), "es_419");
        assert_eq!(java_locale("en"), "en");
        assert_eq!(language_tag(" pt_BR "), "pt-BR");
        assert_eq!(language_tag(""), "en-US");
    }
}
