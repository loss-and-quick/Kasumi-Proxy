//! Which provider meta reaches a subscription without asking: the Display keys
//! (title, traffic, announcements, links) and the Schedule keys (update interval,
//! request timeout). Everything else stays in the raw map until a later phase
//! asks the user.

use happ_sub::MetaMap;
use happ_sub::meta::{normalize_untrusted_text, single_line, truncate_title, validate_url_safety};
use percent_encoding::percent_decode_str;

use crate::state::{NoticeColor, ProviderInfo, ProviderNotice, Subscription, TrafficInfo};

/// Longest announcement kept, in characters; a provider banner is a few lines.
const ANNOUNCE_MAX_CHARS: usize = 2000;
/// Byte counts reach the UI as JS numbers.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Happ's `profile-update-interval` is hours; Kasumi's `interval` is minutes.
pub const fn hours_to_minutes(h: u32) -> i64 {
    h as i64 * 60
}

/// The interval the updater runs on: the provider's unless the user set their own.
pub fn effective_interval_minutes(sub: &Subscription) -> i64 {
    match (sub.provider_interval_hours, sub.interval_override) {
        (Some(h), false) => hours_to_minutes(h),
        _ => sub.interval,
    }
}

/// A provider link the UI may open: well-formed http(s) to a public host.
pub fn safe_provider_link(url: &str) -> Option<String> {
    let url = url.trim();
    if url::Url::parse(url).is_err() || validate_url_safety(url, false).is_err() {
        return None;
    }
    Some(url.to_owned())
}

pub fn provider_info(meta: &MetaMap, content_disposition: Option<&str>) -> ProviderInfo {
    ProviderInfo {
        title: meta
            .profile_title()
            .and_then(clean_title)
            .or_else(|| content_disposition.and_then(disposition_title)),
        announce: meta.announce().and_then(|a| {
            let a = normalize_untrusted_text(a);
            let a = a.trim();
            (!a.is_empty()).then(|| a.chars().take(ANNOUNCE_MAX_CHARS).collect())
        }),
        support_url: meta.support_url().and_then(safe_provider_link),
        web_page_url: meta.profile_web_page_url().and_then(safe_provider_link),
        traffic: meta.user_info().map(|u| TrafficInfo {
            upload: u.upload.min(MAX_SAFE_INTEGER),
            download: u.download.min(MAX_SAFE_INTEGER),
            total: u.total.min(MAX_SAFE_INTEGER),
            expire: i64::try_from(u.expire).ok().filter(|&e| e > 0),
        }),
        notice: notice(meta),
        expired: meta.sub_expire().unwrap_or(false),
        renew_url: meta.sub_expire_button_link().and_then(safe_provider_link),
    }
}

fn notice(meta: &MetaMap) -> Option<ProviderNotice> {
    let text = normalize_untrusted_text(meta.sub_info_text()?);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let color = match meta
        .get("sub-info-color")
        .map(|c| c.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("red") => NoticeColor::Red,
        Some("blue") => NoticeColor::Blue,
        Some("green") => NoticeColor::Green,
        _ => NoticeColor::Default,
    };
    Some(ProviderNotice {
        text: text.to_owned(),
        color,
        button_text: meta
            .sub_info_button_text()
            .map(|b| single_line(&normalize_untrusted_text(b)))
            .filter(|b| !b.is_empty()),
        button_url: meta.sub_info_button_link().and_then(safe_provider_link),
    })
}

/// Auto-apply the Display and Schedule keys. `first_import` is the first fetch a
/// subscription ever applies; later refreshes never touch the user's switches.
pub fn apply_auto(
    sub: &mut Subscription,
    meta: &MetaMap,
    content_disposition: Option<&str>,
    first_import: bool,
) {
    let info = provider_info(meta, content_disposition);
    if !sub.manual_title
        && let Some(title) = &info.title
    {
        sub.remarks = title.clone();
    }
    sub.provider_interval_hours = meta.profile_update_interval();
    sub.request_timeout_secs = meta.subscription_request_timeout();
    // Happ adds a subscription with updates on when the provider sends an interval.
    if first_import && sub.provider_interval_hours.is_some() {
        sub.auto_update = true;
    }
    sub.provider = (info != ProviderInfo::default()).then_some(info);
}

fn clean_title(raw: &str) -> Option<String> {
    let title = truncate_title(&single_line(&normalize_untrusted_text(raw)));
    let title = title.trim();
    (!title.is_empty()).then(|| title.to_owned())
}

/// A title from `Content-Disposition` (RFC 6266), without the extension a panel appends.
pub fn disposition_title(header: &str) -> Option<String> {
    let mut plain = None;
    let mut extended = None;
    for param in split_params(header).into_iter().skip(1) {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "filename*" => extended = extended.or_else(|| decode_ext_value(value.trim())),
            "filename" => plain = plain.or_else(|| Some(unquote(value.trim()))),
            _ => {}
        }
    }
    let name = extended.or(plain)?;
    // A recipient must not trust path parts in a suggested file name.
    let name = name.rsplit(['/', '\\']).next().unwrap_or_default();
    let stem = [".txt", ".yaml", ".yml", ".json"]
        .iter()
        .find_map(|ext| {
            let cut = name.len().checked_sub(ext.len())?;
            (name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(ext))
                .then(|| &name[..cut])
        })
        .unwrap_or(name);
    clean_title(stem)
}

/// Split on `;` outside quoted strings.
fn split_params(header: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted, mut escaped) = (0, false, false);
    for (i, c) in header.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push(&header[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&header[start..]);
    out
}

fn unquote(value: &str) -> String {
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' {
            chars.next().unwrap_or(c)
        } else {
            c
        });
    }
    out
}

/// `charset'language'percent-encoded`; UTF-8 and ISO-8859-1 are the charsets
/// RFC 8187 requires.
fn decode_ext_value(value: &str) -> Option<String> {
    let mut parts = value.splitn(3, '\'');
    let charset = parts.next()?.trim().to_ascii_lowercase();
    let _language = parts.next()?;
    let encoded = parts.next()?;
    let bytes: Vec<u8> = percent_decode_str(encoded).collect();
    match charset.as_str() {
        "utf-8" => String::from_utf8(bytes).ok(),
        "iso-8859-1" => Some(bytes.into_iter().map(char::from).collect()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sub_ingest::tests::http_fixture;

    fn meta(pairs: &[(&str, &str)]) -> MetaMap {
        let mut m = MetaMap::new();
        for (k, v) in pairs {
            m.insert(k, v);
        }
        m
    }

    fn sub() -> Subscription {
        Subscription {
            id: "s1".into(),
            remarks: "sub.example.org".into(),
            url: "https://sub.example.org/s".into(),
            enabled: true,
            interval: 360,
            ..Default::default()
        }
    }

    #[test]
    fn interval_730h_is_43800_minutes() {
        assert_eq!(hours_to_minutes(730), 43_800);
        let mut s = sub();
        apply_auto(
            &mut s,
            &meta(&[("profile-update-interval", "9999")]),
            None,
            false,
        );
        assert_eq!(s.provider_interval_hours, Some(730));
        assert_eq!(effective_interval_minutes(&s), 43_800);
    }

    #[test]
    fn interval_override_uses_user_minutes() {
        let mut s = sub();
        s.provider_interval_hours = Some(1);
        assert_eq!(effective_interval_minutes(&s), 60);
        s.interval_override = true;
        assert_eq!(effective_interval_minutes(&s), 360);
        s.interval_override = false;
        s.provider_interval_hours = None;
        assert_eq!(effective_interval_minutes(&s), 360);
    }

    #[test]
    fn title_truncated_and_single_line() {
        let info = provider_info(
            &meta(&[("profile-title", "Line one\nline two and a long tail here")]),
            None,
        );
        assert_eq!(info.title.as_deref(), Some("Line one line two and a l"));
    }

    #[test]
    fn bidi_and_controls_stripped_from_title() {
        let info = provider_info(
            &meta(&[("profile-title", "\u{202E}Evil\u{200B}\u{0007} VPN\u{FEFF}")]),
            None,
        );
        assert_eq!(info.title.as_deref(), Some("Evil VPN"));
    }

    #[test]
    fn unsafe_support_url_dropped() {
        let info = provider_info(
            &meta(&[
                ("support-url", "http://192.168.1.1/admin"),
                ("profile-web-page-url", "javascript:alert(1)"),
                ("sub-expire-button-link", "https://pay.example.org/renew"),
            ]),
            None,
        );
        assert_eq!(info.support_url, None);
        assert_eq!(info.web_page_url, None);
        assert_eq!(
            info.renew_url.as_deref(),
            Some("https://pay.example.org/renew")
        );
        assert_eq!(safe_provider_link("https://localhost/x"), None);
        assert_eq!(
            safe_provider_link("https://t.me/x").as_deref(),
            Some("https://t.me/x")
        );
    }

    #[test]
    fn userinfo_expire_zero_is_none() {
        let info = provider_info(
            &meta(&[(
                "subscription-userinfo",
                "upload=1; download=2; total=0; expire=0",
            )]),
            None,
        );
        assert_eq!(
            info.traffic,
            Some(TrafficInfo {
                upload: 1,
                download: 2,
                total: 0,
                expire: None
            })
        );
    }

    #[test]
    fn notice_color_and_button() {
        let info = provider_info(
            &meta(&[
                ("sub-info-text", "Pay by Friday"),
                ("sub-info-color", "RED"),
                ("sub-info-button-text", "Pay\nnow"),
                ("sub-info-button-link", "https://pay.example.org"),
            ]),
            None,
        );
        let notice = info.notice.unwrap();
        assert_eq!(notice.color, NoticeColor::Red);
        assert_eq!(notice.button_text.as_deref(), Some("Pay now"));
        assert_eq!(
            notice.button_url.as_deref(),
            Some("https://pay.example.org")
        );
    }

    #[test]
    fn manual_title_not_overwritten() {
        let mut s = sub();
        s.remarks = "Mine".into();
        s.manual_title = true;
        apply_auto(&mut s, &meta(&[("profile-title", "Theirs")]), None, false);
        assert_eq!(s.remarks, "Mine");
        assert_eq!(s.provider.unwrap().title.as_deref(), Some("Theirs"));
    }

    #[test]
    fn first_import_with_interval_enables_auto_update() {
        let mut s = sub();
        apply_auto(
            &mut s,
            &meta(&[("profile-update-interval", "12")]),
            None,
            true,
        );
        assert!(s.auto_update);

        let mut s = sub();
        apply_auto(&mut s, &meta(&[]), None, true);
        assert!(!s.auto_update, "no interval, nothing to schedule");
    }

    #[test]
    fn refresh_does_not_flip_auto_update() {
        let mut s = sub();
        apply_auto(
            &mut s,
            &meta(&[("profile-update-interval", "12")]),
            None,
            false,
        );
        assert!(!s.auto_update);
    }

    #[test]
    fn no_display_keys_leave_no_provider() {
        let mut s = sub();
        apply_auto(
            &mut s,
            &meta(&[("subscription-request-timeout", "60")]),
            None,
            false,
        );
        assert_eq!(s.provider, None);
        assert_eq!(s.request_timeout_secs, Some(15));
        assert_eq!(s.remarks, "sub.example.org");
    }

    #[test]
    fn live_fixture_provider_info() {
        let (headers, _) = http_fixture("01-happ-full");
        let m = happ_sub::meta::parse_headers(&headers, &happ_sub::Limits::default()).unwrap();
        let mut s = sub();
        apply_auto(&mut s, &m, None, true);
        let info = s.provider.as_ref().unwrap();
        assert_eq!(s.remarks, "Example VPN 🗽");
        assert_eq!(s.provider_interval_hours, Some(1));
        assert!(s.auto_update);
        assert!(info.announce.as_deref().unwrap().contains('\n'));
        assert_eq!(
            info.support_url.as_deref(),
            Some("https://t.me/example_vpn_bot")
        );
        assert_eq!(
            info.web_page_url.as_deref(),
            Some("https://example.org/start")
        );
        let traffic = info.traffic.as_ref().unwrap();
        assert_eq!((traffic.total, traffic.expire), (0, Some(1_796_256_000)));
    }

    #[test]
    fn disposition_filename_star_utf8() {
        assert_eq!(
            disposition_title("attachment; filename*=UTF-8''%D0%9C%D0%BE%D0%B9%20VPN.txt")
                .as_deref(),
            Some("Мой VPN")
        );
    }

    #[test]
    fn disposition_plain_filename() {
        assert_eq!(
            disposition_title(r#"attachment; filename="Fast \"Net\".yaml""#).as_deref(),
            Some("Fast \"Net\"")
        );
        assert_eq!(
            disposition_title("attachment; filename=nodes").as_deref(),
            Some("nodes")
        );
    }

    #[test]
    fn disposition_star_wins_over_plain() {
        assert_eq!(
            disposition_title(
                "attachment; filename=\"fallback.txt\"; filename*=utf-8''Real%20name.json"
            )
            .as_deref(),
            Some("Real name")
        );
    }

    #[test]
    fn disposition_extension_stripped_and_path_dropped() {
        assert_eq!(
            disposition_title("attachment; filename=\"../x/My Sub.TXT\"").as_deref(),
            Some("My Sub")
        );
        assert_eq!(
            disposition_title("attachment; filename=\"archive.tar\"").as_deref(),
            Some("archive.tar")
        );
    }

    #[test]
    fn disposition_garbage_ignored() {
        for header in [
            "inline",
            "attachment",
            "attachment; size=10",
            "attachment; filename*=koi8-r''%F0",
            "attachment; filename*=UTF-8''%FF%FE",
            "attachment; filename=\".txt\"",
            "attachment; filename*=nonsense",
        ] {
            assert_eq!(disposition_title(header), None, "{header}");
        }
    }

    #[test]
    fn profile_title_wins_over_disposition() {
        let cd = Some("attachment; filename=\"from-cd.txt\"");
        let info = provider_info(&meta(&[("profile-title", "Header")]), cd);
        assert_eq!(info.title.as_deref(), Some("Header"));
        let info = provider_info(&meta(&[]), cd);
        assert_eq!(info.title.as_deref(), Some("from-cd"));
    }
}
