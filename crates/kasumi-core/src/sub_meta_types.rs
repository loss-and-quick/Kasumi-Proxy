//! What the UI sees of a subscription's provider meta: typed projections of the
//! raw map the backend keeps in `sub-meta.json`.

use serde::{Deserialize, Serialize};

/// What the provider says about a subscription (the auto-applied Display keys).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub web_page_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic: Option<TrafficInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<ProviderNotice>,
    #[serde(default)]
    pub expired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renew_url: Option<String>,
}

/// `subscription-userinfo`, in bytes and unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct TrafficInfo {
    pub upload: u64,
    pub download: u64,
    /// 0 = unmetered.
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire: Option<i64>,
}

/// The `sub-info-*` banner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ProviderNotice {
    pub text: String,
    pub color: NoticeColor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub button_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum NoticeColor {
    Red,
    Blue,
    Green,
    #[default]
    Default,
}

/// Something skipped while ingesting; the rest of the body was used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SubWarning {
    SkippedLines { count: u32, sample: String },
    UnsupportedLinks { count: u32 },
    InvalidRouting { message: String },
    InvalidFragment,
    LegacyParser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum ContentHint {
    Yaml,
    Html,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum PayloadKind {
    XrayJson,
    JsonArray,
    SingBoxJson,
}

/// Why the last update failed, so the UI can explain it in the user's language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SubErrorKind {
    Network,
    Http {
        status: u16,
    },
    #[serde(rename_all = "camelCase")]
    Decrypt {
        key_id: Option<String>,
    },
    EmptyBody,
    UnknownContent {
        hint: ContentHint,
    },
    UnsupportedPayload {
        payload: PayloadKind,
    },
    NoProfiles,
    Limit,
    /// A malformed envelope (server JSON, routing or deeplink).
    Invalid,
}
