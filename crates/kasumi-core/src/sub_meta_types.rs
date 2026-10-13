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
    SkippedLines {
        count: u32,
        sample: String,
    },
    UnsupportedLinks {
        count: u32,
    },
    InvalidRouting {
        message: String,
    },
    InvalidFragment,
    LegacyParser,
    /// The primary URL failed and the accepted fallback URL answered.
    UsedFallback {
        host: String,
    },
    /// Provider Xray configs the sanitiser could not use.
    RejectedConfigs {
        count: u32,
    },
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

/// The risk tier of a provider key, as happ-sub classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum MetaRisk {
    Display,
    Schedule,
    TunnelBehaviour,
    TrustBoundary,
    DeviceIdentity,
    Ignored,
}

impl From<happ_sub::RiskClass> for MetaRisk {
    fn from(r: happ_sub::RiskClass) -> Self {
        // Exhaustive on purpose: a new happ-sub tier must be placed here by hand.
        match r {
            happ_sub::RiskClass::Display => MetaRisk::Display,
            happ_sub::RiskClass::Schedule => MetaRisk::Schedule,
            happ_sub::RiskClass::TunnelBehaviour => MetaRisk::TunnelBehaviour,
            happ_sub::RiskClass::TrustBoundary => MetaRisk::TrustBoundary,
            happ_sub::RiskClass::DeviceIdentity => MetaRisk::DeviceIdentity,
            happ_sub::RiskClass::Ignored => MetaRisk::Ignored,
        }
    }
}

/// A provider key waiting for the user's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PendingChange {
    /// The wire key, e.g. `new-url`.
    pub key: String,
    /// The proposed value, cleaned of control and bidi characters.
    pub value: String,
    /// What Kasumi uses now, when there is such a thing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub risk: MetaRisk,
    pub action: ChangeAction,
    /// SHA-256 of the key and the proposed content: an answer holds for this value only.
    pub digest: String,
    pub seen_at: String,
}

/// What accepting a [`PendingChange`] does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ChangeAction {
    #[serde(rename_all = "camelCase")]
    ReplaceUrl {
        url: String,
        from_host: String,
        to_host: String,
        other_domain: bool,
    },
    #[serde(rename_all = "camelCase")]
    ReplaceDomain {
        url: String,
        from_host: String,
        to_host: String,
        other_domain: bool,
    },
    SetFallbackUrl {
        url: String,
        host: String,
    },
    #[serde(rename_all = "camelCase")]
    SetUserAgent {
        user_agent: String,
    },
    /// `manual-block-user-agent`: the provider's User-Agent replaces the user's.
    LockUserAgent {
        on: bool,
    },
    SetInsecure {
        on: bool,
    },
    ImportRouting {
        routing: RoutingImport,
        activate: bool,
    },
    SetRoutingEnabled {
        on: bool,
    },
    /// A global setting: it changes every profile, not just this subscription's.
    TunnelSetting {
        setting: TunnelSetting,
    },
    /// Import the full Xray configs the provider sends, sanitised.
    AllowProviderConfigs,
    /// Shown, but Kasumi has nothing to apply it to: it can only be dismissed.
    Unsupported,
}

/// A Happ routing profile, cut down to what Kasumi's routes can express.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RoutingImport {
    pub name: String,
    pub direct_sites: Vec<String>,
    pub direct_ip: Vec<String>,
    pub proxy_sites: Vec<String>,
    pub proxy_ip: Vec<String>,
    pub block_sites: Vec<String>,
    pub block_ip: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_proxy: Option<bool>,
    /// Profile fields with no Kasumi equivalent, by their Happ name.
    #[serde(default)]
    pub ignored_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TunnelSetting {
    Mux { on: bool },
    Fragment { on: bool },
    FragmentPackets { value: String },
    FragmentLength { value: String },
    FragmentInterval { value: String },
    Sniffing { on: bool },
}

/// The user's answer to one proposed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ChangeDecision {
    pub key: String,
    pub digest: String,
    pub accepted: bool,
    pub at: String,
}

/// One line of a subscription's history of provider changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub at: String,
    pub key: String,
    pub outcome: AuditOutcome,
    /// The value, or why it was ignored.
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum AuditOutcome {
    AutoApplied,
    Offered,
    Accepted,
    Rejected,
    Ignored,
}
