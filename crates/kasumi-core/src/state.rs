//! Groups, subscriptions, routing rules, asset files, the global advanced
//! settings and the top-level app state. Field names/defaults are fixed by the
//! persisted `app-state.json` shape so old data round-trips on read.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::contract::FetchMode;
use crate::enums::CoreEngine;
use crate::profile::{Profile, Protocol};

// Default local inbound ports used when settings leave them unset.
pub const DEFAULT_LOCAL_SOCKS_PORT: u16 = 10808;
pub const DEFAULT_LOCAL_HTTP_PORT: u16 = 10809;

/// Port of the `force-in` socks inbound, derived from the user-facing ports. This
/// inbound routes straight to the `proxy` outbound, bypassing the geo rules — used
/// for the app's own fetches (subscriptions/assets) when the proxy is wanted
/// regardless of routing.
///
/// Sits at `socks + 2` (the default layout is socks, http = socks + 1, force =
/// socks + 2). A custom `http_port` could land on `socks + 2`, so step past it when
/// it does — `force-in` and `http-in` must never claim the same port or the core
/// won't bind. Deterministic in `(socks, http)`, so the config builders and the
/// platform `proxy_status` compute the identical port without coordinating.
pub const fn force_socks_port(socks: u16, http: u16) -> u16 {
    let candidate = socks.saturating_add(2);
    if candidate == http {
        socks.saturating_add(3)
    } else {
        candidate
    }
}

// Default probe URLs used when delayTestUrl/speedTestUrl are unset.
pub const DEFAULT_DELAY_TEST_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_SPEED_TEST_URL: &str = "http://speed.cloudflare.com/__down?bytes=10000000";

// Default upstream resolvers when remoteDns is unset (sing-box uses the first, xray the list).
pub const DEFAULT_REMOTE_DNS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];
// fake-IP v4 range for the fakeDns feature, shared by both engines.
pub const FAKEIP_INET4_RANGE: &str = "198.18.0.0/15";
// Default log-rotation cap (KB).
pub const DEFAULT_LOG_ROTATE_KB: i64 = 512;

/// The base group that must always exist (default `groupId`, can't be deleted).
pub const BASE_GROUP_ID: &str = "g-main";
pub const BASE_GROUP_NAME: &str = "Main";

/// A profile group (`GroupSchema`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub_id: Option<String>,
}

/// A subscription source (`SubscriptionSchema`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: String,
    pub remarks: String,
    pub url: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub group_id: Option<String>,
    pub auto_update: bool,
    pub interval: i64,
    pub allow_insecure: bool,
    pub user_agent: String,
    pub filter: String,
    #[serde(default)]
    pub update_mode: FetchMode,
    pub last_updated: String,
    pub count: i64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub prev_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub next_profile: Option<String>,
}

/// Transport scope of a routing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum RuleNetwork {
    Tcp,
    Udp,
    #[serde(rename = "tcp,udp")]
    TcpUdp,
}

/// A custom routing rule (`RoutingRuleSchema`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    pub id: String,
    pub remarks: String,
    pub enabled: bool,
    pub outbound_tag: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ip: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub network: Option<RuleNetwork>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub protocol: Option<Vec<String>>,
}

/// A downloadable asset (geoip/geosite) the daemon keeps current (`AssetFileSchema`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct AssetFile {
    pub id: String,
    pub remarks: String,
    pub url: String,
    /// Epoch-ms of last refresh, or `null` if never fetched (required + nullable).
    pub last_updated: Option<i64>,
    pub locked: bool,
}

// ---- AdvancedSettings enums ----

/// How traffic is routed. `bypass-lan` is a legacy alias mapped to `global`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    #[default]
    #[serde(alias = "bypass-lan")]
    Global,
    Custom,
    Rules,
}

/// Xray domain resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, specta::Type)]
pub enum DomainStrategy {
    #[serde(rename = "AsIs")]
    AsIs,
    #[default]
    #[serde(rename = "IPIfNonMatch")]
    IpIfNonMatch,
    #[serde(rename = "IPOnDemand")]
    IpOnDemand,
}

/// sing-box domain resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum SingboxDomainStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

/// sing-box tun network stack (see the Zod comment / [[singbox-gvisor-stack]]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum SingboxStack {
    #[default]
    Gvisor,
    System,
}

/// Mux xudp-over-443 handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum MuxXudp443 {
    Reject,
    Proxy,
}

/// Core log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    None,
}

/// Which apps the tun captures by default (per-app filtering base).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum AppCaptureMode {
    #[default]
    All,
    None,
}

/// Per-app override against the capture mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "kebab-case")]
pub enum AppFilterMode {
    ForceProxy,
    Bypass,
}

/// Global advanced settings (`AdvancedSettingsSchema`). Optional fields omit when
/// unset; the rest always serialize with their Zod defaults (see [`Default`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase", default)]
pub struct AdvancedSettings {
    pub routing_mode: RoutingMode,
    pub domain_sniffing: bool,
    pub route_only: bool,
    pub domain_strategy: DomainStrategy,
    pub domain_strategy4_singbox: SingboxDomainStrategy,
    pub strict_route: bool,
    pub singbox_stack: SingboxStack,
    pub dns_via_proxy: bool,
    pub fake_dns: bool,
    pub prefer_ipv6: bool,
    pub mux: bool,
    pub mux_concurrency: i64,
    pub ping_concurrency: i64,
    pub speed_concurrency: i64,
    pub auto_start: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mux_xudp_concurrency: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mux_xudp443: Option<MuxXudp443>,
    pub fragment: bool,
    pub fragment_packets: String,
    pub mtu: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_length: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment_delay: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,
    pub log_rotate_max_kb: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_socks_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_http_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domestic_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_hosts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay_test_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed_test_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_routing: Option<String>,
    pub core_by_protocol: BTreeMap<Protocol, CoreEngine>,
    pub app_capture_mode: AppCaptureMode,
    pub app_filter: BTreeMap<String, AppFilterMode>,
    pub dedup_on_update: bool,
    pub allow_non_localhost: bool,
}

impl Default for AdvancedSettings {
    fn default() -> Self {
        Self {
            routing_mode: RoutingMode::Global,
            domain_sniffing: true,
            route_only: false,
            domain_strategy: DomainStrategy::IpIfNonMatch,
            domain_strategy4_singbox: SingboxDomainStrategy::PreferIpv4,
            strict_route: false,
            singbox_stack: SingboxStack::Gvisor,
            dns_via_proxy: true,
            fake_dns: false,
            prefer_ipv6: false,
            mux: false,
            mux_concurrency: 8,
            ping_concurrency: 3,
            speed_concurrency: 1,
            auto_start: true,
            mux_xudp_concurrency: None,
            mux_xudp443: None,
            fragment: false,
            fragment_packets: "tlshello".into(),
            mtu: 1350,
            fragment_length: None,
            fragment_delay: None,
            log_level: None,
            log_rotate_max_kb: DEFAULT_LOG_ROTATE_KB,
            local_socks_port: None,
            local_http_port: None,
            remote_dns: None,
            domestic_dns: None,
            dns_hosts: None,
            ipv6_enabled: None,
            socks_username: None,
            socks_password: None,
            delay_test_url: None,
            speed_test_url: None,
            custom_routing: None,
            core_by_protocol: BTreeMap::new(),
            app_capture_mode: AppCaptureMode::All,
            app_filter: BTreeMap::new(),
            dedup_on_update: false,
            allow_non_localhost: false,
        }
    }
}

/// The persisted top-level state (`AppStateSchema`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct AppState {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    pub groups: Vec<Group>,
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    #[serde(default)]
    pub asset_files: Vec<AssetFile>,
    pub settings: AdvancedSettings,
    /// Active profile id, or `null` (required + nullable).
    pub active_id: Option<String>,
    /// Module version that last wrote this state; absent on legacy state.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,
    /// On-disk schema version; absent (→ 0) on pre-versioning data. The read path
    /// runs [`crate::migrate`] up to the current version before deserializing.
    #[serde(default)]
    pub schema_version: u32,
}

/// The canonical fresh state: empty everything but the mandatory base group
/// `g-main`, default settings, nothing active. Fixes the first-run "{}" →
/// ZodError / "import into nowhere" bugs (findings #12/#12b).
pub fn default_app_state() -> AppState {
    AppState {
        profiles: Vec::new(),
        groups: vec![Group {
            id: BASE_GROUP_ID.into(),
            name: BASE_GROUP_NAME.into(),
            sub_id: None,
        }],
        subscriptions: Vec::new(),
        routing_rules: Vec::new(),
        asset_files: Vec::new(),
        settings: AdvancedSettings::default(),
        active_id: None,
        version: None,
        schema_version: crate::migrate::SCHEMA_VERSION,
    }
}

/// Null a dangling `active_id`: a required invariant for [`crate::core_config`],
/// which looks the active profile up by id and fails when it's missing. After any
/// edit that may have removed the active profile (a removal, a group/sub deletion,
/// a backup restore), clear `active_id` when it no longer points at a live profile.
/// Pure; idempotent.
pub fn fixup_active_id(state: &mut AppState) {
    if let Some(id) = &state.active_id {
        if !state.profiles.iter().any(|p| p.meta().id == *id) {
            state.active_id = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_omits_optional_sub_id() {
        let g: Group = serde_json::from_str(r#"{"id":"g-main","name":"Main"}"#).unwrap();
        assert_eq!(g.sub_id, None);
        assert!(serde_json::to_value(&g).unwrap().get("subId").is_none());
    }

    #[test]
    fn force_socks_port_steps_past_a_colliding_http_port() {
        // Default layout: socks, http = socks + 1 → force = socks + 2, no collision.
        assert_eq!(force_socks_port(10808, 10809), 10810);
        // A custom http_port on socks + 2 would clash with force-in → step to socks + 3.
        assert_eq!(force_socks_port(10808, 10810), 10811);
        // socks + 3 itself never collides (only reached when http == socks + 2).
        assert_eq!(force_socks_port(10808, 10811), 10810);
    }

    #[test]
    fn subscription_update_mode_default_and_camel() {
        let s: Subscription = serde_json::from_str(
            r#"{"id":"s","remarks":"r","url":"u","enabled":true,"autoUpdate":false,
                "interval":60,"allowInsecure":false,"userAgent":"","filter":"",
                "lastUpdated":"","count":0}"#,
        )
        .unwrap();
        assert_eq!(s.update_mode, FetchMode::Auto);
        assert_eq!(s.last_error, None);
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["updateMode"], "auto");
        assert!(v.get("lastError").is_none());
    }

    #[test]
    fn rule_network_and_asset_null() {
        assert_eq!(
            serde_json::to_string(&RuleNetwork::TcpUdp).unwrap(),
            "\"tcp,udp\""
        );
        let a: AssetFile = serde_json::from_str(
            r#"{"id":"geoip","remarks":"GeoIP","url":"u","lastUpdated":null,"locked":true}"#,
        )
        .unwrap();
        assert!(serde_json::to_value(&a).unwrap()["lastUpdated"].is_null());
    }

    #[test]
    fn advanced_settings_defaults_from_empty() {
        let s: AdvancedSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, AdvancedSettings::default());
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["routingMode"], "global");
        assert_eq!(v["domainSniffing"], true);
        assert_eq!(v["domainStrategy"], "IPIfNonMatch");
        assert_eq!(v["domainStrategy4Singbox"], "prefer_ipv4");
        assert_eq!(v["singboxStack"], "gvisor");
        assert_eq!(v["muxConcurrency"], 8);
        assert_eq!(v["mtu"], 1350);
        assert_eq!(v["fragmentPackets"], "tlshello");
        assert_eq!(v["logRotateMaxKb"], 512);
        assert_eq!(v["appCaptureMode"], "all");
        assert!(v["coreByProtocol"].as_object().unwrap().is_empty());
        // Optional fields omitted, not null.
        assert!(v.get("localSocksPort").is_none());
        assert!(v.get("logLevel").is_none());
        assert!(v.get("remoteDns").is_none());
    }

    #[test]
    fn routing_mode_legacy_alias() {
        // Legacy "bypass-lan" deserializes to Global and re-serializes as "global".
        let m: RoutingMode = serde_json::from_str("\"bypass-lan\"").unwrap();
        assert_eq!(m, RoutingMode::Global);
        assert_eq!(serde_json::to_string(&m).unwrap(), "\"global\"");
    }

    #[test]
    fn core_by_protocol_and_app_filter_maps() {
        let s: AdvancedSettings = serde_json::from_str(
            r#"{"coreByProtocol":{"vless":"xray","hysteria2":"sing-box"},
                "appFilter":{"com.x":"force-proxy"}}"#,
        )
        .unwrap();
        assert_eq!(s.core_by_protocol[&Protocol::Vless], CoreEngine::Xray);
        assert_eq!(
            s.core_by_protocol[&Protocol::Hysteria2],
            CoreEngine::SingBox
        );
        assert_eq!(s.app_filter["com.x"], AppFilterMode::ForceProxy);
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["appFilter"]["com.x"], "force-proxy");
    }

    #[test]
    fn default_state_has_base_group() {
        let st = default_app_state();
        assert_eq!(st.groups.len(), 1);
        assert_eq!(st.groups[0].id, "g-main");
        assert_eq!(st.groups[0].name, "Main");
        assert_eq!(st.active_id, None);
        // active_id is required+nullable → serializes as null; version omitted.
        let v = serde_json::to_value(&st).unwrap();
        assert!(v["activeId"].is_null());
        assert!(v.get("version").is_none());
        assert!(v["profiles"].as_array().unwrap().is_empty());
    }
}
