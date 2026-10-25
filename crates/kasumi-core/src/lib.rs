// The `serde_json::json!` macro in the profile fixtures expands deeply (a profile
// has ~50 flat keys); lift the default 128 recursion limit for those tests.
#![recursion_limit = "512"]

//! Kasumi domain core.
//!
//! The neutral, IO-free domain logic shared by every shell: profile/state types
//! (serde + `specta::Type`), share-link parse/build, the xray/sing-box config
//! builders, subscription apply/dedup and constants. The config builders are
//! pinned byte-for-byte against committed reference fixtures (compared as
//! `serde_json::Value`, so key order is irrelevant).
//!
//! Modules:
//! - [`contract`] — daemon↔UI wire types + test-port constants
//! - [`enums`] — engine/transport/TLS value sets
//! - [`mixins`] — shared field groups (meta/endpoint/transport/tls)
//! - [`profile`] — the 13-protocol `Profile` discriminated union
//! - [`state`] — groups/subscriptions/rules/assets + settings/AppState
//! - [`route`] — rule blocks and the route each profile runs with
//! - [`share`] — share-link parse/build
//! - [`sub_ingest`] — subscription responses to profiles and provider meta
//! - [`sub_policy`] — which provider meta is applied to a subscription, and how
//! - [`sub_changes`] — provider changes that wait for the user's consent
//! - [`request_identity`] — the identity a subscription fetch sends, built by happ-sub
//! - [`custom_sanitize`] — provider Xray JSON reduced to an allowlist
//! - [`custom_target`] — which outbound a provider config sends traffic to by default
//! - [`singbox_import`] — provider sing-box JSON decomposed into typed profiles
//! - [`import_input`] — pasted subscription URLs, `happ://` links and share links

pub mod app_process;
pub mod asset;
pub mod chain;
pub mod config_shared;
pub mod contract;
pub mod core;
pub mod core_config;
pub mod custom_sanitize;
pub mod custom_target;
pub mod data_path_plan;
pub mod data_path_state;
pub mod enums;
pub mod hev_config;
pub mod import_input;
pub mod migrate;
pub mod mixins;
pub mod mutate;
pub mod normalize;
pub mod outbound_bind;
pub mod profile;
pub mod provider_graph;
pub mod request_identity;
pub mod route;
pub mod share;
pub mod singbox_config;
pub mod singbox_import;
pub mod state;
pub mod sub_apply;
pub mod sub_changes;
pub mod sub_ingest;
pub mod sub_meta_types;
pub mod sub_policy;
pub mod tun;
pub mod tun2socks_config;
pub mod uid;
pub mod xray_config;
