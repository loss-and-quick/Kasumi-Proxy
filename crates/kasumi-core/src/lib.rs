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
//! - [`share`] — share-link parse/build

pub mod config_shared;
pub mod contract;
pub mod core;
pub mod core_config;
pub mod enums;
pub mod migrate;
pub mod mixins;
pub mod profile;
pub mod share;
pub mod singbox_config;
pub mod state;
pub mod sub_apply;
pub mod uid;
pub mod xray_config;
