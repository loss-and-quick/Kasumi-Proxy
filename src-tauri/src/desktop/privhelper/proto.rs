//! Wire protocol for the privileged desktop data-path helper.
//!
//! The desktop splits privilege: a small root helper owns the data-path — the
//! cores, tun2socks and `ip` routing all need `CAP_NET_ADMIN` (the cores create
//! the tun themselves) — while the unprivileged GUI drives it over a unix socket.
//! The boundary is the privileged subset of the [`Platform`] trait; everything
//! pure or read-only (config tuning, the netlink uplink watch, core-path lookups,
//! asset conversion) stays in the GUI with no privilege.
//!
//! State travels back inside replies, never through root-owned files, so the GUI
//! never has to read what root wrote (no shared-ownership/permission dance).
//!
//! Framing is one JSON object per line (newline-delimited): the GUI writes a
//! [`PrivRequest`], the helper writes exactly one [`PrivReply`], correlated
//! positionally over the connection.
//!
//! [`Platform`]: kasumi_backend::platform::Platform

use serde::{Deserialize, Serialize};

use kasumi_core::contract::ServiceState;
use kasumi_core::enums::CoreEngine;

/// A privileged operation the GUI asks the helper to perform. Mirrors the
/// privilege-needing methods of `Platform`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PrivRequest {
    /// Readiness probe — the GUI waits for a `Pong` after spawning the helper.
    Ping,
    /// One-time boot setup (run dirs, seed lifecycle state).
    BootInit,
    /// Bring the data-path up for `engine`, routing through the local SOCKS.
    StartDataPath { engine: CoreEngine, socks_port: u16 },
    /// Tear the data-path down. Idempotent.
    StopDataPath { keep_service_state: bool },
    /// Current data-path status (liveness + byte counters).
    ServiceState,
    /// Whether a core is live and the SOCKS port to reach it on.
    ProxyStatus,
    /// Whether every data-path process is still alive (drives the watchdog).
    DataPathHealthy,
}

/// The helper's reply to one [`PrivRequest`]. `ProxyStatus` is flattened to
/// primitives because its `Platform` struct isn't serializable; the client rebuilds
/// it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum PrivReply {
    Pong,
    /// An operation with no payload succeeded (`BootInit` / `StartDataPath` /
    /// `StopDataPath`).
    Ok,
    State(ServiceState),
    Proxy {
        running: bool,
        socks_port: u16,
        http_port: u16,
    },
    Healthy {
        healthy: Option<bool>,
    },
    /// The operation failed; carries the reason (a stringified `anyhow::Error`).
    Err {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_core::contract::RunState;

    /// One line in, one value out — every request/reply variant survives the JSON
    /// framing intact (the transport relies on this round-trip).
    fn req_roundtrip(r: &PrivRequest) {
        let line = serde_json::to_string(r).unwrap();
        assert!(!line.contains('\n'), "framing assumes single-line JSON");
        assert_eq!(&serde_json::from_str::<PrivRequest>(&line).unwrap(), r);
    }

    fn reply_roundtrip(r: &PrivReply) {
        let line = serde_json::to_string(r).unwrap();
        assert!(!line.contains('\n'), "framing assumes single-line JSON");
        assert_eq!(&serde_json::from_str::<PrivReply>(&line).unwrap(), r);
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            PrivRequest::Ping,
            PrivRequest::BootInit,
            PrivRequest::StartDataPath {
                engine: CoreEngine::Xray,
                socks_port: 10808,
            },
            PrivRequest::StartDataPath {
                engine: CoreEngine::SingBox,
                socks_port: 1080,
            },
            PrivRequest::StopDataPath {
                keep_service_state: true,
            },
            PrivRequest::ServiceState,
            PrivRequest::ProxyStatus,
            PrivRequest::DataPathHealthy,
        ] {
            req_roundtrip(&r);
        }
    }

    #[test]
    fn replies_round_trip() {
        for r in [
            PrivReply::Pong,
            PrivReply::Ok,
            PrivReply::State(ServiceState {
                state: RunState::Connecting,
                error: None,
                upload_bytes: 1,
                download_bytes: 2,
                uptime_sec: 3,
                engine: Some(CoreEngine::SingBox),
            }),
            PrivReply::Proxy {
                running: true,
                socks_port: 10808,
                http_port: 10809,
            },
            PrivReply::Healthy {
                healthy: Some(false),
            },
            PrivReply::Err {
                message: "boom".into(),
            },
        ] {
            reply_roundtrip(&r);
        }
    }

    /// The tag keys (`op` / `reply`) are distinct so a reply can't be misread as a
    /// request on a shared decoder, and snake_case is stable across renames.
    #[test]
    fn tags_are_snake_case() {
        let line = serde_json::to_string(&PrivRequest::DataPathHealthy).unwrap();
        assert_eq!(line, r#"{"op":"data_path_healthy"}"#);
        let line = serde_json::to_string(&PrivReply::Ok).unwrap();
        assert_eq!(line, r#"{"reply":"ok"}"#);
    }
}
