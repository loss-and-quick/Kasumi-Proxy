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
use kasumi_core::data_path_plan::DataPathPlan;
use kasumi_core::enums::CoreEngine;

/// Version of this protocol, reported in the helper's `Pong`. Bump it whenever a
/// request or reply changes in a way the other side can't read, so a helper left
/// over from another build is refused at the handshake instead of failing later on
/// a request it doesn't know.
pub const PROTOCOL_VERSION: u32 = 2;

/// A privileged operation the GUI asks the helper to perform. Mirrors the
/// privilege-needing methods of `Platform`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PrivRequest {
    /// Readiness probe and handshake — the GUI waits for a `Pong` after spawning the
    /// helper and checks its protocol version.
    Ping,
    /// One-time boot setup (run dirs, seed lifecycle state).
    BootInit,
    /// Bring up the data path the GUI planned. The helper executes the plan as is,
    /// so start and the state it records come from one decision.
    StartDataPath { plan: DataPathPlan },
    /// Tear the data-path down. Idempotent.
    StopDataPath { keep_service_state: bool },
    /// Current data-path status (liveness + byte counters).
    ServiceState,
    /// Whether a core is live and the SOCKS port to reach it on.
    ProxyStatus,
    /// Whether every data-path process is still alive (drives the watchdog).
    DataPathHealthy,
    /// Spawn a throwaway test core (as root, so it can bind the uplink and escape an
    /// active tun) from a GUI-written config, logging to `log_path`. Returns a handle
    /// to kill it with.
    SpawnTestCore {
        engine: CoreEngine,
        cfg_path: String,
        log_path: String,
    },
    /// Kill a test core spawned by `SpawnTestCore`. Idempotent (a handle the helper's
    /// orphan-sweep already reaped is silently ignored).
    KillTestCore { handle: u64 },
    /// Time a TCP connect to `host:port` with the socket bound to the physical
    /// uplink (`SO_BINDTODEVICE` needs `CAP_NET_RAW`), so an active tun can't
    /// capture the probe.
    TcpPing {
        host: String,
        port: u16,
        timeout_ms: u64,
    },
}

/// The helper's reply to one [`PrivRequest`]. `ProxyStatus` is flattened to
/// primitives because its `Platform` struct isn't serializable; the client rebuilds
/// it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum PrivReply {
    /// `protocol` is [`PROTOCOL_VERSION`]; a helper from before the handshake
    /// existed sends none.
    Pong {
        #[serde(default)]
        protocol: Option<u32>,
    },
    /// An operation with no payload succeeded (`BootInit` / `StartDataPath` /
    /// `StopDataPath`).
    Ok,
    State(ServiceState),
    Proxy {
        running: bool,
        socks_port: u16,
        http_port: u16,
        /// Absent from a helper that derived it from the http port.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        force_port: Option<u16>,
    },
    Healthy {
        healthy: Option<bool>,
    },
    /// The handle of a freshly spawned test core (to pass back to `KillTestCore`).
    TestCoreSpawned {
        handle: u64,
    },
    /// A `TcpPing` result in ms; `None` when the server didn't answer.
    Latency {
        ms: Option<u64>,
    },
    /// An operation failed; carries the reason (a stringified `anyhow::Error`).
    Err {
        message: String,
    },
    /// The data-path belongs to another GUI, in Windows session `owner` (see
    /// [`super::session`]); sent instead of any reply, then the helper hangs up.
    OtherSession {
        owner: Option<u32>,
    },
}

/// The helper answered the handshake with another protocol version, or with none
/// (a helper from before the handshake). It is a different build of the app, so
/// retrying can't help: the helper has to be restarted or reinstalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperOutdated {
    pub helper: Option<u32>,
}

impl std::fmt::Display for HelperOutdated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let helper = self
            .helper
            .map_or_else(|| "none".to_owned(), |v| v.to_string());
        write!(
            f,
            "the privileged helper speaks protocol {helper}, this app {PROTOCOL_VERSION}; \
             restart or reinstall Kasumi Proxy"
        )
    }
}

impl std::error::Error for HelperOutdated {}

/// Accept the helper's reply to `Ping` only from a helper on this protocol.
pub fn check_handshake(reply: &PrivReply) -> anyhow::Result<()> {
    match reply {
        PrivReply::Pong {
            protocol: Some(PROTOCOL_VERSION),
        } => Ok(()),
        PrivReply::Pong { protocol } => Err(HelperOutdated { helper: *protocol }.into()),
        other => anyhow::bail!("helper did not answer Ping: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_core::contract::RunState;
    use kasumi_core::data_path_plan::{AppRouting, HostTraits};
    use kasumi_core::enums::TunEngine;
    use kasumi_core::state::{AdvancedSettings, ProxyMode, SingboxStack};

    #[test]
    fn pong_carries_the_protocol_version() {
        let pong = PrivReply::Pong {
            protocol: Some(PROTOCOL_VERSION),
        };
        assert_eq!(
            serde_json::to_string(&pong).unwrap(),
            format!(r#"{{"reply":"pong","protocol":{PROTOCOL_VERSION}}}"#)
        );
        assert!(check_handshake(&pong).is_ok());
    }

    // A helper from before the handshake answers a bare pong: that is a mismatch.
    #[test]
    fn a_pong_without_a_version_is_an_outdated_helper() {
        let old: PrivReply = serde_json::from_str(r#"{"reply":"pong"}"#).unwrap();
        assert_eq!(old, PrivReply::Pong { protocol: None });
        let err = check_handshake(&old).unwrap_err();
        assert_eq!(
            err.downcast_ref::<HelperOutdated>(),
            Some(&HelperOutdated { helper: None })
        );
    }

    #[test]
    fn another_protocol_version_is_refused() {
        for v in [PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1] {
            let err = check_handshake(&PrivReply::Pong { protocol: Some(v) }).unwrap_err();
            assert_eq!(
                err.downcast_ref::<HelperOutdated>(),
                Some(&HelperOutdated { helper: Some(v) })
            );
        }
        let err = check_handshake(&PrivReply::Ok).unwrap_err();
        assert!(err.downcast_ref::<HelperOutdated>().is_none());
    }

    // An older GUI, whose `Pong` has no fields, still reads the new reply.
    #[test]
    fn an_older_gui_still_reads_the_versioned_pong() {
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(tag = "reply", rename_all = "snake_case")]
        enum OldReply {
            Pong,
        }
        let line = serde_json::to_string(&PrivReply::Pong {
            protocol: Some(PROTOCOL_VERSION),
        })
        .unwrap();
        assert_eq!(
            serde_json::from_str::<OldReply>(&line).unwrap(),
            OldReply::Pong
        );
    }

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

    fn plan(engine: CoreEngine, tun: TunEngine, mode: ProxyMode) -> DataPathPlan {
        let mut s = AdvancedSettings {
            proxy_mode: mode,
            ..Default::default()
        };
        s.tun_by_core.insert(engine, tun);
        let host = HostTraits {
            proxy_modes: true,
            app_routing: AppRouting::PerProcess,
            pinned_singbox_stack: Some(SingboxStack::Gvisor),
        };
        DataPathPlan::resolve(engine, &s, host)
    }

    #[test]
    fn requests_round_trip() {
        for r in [
            PrivRequest::Ping,
            PrivRequest::BootInit,
            PrivRequest::StartDataPath {
                plan: plan(CoreEngine::Xray, TunEngine::Hev, ProxyMode::Tun),
            },
            PrivRequest::StartDataPath {
                plan: plan(
                    CoreEngine::SingBox,
                    TunEngine::SingboxTun,
                    ProxyMode::ProxyOnly,
                ),
            },
            PrivRequest::StopDataPath {
                keep_service_state: true,
            },
            PrivRequest::ServiceState,
            PrivRequest::ProxyStatus,
            PrivRequest::DataPathHealthy,
            PrivRequest::SpawnTestCore {
                engine: CoreEngine::Xray,
                cfg_path: "/run/test-43210.json".into(),
                log_path: "/run/test-43210.log".into(),
            },
            PrivRequest::KillTestCore { handle: 7 },
            PrivRequest::TcpPing {
                host: "e.example".into(),
                port: 443,
                timeout_ms: 3000,
            },
        ] {
            req_roundtrip(&r);
        }
    }

    #[test]
    fn replies_round_trip() {
        for r in [
            PrivReply::Pong {
                protocol: Some(PROTOCOL_VERSION),
            },
            PrivReply::Ok,
            PrivReply::State(ServiceState {
                state: RunState::Connecting,
                error: None,
                upload_bytes: 1,
                download_bytes: 2,
                uptime_sec: 3,
                engine: Some(CoreEngine::SingBox),
                tether_offload_bypass: false,
            }),
            PrivReply::Proxy {
                running: true,
                socks_port: 10808,
                http_port: 10809,
                force_port: Some(10810),
            },
            PrivReply::Healthy {
                healthy: Some(false),
            },
            PrivReply::TestCoreSpawned { handle: 7 },
            PrivReply::Latency { ms: Some(12) },
            PrivReply::Latency { ms: None },
            PrivReply::Err {
                message: "boom".into(),
            },
            PrivReply::OtherSession { owner: Some(2) },
            PrivReply::OtherSession { owner: None },
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
