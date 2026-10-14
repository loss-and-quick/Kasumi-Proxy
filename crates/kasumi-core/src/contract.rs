//! Wire contract between the backend daemon and the UI bridge — the types and
//! constants both sides agree on but that aren't persisted app state. Field
//! names and string values are fixed by the WS/JSON protocol the UI speaks.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::enums::CoreEngine;
use crate::profile::Protocol;

/// Canonical log-file identifiers (backend log paths ↔ UI log picker).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::EnumIter, specta::Type,
)]
#[serde(rename_all = "lowercase")]
pub enum LogTarget {
    Daemon,
    Xray,
    Singbox,
    #[serde(rename = "tun-engine")]
    TunEngine,
}

/// One profile's core resolution (the `resolveCores` reply): the engine the
/// backend will actually run it on, and the engine a capability pins it to
/// (`None` when the profile is freely selectable). The UI renders these instead
/// of re-implementing the resolution matrix (`core::resolve_core`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct CoreResolution {
    pub resolved: CoreEngine,
    pub forced: Option<CoreEngine>,
    /// Remarks of the chain hop that pins `forced`, when a hop rather than the
    /// profile itself needs that core.
    #[serde(default)]
    pub forced_by_hop: Option<String>,
    /// Set when no core can run the profile as configured; it can't start.
    #[serde(default)]
    pub conflict: Option<CoreConflict>,
    /// Whether that core can tell which program opened a connection in the current
    /// proxy mode — what the desktop per-app filter needs
    /// (`app_process::sees_processes`).
    #[serde(default)]
    pub sees_processes: bool,
    /// The cores that can't build this profile as the target of another
    /// profile's routing rule, and why (`core::rule_target_fallback`). On such a
    /// core the rule's traffic goes through the active proxy instead.
    #[serde(default)]
    pub rule_target_fallback: BTreeMap<CoreEngine, TargetFallback>,
    /// Settings of this profile that only xray can build and that stop it
    /// connecting when sing-box builds it (`core::xray_only_settings`): sing-box
    /// leaves them out of its config without saying so.
    #[serde(default)]
    pub xray_only_settings: Vec<XrayOnlySetting>,
}

/// A setting sing-box can't carry, left out of the config it builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum XrayOnlySetting {
    VlessEncryption,
    /// The `xtls-rprx-vision-udp443` flow, which sing-box has no name for.
    VisionUdp443Flow,
    /// The mKCP transport.
    Kcp,
    /// The XHTTP transport.
    Xhttp,
    /// A gRPC service name starting with `/`, which xray reads as the whole path.
    GrpcServicePath,
    /// The name the server certificate is verified against, when it differs from the SNI.
    VerifyPeerCertName,
}

/// Why a core can't build a profile as a routing-rule target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TargetFallback {
    /// A custom config is a whole core config of its own, not one outbound that
    /// fits into another profile's.
    CustomConfig,
    /// Its protocol, transport or TLS settings run only on sing-box.
    SingBoxOnly,
    /// No core can run the profile at all.
    CantStart { conflict: CoreConflict },
}

/// Why no core can run a profile (`core::core_conflict`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CoreConflict {
    /// TLS without a certificate check or a pinned certificate, on a profile only
    /// xray runs: xray has dropped `allowInsecure`, so only a pin gets past its check.
    UnpinnedInsecureTls,
    /// The same for a custom Xray config: some `tlsSettings` of it sets
    /// `allowInsecure` without a `pinnedPeerCertSha256`.
    CustomAllowInsecure,
    /// A proxy chain that no single core can build: every hop is an outbound of the
    /// one config, and these two profiles of it each run on a different core only.
    ChainCoreConflict {
        /// Remarks of the profile that runs only on xray.
        xray: String,
        /// Remarks of the profile that runs only on sing-box.
        #[serde(rename = "singBox")]
        sing_box: String,
    },
}

/// A chain hop that can't be dialled through because its core requirement
/// conflicts with the profile's chain (`core::chain_conflicts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct HopConflict {
    pub id: String,
    pub conflict: CoreConflict,
}

impl std::fmt::Display for CoreConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnpinnedInsecureTls => f.write_str(
                "this profile runs only on xray, which no longer skips certificate checks: \
                 pin the server certificate (SHA-256) or turn off \"Allow insecure\"",
            ),
            Self::CustomAllowInsecure => f.write_str(
                "this config sets \"allowInsecure\", which xray no longer accepts: \
                 add \"pinnedPeerCertSha256\" beside it or remove it",
            ),
            Self::ChainCoreConflict { xray, sing_box } => write!(
                f,
                "proxy chain needs two cores: \"{xray}\" runs only on xray, \"{sing_box}\" only on sing-box",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum TestKind {
    TcpPing,
    RealPing,
    Speed,
}

/// How a network job (subscription fetch, asset download) reaches the net.
/// Reused as a subscription's `updateMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum FetchMode {
    #[default]
    Auto,
    Proxy,
    Direct,
}

/// Data-path run states. The truthful distinction the UI needs is `Connected`
/// (the core is up AND a probe through it actually reached the internet) vs
/// `NoInternet` (the core+tun are up but the probe fails — dead upstream / handshake
/// failure). `Connecting` covers both the lifecycle bring-up and the window after
/// the core is up but before the first connectivity probe lands. `Failed`/`NoInternet`
/// carry their reason in [`ServiceState::error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub enum RunState {
    Stopped,
    Connecting,
    Connected,
    NoInternet,
    Failed,
}

/// Runtime facts about the data-path (`status` RPC / `Platform::service_state`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ServiceState {
    pub state: RunState,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub uptime_sec: u64,
    /// Engine actually running (PID truth), or `null` when nothing is up.
    pub engine: Option<CoreEngine>,
    /// Android: hardware offload still forwards a tethering session that was
    /// running before "proxy tethering" turned it off, so some tethered traffic
    /// bypasses the proxy until tethering is restarted. Always `false` elsewhere.
    #[serde(default)]
    pub tether_offload_bypass: bool,
}

/// Full status frame pushed to clients: runtime facts + active profile + core label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    #[serde(flatten)]
    pub service: ServiceState,
    pub active_id: Option<String>,
    /// e.g. `"Xray 25.5.16"`.
    pub core: String,
    /// The running data path was started from settings that have since changed;
    /// one restart applies them all. Always `false` while nothing is running.
    #[serde(default)]
    pub pending_restart: bool,
    /// Round trip of the latest successful connectivity probe through the running
    /// core of `active_id`, in ms; `null` until one lands, while the check is off,
    /// or while a saved switch to `active_id` is not running yet.
    #[serde(default)]
    pub latency_ms: Option<u64>,
}

/// Reply to the on-demand connectivity probe. It names the profile whose core
/// answered, which can differ from the active one while a saved switch has not
/// been restarted into yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProbe {
    pub profile_id: Option<String>,
    /// Round trip in ms; `null` when unreachable or nothing is running.
    pub latency_ms: Option<u64>,
}

/// Reply to the `capabilities` RPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// UI runtime: `"ksu-js"` | `"web"` | `"mock"` (and, on desktop, `"tauri"`).
    pub bridge: String,
    /// Installed Xray version, empty when not installed.
    pub xray_version: String,
    /// Installed sing-box version, empty when not installed.
    pub singbox_version: String,
    /// Whether the host can route through a TUN device.
    pub tun: bool,
    /// Protocols this host's cores can't run (Android: naive, which the bundled
    /// sing-box is compiled without). Absent from an older daemon: none.
    #[serde(default)]
    pub unavailable_protocols: Vec<Protocol>,
}

/// Daemon push: it fetched & applied a subscription headlessly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct SubAppliedEvent {
    #[serde(rename = "subId")]
    pub sub_id: String,
    pub remarks: String,
    pub count: u32,
}

/// Daemon push: it refreshed geo assets headlessly. `restart_pending` says the
/// running core still has the old data and picks the new up on its next start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct AssetsUpdatedEvent {
    pub remarks: Vec<String>,
    pub restart_pending: bool,
}

/// One WS RPC call (client → daemon).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    pub id: i64,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub payload: Option<String>,
}

/// Reply to one [`RpcRequest`] (daemon → client), correlated by `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: i64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// Server-initiated frames (no `id`): live status and headless sub-apply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "event")]
pub enum PushFrame {
    #[serde(rename = "status")]
    Status { value: ServiceStatus },
    #[serde(rename = "subApplied")]
    SubApplied { value: SubAppliedEvent },
    #[serde(rename = "assetsUpdated")]
    AssetsUpdated { value: AssetsUpdatedEvent },
}

/// WS bootstrap the daemon writes (and serves via the `wsInfo` command).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct WsInfo {
    pub port: u16,
    pub token: String,
}

/// First local port probed for on-demand test cores. One shared pool for every
/// diagnostic (real-ping and speed alike): the lease registry hands each concurrent
/// test a non-overlapping block, so a profile being speed-tested and another being
/// pinged never collide regardless of test type.
pub const TEST_PORT_BASE: u16 = 19000;
/// Consecutive free ports each test core reserves, so concurrent runs hand out
/// non-colliding blocks.
pub const TEST_PORT_SPAN: u16 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_json_shape() {
        let status = ServiceStatus {
            service: ServiceState {
                state: RunState::Connected,
                error: None,
                upload_bytes: 10,
                download_bytes: 20,
                uptime_sec: 5,
                engine: Some(CoreEngine::Xray),
                tether_offload_bypass: false,
            },
            active_id: Some("p1".into()),
            core: "Xray 25.5.16".into(),
            pending_restart: true,
            latency_ms: Some(42),
        };
        let v: serde_json::Value = serde_json::to_value(&status).unwrap();
        // Flattened ServiceState fields + camelCase keys, error omitted when None.
        assert_eq!(v["state"], "connected");
        assert_eq!(v["uploadBytes"], 10);
        assert_eq!(v["downloadBytes"], 20);
        assert_eq!(v["uptimeSec"], 5);
        assert_eq!(v["engine"], "xray");
        assert_eq!(v["activeId"], "p1");
        assert_eq!(v["core"], "Xray 25.5.16");
        assert_eq!(v["pendingRestart"], true);
        assert_eq!(v["latencyMs"], 42);
        assert!(v.get("error").is_none());
        // Round-trips.
        assert_eq!(serde_json::from_value::<ServiceStatus>(v).unwrap(), status);
    }

    #[test]
    fn pending_restart_defaults_false_when_absent() {
        // Frames from senders that predate the field must still parse.
        let v = serde_json::json!({
            "state": "connected",
            "uploadBytes": 0,
            "downloadBytes": 0,
            "uptimeSec": 0,
            "engine": "xray",
            "activeId": null,
            "core": "",
        });
        let status = serde_json::from_value::<ServiceStatus>(v).unwrap();
        assert!(!status.pending_restart);
        assert!(status.latency_ms.is_none());
    }

    #[test]
    fn engine_null_when_stopped() {
        let s = ServiceState {
            state: RunState::Stopped,
            error: None,
            upload_bytes: 0,
            download_bytes: 0,
            uptime_sec: 0,
            engine: None,
            tether_offload_bypass: false,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert!(v["engine"].is_null());
    }

    #[test]
    fn push_frame_tagged_on_event() {
        let f = PushFrame::SubApplied {
            value: SubAppliedEvent {
                sub_id: "s1".into(),
                remarks: "Home".into(),
                count: 3,
            },
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["event"], "subApplied");
        assert_eq!(v["value"]["subId"], "s1");
        assert_eq!(v["value"]["count"], 3);
    }

    #[test]
    fn log_target_values() {
        assert_eq!(
            serde_json::to_string(&LogTarget::Singbox).unwrap(),
            "\"singbox\""
        );
        assert_eq!(
            serde_json::to_string(&LogTarget::TunEngine).unwrap(),
            "\"tun-engine\""
        );
    }

    #[test]
    fn test_kind_values() {
        assert_eq!(
            serde_json::to_string(&TestKind::TcpPing).unwrap(),
            "\"tcpPing\""
        );
        assert_eq!(
            serde_json::to_string(&TestKind::RealPing).unwrap(),
            "\"realPing\""
        );
        assert_eq!(
            serde_json::to_string(&TestKind::Speed).unwrap(),
            "\"speed\""
        );
    }
}
