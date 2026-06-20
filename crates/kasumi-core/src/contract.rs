//! Wire contract between the backend daemon and the UI bridge — the types and
//! constants both sides agree on but that aren't persisted app state. Field
//! names and string values are fixed by the WS/JSON protocol the UI speaks.

use serde::{Deserialize, Serialize};

use crate::enums::CoreEngine;

/// Canonical log-file identifiers (backend log paths ↔ UI log picker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum LogTarget {
    Daemon,
    Xray,
    Singbox,
    Tun2socks,
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
}

/// Reply to the `capabilities` RPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// UI runtime: `"ksu-js"` | `"web"` | `"mock"` (and, on desktop, `"tauri"`).
    pub bridge: String,
    /// Xray version.
    pub core: String,
    pub singbox_version: String,
    pub curl: bool,
    pub tun: bool,
}

/// Daemon push: it fetched & applied a subscription headlessly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
pub struct SubAppliedEvent {
    #[serde(rename = "subId")]
    pub sub_id: String,
    pub remarks: String,
    pub count: u32,
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
            },
            active_id: Some("p1".into()),
            core: "Xray 25.5.16".into(),
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
        assert!(v.get("error").is_none());
        // Round-trips.
        assert_eq!(serde_json::from_value::<ServiceStatus>(v).unwrap(), status);
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
            serde_json::to_string(&LogTarget::Tun2socks).unwrap(),
            "\"tun2socks\""
        );
    }
}
