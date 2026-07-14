//! The single persisted record of the running data-path, written by the data-path
//! owner (the desktop privilege helper, the Android daemon) and read back by the same
//! process for status, the watchdog and teardown.

use serde::{Deserialize, Serialize};

use crate::contract::RunState;
use crate::enums::{CoreEngine, TunEngine};

/// The TUN a running data-path uses. `NoTun` (proxy-only/system/pac modes) is a first
/// class value, not an absent marker — so "no tun" and "no data-path known" never
/// collapse together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunSelection {
    Engine(TunEngine),
    NoTun,
}

/// Runtime facts about the active data-path. A read that is missing, corrupt or
/// carries a stale [`DataPathState::VERSION`] is treated as absent — meaning "no
/// data-path known" (the same state a fresh boot leaves), never a partial guess.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataPathState {
    /// Bumped on any shape change; a read whose version differs is treated as absent.
    pub version: u32,
    pub run: RunState,
    /// The `failed:<reason>` string packing, replaced by a typed field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub failure_reason: Option<String>,
    pub engine: Option<CoreEngine>,
    pub tun: TunSelection,
    pub socks_port: u16,
    /// Epoch seconds the core process came up; `Some` marks the old `running` state
    /// (vs bring-up `connecting`) and drives uptime. Every non-running write clears it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub started_at: Option<u64>,
}

impl Default for DataPathState {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            run: RunState::Stopped,
            failure_reason: None,
            engine: None,
            tun: TunSelection::NoTun,
            socks_port: 0,
            started_at: None,
        }
    }
}

impl DataPathState {
    pub const VERSION: u32 = 1;

    /// Parse a stored document, or `None` if it is corrupt or carries another version.
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        let doc: Self = serde_json::from_slice(bytes).ok()?;
        (doc.version == Self::VERSION).then_some(doc)
    }

    /// Serialize for an atomic write.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The external TUN helper engine this data-path expects, or `None` when the core
    /// owns its TUN natively (native sing-box) or there is no TUN. A lookup, not a
    /// heuristic: the helper expectation is fully determined by `tun` + `engine`.
    pub fn external_tun(&self) -> Option<TunEngine> {
        match self.tun {
            TunSelection::NoTun => None,
            TunSelection::Engine(tun) => {
                let native =
                    self.engine == Some(CoreEngine::SingBox) && tun == TunEngine::SingboxTun;
                (!native).then_some(tun)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DataPathState {
        DataPathState {
            version: DataPathState::VERSION,
            run: RunState::Connecting,
            failure_reason: None,
            engine: Some(CoreEngine::Xray),
            tun: TunSelection::Engine(TunEngine::Tun2socks),
            socks_port: 10808,
            started_at: Some(1_700_000_000),
        }
    }

    #[test]
    fn round_trips() {
        let doc = sample();
        assert_eq!(
            DataPathState::from_json(doc.to_json().as_bytes()),
            Some(doc)
        );
    }

    #[test]
    fn tun_selection_wire_shape() {
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&sample()).unwrap()).unwrap();
        assert_eq!(v["tun"], serde_json::json!({ "engine": "tun2socks" }));
        let no_tun = serde_json::to_value(TunSelection::NoTun).unwrap();
        assert_eq!(no_tun, serde_json::json!("no-tun"));
    }

    #[test]
    fn wrong_version_reads_as_absent() {
        let mut doc = sample();
        doc.version = DataPathState::VERSION + 1;
        assert_eq!(DataPathState::from_json(doc.to_json().as_bytes()), None);
    }

    #[test]
    fn corrupt_reads_as_absent() {
        assert_eq!(DataPathState::from_json(b"{ not json"), None);
        assert_eq!(DataPathState::from_json(b""), None);
    }

    #[test]
    fn external_tun_is_a_lookup() {
        let mut doc = sample();
        // External engine → its helper, whatever the core.
        doc.tun = TunSelection::Engine(TunEngine::Hev);
        doc.engine = Some(CoreEngine::SingBox);
        assert_eq!(doc.external_tun(), Some(TunEngine::Hev));
        // SingboxTun is native only under the sing-box core.
        doc.tun = TunSelection::Engine(TunEngine::SingboxTun);
        assert_eq!(doc.external_tun(), None);
        doc.engine = Some(CoreEngine::Xray);
        assert_eq!(doc.external_tun(), Some(TunEngine::SingboxTun));
        // No tun → no helper.
        doc.tun = TunSelection::NoTun;
        assert_eq!(doc.external_tun(), None);
    }

    #[test]
    fn failure_and_started_at_omitted_when_none() {
        let doc = DataPathState {
            run: RunState::Stopped,
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::from_str(&doc.to_json()).unwrap();
        assert!(v.get("failureReason").is_none() && v.get("failure_reason").is_none());
        assert!(v.get("startedAt").is_none() && v.get("started_at").is_none());
    }
}
