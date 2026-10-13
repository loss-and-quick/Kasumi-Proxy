//! The single persisted record of the running data-path, written by the data-path
//! owner (the desktop privilege helper, the Android daemon) and read back by the same
//! process for status, the watchdog and teardown.

use serde::{Deserialize, Serialize};

use crate::contract::RunState;
use crate::core::owns_native_tun;
use crate::enums::{CoreEngine, TunEngine};
use crate::state::{DEFAULT_LOCAL_SOCKS_PORT, force_socks_port};
use crate::tun::{
    TUN_IPV4, TUN_IPV4_CIDR, TUN_IPV6, TUN_IPV6_CIDR, TUN2_IPV4, TUN2_IPV4_CIDR, TUN2_IPV6,
    TUN2_IPV6_CIDR,
};

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
    /// The core's http and `force-in` ports; 0 in a record from before they were kept.
    #[serde(default)]
    pub http_port: u16,
    #[serde(default)]
    pub force_port: u16,
    /// A second external helper bridges the force-proxy tun. Absent in documents
    /// written before the field existed, which never ran one.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub force_tun: bool,
    /// Epoch seconds the core process came up; `Some` marks the old `running` state
    /// (vs bring-up `connecting`) and drives uptime. Every non-running write clears it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub started_at: Option<u64>,
}

/// Which of a data path's tuns an external helper bridges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunSlot {
    Main,
    /// The force-proxy apps' tun.
    Force,
}

impl TunSlot {
    pub fn ipv4(self) -> &'static str {
        match self {
            Self::Main => TUN_IPV4,
            Self::Force => TUN2_IPV4,
        }
    }

    pub fn ipv4_cidr(self) -> &'static str {
        match self {
            Self::Main => TUN_IPV4_CIDR,
            Self::Force => TUN2_IPV4_CIDR,
        }
    }

    pub fn ipv6(self) -> &'static str {
        match self {
            Self::Main => TUN_IPV6,
            Self::Force => TUN2_IPV6,
        }
    }

    pub fn ipv6_cidr(self) -> &'static str {
        match self {
            Self::Main => TUN_IPV6_CIDR,
            Self::Force => TUN2_IPV6_CIDR,
        }
    }
}

/// One external helper process a data path runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperSlot {
    pub engine: TunEngine,
    pub slot: TunSlot,
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
            http_port: 0,
            force_port: 0,
            force_tun: false,
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
                let native = self.engine.is_some_and(|e| owns_native_tun(e, tun));
                (!native).then_some(tun)
            }
        }
    }

    /// The `(socks, http, force)` ports the recorded data path listens on. A record
    /// without them falls back to the default socks port and `http_fallback`.
    pub fn listening_ports(&self, http_fallback: u16) -> (u16, u16, u16) {
        let or = |port: u16, fallback: u16| if port == 0 { fallback } else { port };
        let socks = or(self.socks_port, DEFAULT_LOCAL_SOCKS_PORT);
        let http = or(self.http_port, http_fallback);
        (
            socks,
            http,
            or(self.force_port, force_socks_port(socks, http)),
        )
    }

    /// The helper processes this data path runs; start brings up exactly these and
    /// the watchdog and teardown look for exactly these.
    pub fn helpers(&self) -> Vec<HelperSlot> {
        let Some(engine) = self.external_tun() else {
            return Vec::new();
        };
        let mut slots = vec![HelperSlot {
            engine,
            slot: TunSlot::Main,
        }];
        if self.force_tun {
            slots.push(HelperSlot {
                engine,
                slot: TunSlot::Force,
            });
        }
        slots
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
            http_port: 10809,
            force_port: 10810,
            force_tun: true,
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

    #[test]
    fn a_document_without_force_tun_still_reads() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v.as_object_mut().unwrap().remove("force_tun");
        let doc = DataPathState::from_json(v.to_string().as_bytes()).unwrap();
        assert!(!doc.force_tun);
    }

    #[test]
    fn each_slot_carries_its_own_addresses() {
        for slot in [TunSlot::Main, TunSlot::Force] {
            assert!(slot.ipv4_cidr().starts_with(&format!("{}/", slot.ipv4())));
            assert!(slot.ipv6_cidr().starts_with(&format!("{}/", slot.ipv6())));
        }
        assert_ne!(TunSlot::Main.ipv4(), TunSlot::Force.ipv4());
    }

    #[test]
    fn listening_ports_fall_back_for_an_older_record() {
        assert_eq!(sample().listening_ports(1), (10808, 10809, 10810));
        let mut v = serde_json::to_value(sample()).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("http_port");
        obj.remove("force_port");
        let old = DataPathState::from_json(v.to_string().as_bytes()).unwrap();
        // http on socks + 2 pushes force-in to socks + 3.
        assert_eq!(old.listening_ports(10810), (10808, 10810, 10811));
    }

    #[test]
    fn helpers_follow_the_external_engine() {
        let mut doc = sample();
        let slots = |d: &DataPathState| {
            d.helpers()
                .iter()
                .map(|h| (h.engine, h.slot))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            slots(&doc),
            [
                (TunEngine::Tun2socks, TunSlot::Main),
                (TunEngine::Tun2socks, TunSlot::Force)
            ]
        );
        doc.force_tun = false;
        assert_eq!(slots(&doc), [(TunEngine::Tun2socks, TunSlot::Main)]);
        // A native tun has no helper, whatever the force flag says.
        doc.engine = Some(CoreEngine::SingBox);
        doc.tun = TunSelection::Engine(TunEngine::SingboxTun);
        doc.force_tun = true;
        assert!(doc.helpers().is_empty());
    }
}
