//! What a data-path start brings up, decided once from the resolved core and the
//! settings. The shells execute a plan, and the state they record for the watchdog
//! and teardown is derived from it, so start and supervision read one decision.

use serde::{Deserialize, Serialize};

use crate::contract::RunState;
use crate::core::{owns_native_tun, resolve_tun};
use crate::data_path_state::{DataPathState, HelperSlot, TunSelection};
use crate::enums::{CoreEngine, TunEngine};
use crate::singbox_config::uid_of;
use crate::state::{
    AdvancedSettings, AppFilterMode, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_PAC_PORT,
    DEFAULT_LOCAL_SOCKS_PORT, ProxyMode, SingboxStack, force_socks_port,
};
use crate::tun::TunOptions;

/// How a host enforces the per-app filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRouting {
    /// By uid in the OS routing (Android `iptables --uid-owner`), with a second tun
    /// for force-proxy apps.
    PerUid,
    /// By program in the core's own routing (desktop process rules).
    PerProcess,
}

/// The facts about a host that shape its data path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostTraits {
    /// The non-tun proxy modes are honoured; without them every start runs a tun.
    pub proxy_modes: bool,
    pub app_routing: AppRouting,
    /// A sing-box tun stack the host requires whatever the setting says.
    pub pinned_singbox_stack: Option<SingboxStack>,
}

/// A host that honours every mode and pins nothing, for tests that only build configs.
#[cfg(test)]
pub(crate) const TEST_HOST: HostTraits = HostTraits {
    proxy_modes: true,
    app_routing: AppRouting::PerProcess,
    pinned_singbox_stack: None,
};

impl HostTraits {
    pub fn effective_mode(self, saved: ProxyMode) -> ProxyMode {
        if self.proxy_modes {
            saved
        } else {
            ProxyMode::Tun
        }
    }
}

/// An external tun→socks engine in front of the core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalTun {
    /// `SingboxTun` here is a sidecar sing-box, never the core's own tun.
    pub engine: TunEngine,
    pub opts: TunOptions,
    /// The sidecar sing-box's tun stack; the other engines ignore it.
    pub stack: SingboxStack,
    /// A second helper bridges the force-proxy tun.
    pub force_tun: bool,
}

/// The tun a data path runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TunPlan {
    /// proxy-only / system / pac: the core's local inbounds are the data path.
    None,
    /// The sing-box core owns `tun-in`, plus `tun-force` when `force_tun`.
    #[serde(rename_all = "camelCase")]
    Native {
        force_tun: bool,
    },
    External(ExternalTun),
}

/// The local listeners the core and the OS proxy use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPorts {
    pub socks: u16,
    pub http: u16,
    pub force: u16,
    pub pac: u16,
}

impl LocalPorts {
    pub fn from_settings(s: &AdvancedSettings) -> Self {
        let socks = s.local_socks_port.unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
        let http = s.local_http_port.unwrap_or(DEFAULT_LOCAL_HTTP_PORT);
        Self {
            socks,
            http,
            force: force_socks_port(socks, http),
            pac: s.local_pac_port.unwrap_or(DEFAULT_LOCAL_PAC_PORT),
        }
    }
}

/// Everything a start brings up, as one serializable value. Holds no paths: the
/// executor (possibly a privileged helper) resolves those itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataPathPlan {
    pub engine: CoreEngine,
    /// Already normalized for the host (see [`HostTraits::effective_mode`]).
    pub mode: ProxyMode,
    pub tun: TunPlan,
    pub ports: LocalPorts,
}

impl DataPathPlan {
    pub fn resolve(engine: CoreEngine, s: &AdvancedSettings, host: HostTraits) -> Self {
        let mode = host.effective_mode(s.proxy_mode);
        let tun_engine = resolve_tun(engine, s);
        let force_tun = host.app_routing == AppRouting::PerUid
            && s.app_filter
                .iter()
                .any(|(k, m)| *m == AppFilterMode::ForceProxy && uid_of(k).is_some());
        let tun = if mode != ProxyMode::Tun {
            TunPlan::None
        } else if owns_native_tun(engine, tun_engine) {
            TunPlan::Native { force_tun }
        } else {
            TunPlan::External(ExternalTun {
                engine: tun_engine,
                opts: s.tun_options(),
                stack: host.pinned_singbox_stack.unwrap_or(s.singbox_stack),
                force_tun,
            })
        };
        Self {
            engine,
            mode,
            tun,
            ports: LocalPorts::from_settings(s),
        }
    }

    pub fn external(&self) -> Option<&ExternalTun> {
        match &self.tun {
            TunPlan::External(ext) => Some(ext),
            _ => None,
        }
    }

    /// The record a start writes before bring-up; the watchdog and teardown read
    /// their expectations back from it.
    pub fn state(&self, run: RunState) -> DataPathState {
        let tun = match &self.tun {
            TunPlan::None => TunSelection::NoTun,
            TunPlan::Native { .. } => TunSelection::Engine(TunEngine::SingboxTun),
            TunPlan::External(ext) => TunSelection::Engine(ext.engine),
        };
        DataPathState {
            run,
            engine: Some(self.engine),
            tun,
            socks_port: self.ports.socks,
            force_tun: self.external().is_some_and(|e| e.force_tun),
            ..Default::default()
        }
    }

    /// The helper processes this plan brings up.
    pub fn helpers(&self) -> Vec<HelperSlot> {
        self.state(RunState::Connecting).helpers()
    }

    /// The HTTP port to point an OS proxy at: sing-box serves HTTP on its `mixed`
    /// socks inbound, xray on a separate `http-in`.
    pub fn os_proxy_http_port(&self) -> u16 {
        match self.engine {
            CoreEngine::SingBox => self.ports.socks,
            CoreEngine::Xray => self.ports.http,
        }
    }

    /// Whether the core accepts connections itself and so can see the program
    /// behind each; behind an external helper every connection comes from it.
    pub fn sees_processes(&self) -> bool {
        self.external().is_none()
    }

    /// Whether an app-filter edit applies to the running data path without a
    /// restart: sing-box bakes the filter into its config, xray's is OS routing.
    pub fn app_filter_live(&self) -> bool {
        self.engine == CoreEngine::Xray
    }

    /// What of the plan, beyond the core config itself, needs a restart to change.
    pub(crate) fn restart_key(&self) -> Option<&TunOptions> {
        self.external().map(|e| &e.opts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_path_state::TunSlot;

    const ANDROID: HostTraits = HostTraits {
        proxy_modes: false,
        app_routing: AppRouting::PerUid,
        pinned_singbox_stack: None,
    };
    const DESKTOP: HostTraits = HostTraits {
        proxy_modes: true,
        app_routing: AppRouting::PerProcess,
        pinned_singbox_stack: Some(SingboxStack::Gvisor),
    };

    fn settings(tun: TunEngine, mode: ProxyMode) -> AdvancedSettings {
        let mut s = AdvancedSettings {
            proxy_mode: mode,
            ..Default::default()
        };
        s.tun_by_core.insert(CoreEngine::Xray, tun);
        s.tun_by_core.insert(CoreEngine::SingBox, tun);
        s
    }

    #[test]
    fn only_singbox_on_its_own_tun_is_native() {
        let s = settings(TunEngine::SingboxTun, ProxyMode::Tun);
        let native = DataPathPlan::resolve(CoreEngine::SingBox, &s, ANDROID);
        assert_eq!(native.tun, TunPlan::Native { force_tun: false });
        let sidecar = DataPathPlan::resolve(CoreEngine::Xray, &s, ANDROID);
        assert_eq!(
            sidecar.external().map(|e| e.engine),
            Some(TunEngine::SingboxTun)
        );
        let s = settings(TunEngine::Hev, ProxyMode::Tun);
        let hev = DataPathPlan::resolve(CoreEngine::SingBox, &s, ANDROID);
        assert_eq!(hev.external().map(|e| e.engine), Some(TunEngine::Hev));
    }

    #[test]
    fn a_host_without_proxy_modes_always_runs_a_tun() {
        let s = settings(TunEngine::Tun2socks, ProxyMode::System);
        let android = DataPathPlan::resolve(CoreEngine::Xray, &s, ANDROID);
        assert_eq!(android.mode, ProxyMode::Tun);
        assert!(android.external().is_some());
        let desktop = DataPathPlan::resolve(CoreEngine::Xray, &s, DESKTOP);
        assert_eq!(desktop.mode, ProxyMode::System);
        assert_eq!(desktop.tun, TunPlan::None);
        assert_eq!(desktop.state(RunState::Connecting).tun, TunSelection::NoTun);
    }

    #[test]
    fn force_tun_needs_a_uid_entry_on_a_per_uid_host() {
        let mut s = settings(TunEngine::Tun2socks, ProxyMode::Tun);
        s.app_filter
            .insert("exe:/usr/bin/curl".into(), AppFilterMode::ForceProxy);
        let plan = DataPathPlan::resolve(CoreEngine::Xray, &s, ANDROID);
        assert!(!plan.external().unwrap().force_tun);
        s.app_filter
            .insert("org.game:10200".into(), AppFilterMode::ForceProxy);
        let plan = DataPathPlan::resolve(CoreEngine::Xray, &s, ANDROID);
        assert!(plan.external().unwrap().force_tun);
        let slots: Vec<_> = plan.helpers().iter().map(|h| h.slot).collect();
        assert_eq!(slots, [TunSlot::Main, TunSlot::Force]);
        // Desktop routes programs in the core, never through a second tun.
        let plan = DataPathPlan::resolve(CoreEngine::Xray, &s, DESKTOP);
        assert!(!plan.external().unwrap().force_tun);
    }

    #[test]
    fn a_pinned_stack_wins_over_the_setting() {
        let mut s = settings(TunEngine::SingboxTun, ProxyMode::Tun);
        s.singbox_stack = SingboxStack::System;
        let android = DataPathPlan::resolve(CoreEngine::Xray, &s, ANDROID);
        assert_eq!(android.external().unwrap().stack, SingboxStack::System);
        let desktop = DataPathPlan::resolve(CoreEngine::Xray, &s, DESKTOP);
        assert_eq!(desktop.external().unwrap().stack, SingboxStack::Gvisor);
    }

    #[test]
    fn os_proxy_http_follows_the_inbound_layout() {
        let s = AdvancedSettings {
            local_socks_port: Some(2000),
            local_http_port: Some(2002),
            ..Default::default()
        };
        let xray = DataPathPlan::resolve(CoreEngine::Xray, &s, DESKTOP);
        assert_eq!(xray.os_proxy_http_port(), 2002);
        assert_eq!(xray.ports.force, 2003);
        let sing_box = DataPathPlan::resolve(CoreEngine::SingBox, &s, DESKTOP);
        assert_eq!(sing_box.os_proxy_http_port(), 2000);
    }

    #[test]
    fn plan_round_trips() {
        let mut s = settings(TunEngine::Hev, ProxyMode::Tun);
        s.app_filter
            .insert("org.game:10200".into(), AppFilterMode::ForceProxy);
        let plan = DataPathPlan::resolve(CoreEngine::Xray, &s, ANDROID);
        let line = serde_json::to_string(&plan).unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(serde_json::from_str::<DataPathPlan>(&line).unwrap(), plan);
    }
}
