//! Status assembly: the status frame, the connectivity overlay, and the event
//! stream both transports subscribe to.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use kasumi_core::contract::{ConnectionProbe, FetchMode, PushFrame, RunState, ServiceStatus};
use kasumi_core::state::DEFAULT_DELAY_TEST_URL;

use crate::net::{FetchUrlOptions, fetch_url};
use kasumi_log::{Area, ks_debug, ks_warn};

use super::Service;

/// Result of the latest end-to-end connectivity probe (a fetch through the active
/// core's SOCKS). `Unknown` until the first probe lands after the core comes up.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) enum Connectivity {
    #[default]
    Unknown,
    /// Reached the test URL; the fetch's round trip in ms.
    Reachable {
        latency_ms: u64,
    },
    Unreachable(String),
}

/// A stored [`Connectivity`] and the profile whose core it measured. A profile
/// switch is saved before the restart that runs it, so the active profile can
/// briefly differ from the one the verdict describes.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct ProbeVerdict {
    profile_id: Option<String>,
    connectivity: Connectivity,
}

impl From<ProbeVerdict> for ConnectionProbe {
    fn from(v: ProbeVerdict) -> Self {
        Self {
            profile_id: v.profile_id,
            latency_ms: match v.connectivity {
                Connectivity::Reachable { latency_ms } => Some(latency_ms),
                _ => None,
            },
        }
    }
}

impl Service {
    /// Subscribe to the status / `subApplied` event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<PushFrame> {
        self.events.subscribe()
    }

    /// Build the full status frame (runtime facts + active id + running-core label).
    /// `None` when the platform's state probe fails. Both shells use it for the
    /// initial frame a client gets on connect.
    pub async fn current_status(&self) -> Option<ServiceStatus> {
        let mut service = match self.platform.service_state().await {
            Ok(service) => service,
            // The caller gets no frame at all, so a probe that keeps failing looks
            // like a quiet daemon rather than a broken one.
            Err(e) => {
                ks_warn!(Area::Platform, "service state unavailable: {e}");
                return None;
            }
        };
        let state = crate::state::read_state_shell(&self.platform.paths().app_state).await;
        let check = state.as_ref().is_none_or(|s| s.settings.connectivity_check);
        let active_id = state.and_then(|s| s.active_id);
        let mut latency_ms = None;
        // The platform reports process-truth (Connecting once the core is up). Refine
        // it with the latest connectivity probe of the active profile: a running core
        // that actually reaches the internet is Connected; one that can't is
        // NoInternet; before the first probe lands it stays Connecting. With the
        // check off there is no probe to wait for, so a running core counts as
        // Connected.
        if service.state == RunState::Connecting && service.engine.is_some() {
            if !check {
                service.state = RunState::Connected;
            } else {
                let verdict = self.connectivity.lock().unwrap().clone();
                // A verdict on another profile's core says nothing about this one.
                if verdict.profile_id == active_id {
                    match verdict.connectivity {
                        Connectivity::Reachable { latency_ms: ms } => {
                            service.state = RunState::Connected;
                            latency_ms = Some(ms);
                        }
                        Connectivity::Unreachable(reason) => {
                            service.state = RunState::NoInternet;
                            service.error = Some(reason);
                        }
                        Connectivity::Unknown => {}
                    }
                }
            }
        }
        let core = match service.engine {
            Some(kasumi_core::enums::CoreEngine::Xray) => self.cores.xray.clone(),
            Some(kasumi_core::enums::CoreEngine::SingBox) => self.cores.singbox.clone(),
            None => None,
        }
        .unwrap_or_default();
        Some(ServiceStatus {
            service,
            active_id,
            core,
            pending_restart: self.pending_restart.load(Ordering::SeqCst)
                || self.assets_stale.load(Ordering::SeqCst),
            latency_ms,
        })
    }

    pub(super) async fn emit_status(&self) {
        if let Some(status) = self.current_status().await {
            let _ = self.events.send(PushFrame::Status { value: status });
        }
    }

    /// One end-to-end connectivity probe through the active core's SOCKS — the same
    /// fetch a real client would do, so it tells whether the proxy actually reaches
    /// the internet (Connected) or only looks up (NoInternet). Engine-agnostic.
    pub(super) async fn probe_connectivity(&self) -> Connectivity {
        let proxy = match self.platform.proxy_status().await {
            Ok(p) if p.running => p,
            _ => return Connectivity::Unknown,
        };
        let url = crate::state::read_state_shell(&self.platform.paths().app_state)
            .await
            .and_then(|s| s.settings.delay_test_url)
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_DELAY_TEST_URL.to_owned());
        let t0 = Instant::now();
        match fetch_url(
            &url,
            FetchUrlOptions {
                mode: FetchMode::Proxy,
                proxy: Some(proxy),
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .await
        {
            Ok(_) => Connectivity::Reachable {
                latency_ms: t0.elapsed().as_millis() as u64,
            },
            Err(e) => {
                // The UI shows only the capped reason; the chain says why the probe
                // itself could not run, which is the part that needs the log.
                ks_debug!(Area::Net, "connectivity probe failed: {e:#}");
                // Root cause, capped — e.g. "connection timed out", "connection refused".
                let reason = e.to_string();
                let reason = reason.chars().take(120).collect::<String>();
                Connectivity::Unreachable(reason)
            }
        }
    }

    /// Probe now and store the verdict, unless the data path was stopped or
    /// restarted while the probe ran (its answer would describe the old core).
    /// Returns the verdict and whether the stored one changed, so a caller only
    /// re-emits status when there's something new.
    pub(super) async fn probe_and_store(&self) -> (ProbeVerdict, bool) {
        let generation = self.data_path_generation.load(Ordering::SeqCst);
        let verdict = ProbeVerdict {
            profile_id: self.probed_profile().await,
            connectivity: self.probe_connectivity().await,
        };
        let mut guard = self.connectivity.lock().unwrap();
        if self.data_path_generation.load(Ordering::SeqCst) != generation || *guard == verdict {
            return (verdict, false);
        }
        *guard = verdict.clone();
        (verdict, true)
    }

    /// The profile a probe started now measures: the one this process started the
    /// running core with, else (a core still coming up, or one that outlived the
    /// process that started it) the saved active one.
    async fn probed_profile(&self) -> Option<String> {
        let running = self
            .running_config
            .lock()
            .unwrap()
            .as_ref()
            .map(|r| r.profile_id.clone());
        match running {
            Some(id) => Some(id),
            None => crate::state::read_state_shell(&self.platform.paths().app_state)
                .await
                .and_then(|s| s.active_id),
        }
    }

    /// Forget the last verdict (the data path went down or is being replaced). Bumps
    /// the generation so a probe still in flight can't store a stale answer.
    pub(super) fn reset_connectivity(&self) -> bool {
        self.data_path_generation.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.connectivity.lock().unwrap();
        let changed = guard.connectivity != Connectivity::Unknown;
        *guard = ProbeVerdict::default();
        changed
    }

    /// Hand the stored verdict from `from` to `to`, a profile that runs the same core.
    pub(super) fn reassign_verdict(&self, from: &str, to: &str) {
        let mut verdict = self.connectivity.lock().unwrap();
        if verdict.profile_id.as_deref() == Some(from) {
            verdict.profile_id = Some(to.to_owned());
        }
    }

    pub(super) fn connectivity(&self) -> Connectivity {
        self.connectivity.lock().unwrap().connectivity.clone()
    }
}
