//! Status assembly: the status frame, the connectivity overlay, and the event
//! stream both transports subscribe to.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

use kasumi_core::contract::{FetchMode, PushFrame, RunState, ServiceStatus};
use kasumi_core::state::{AppState, DEFAULT_DELAY_TEST_URL};

use crate::fsjson::read_json;
use crate::net::{FetchUrlOptions, fetch_url};

use super::Service;

/// Result of the latest end-to-end connectivity probe (a fetch through the active
/// core's SOCKS). `Unknown` until the first probe lands after the core comes up.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Connectivity {
    Unknown,
    /// Reached the test URL; the fetch's round trip in ms.
    Reachable {
        latency_ms: u64,
    },
    Unreachable(String),
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
        let mut service = self.platform.service_state().await.ok()?;
        let state = read_json::<AppState>(&self.platform.paths().app_state).await;
        let check = state.as_ref().is_none_or(|s| s.settings.connectivity_check);
        let mut latency_ms = None;
        // The platform reports process-truth (Connecting once the core is up). Refine
        // it with the latest connectivity probe: a running core that actually reaches
        // the internet is Connected; one that can't is NoInternet; before the first
        // probe lands it stays Connecting. With the check off there is no probe to
        // wait for, so a running core counts as Connected.
        if service.state == RunState::Connecting && service.engine.is_some() {
            if !check {
                service.state = RunState::Connected;
            } else {
                match &*self.connectivity.lock().unwrap() {
                    Connectivity::Reachable { latency_ms: ms } => {
                        service.state = RunState::Connected;
                        latency_ms = Some(*ms);
                    }
                    Connectivity::Unreachable(reason) => {
                        service.state = RunState::NoInternet;
                        service.error = Some(reason.clone());
                    }
                    Connectivity::Unknown => {}
                }
            }
        }
        let active_id = state.and_then(|s| s.active_id);
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
            pending_restart: self.pending_restart.load(Ordering::SeqCst),
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
        let url = read_json::<AppState>(&self.platform.paths().app_state)
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
    pub(super) async fn probe_and_store(&self) -> (Connectivity, bool) {
        let generation = self.data_path_generation.load(Ordering::SeqCst);
        let verdict = self.probe_connectivity().await;
        let mut guard = self.connectivity.lock().unwrap();
        if self.data_path_generation.load(Ordering::SeqCst) != generation || *guard == verdict {
            return (verdict, false);
        }
        *guard = verdict.clone();
        (verdict, true)
    }

    /// Forget the last verdict (the data path went down or is being replaced). Bumps
    /// the generation so a probe still in flight can't store a stale answer.
    pub(super) fn reset_connectivity(&self) -> bool {
        self.data_path_generation.fetch_add(1, Ordering::SeqCst);
        let mut guard = self.connectivity.lock().unwrap();
        let changed = *guard != Connectivity::Unknown;
        *guard = Connectivity::Unknown;
        changed
    }

    pub(super) fn connectivity(&self) -> Connectivity {
        self.connectivity.lock().unwrap().clone()
    }
}
