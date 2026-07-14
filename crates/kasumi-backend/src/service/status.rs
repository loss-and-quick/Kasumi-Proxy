//! Status assembly: the status frame, the connectivity overlay, and the event
//! stream both transports subscribe to.

use std::sync::atomic::Ordering;
use std::time::Duration;

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
    Reachable,
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
        // The platform reports process-truth (Connecting once the core is up). Refine
        // it with the latest connectivity probe: a running core that actually reaches
        // the internet is Connected; one that can't is NoInternet; before the first
        // probe lands it stays Connecting.
        if service.state == RunState::Connecting && service.engine.is_some() {
            match &*self.connectivity.lock().unwrap() {
                Connectivity::Reachable => service.state = RunState::Connected,
                Connectivity::Unreachable(reason) => {
                    service.state = RunState::NoInternet;
                    service.error = Some(reason.clone());
                }
                Connectivity::Unknown => {}
            }
        }
        let active_id = read_json::<AppState>(&self.platform.paths().app_state)
            .await
            .and_then(|s| s.active_id);
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
            Ok(_) => Connectivity::Reachable,
            Err(e) => {
                // Root cause, capped — e.g. "connection timed out", "connection refused".
                let reason = e.to_string();
                let reason = reason.chars().take(120).collect::<String>();
                Connectivity::Unreachable(reason)
            }
        }
    }

    /// Store the connectivity verdict; returns whether it changed (so a caller only
    /// re-emits status when there's something new).
    pub(super) fn set_connectivity(&self, c: Connectivity) -> bool {
        let mut guard = self.connectivity.lock().unwrap();
        if *guard != c {
            *guard = c;
            true
        } else {
            false
        }
    }
}
