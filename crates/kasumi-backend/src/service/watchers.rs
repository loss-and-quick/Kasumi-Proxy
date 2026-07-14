//! The background loops: boot auto-start, network/resume re-pin, watchdog,
//! sub-updater and the 1 Hz status push.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kasumi_core::contract::{PushFrame, RunState, SubAppliedEvent};
use kasumi_core::state::AppState;

use crate::fsjson::read_json;
use crate::platform::StopDataPath;
use crate::sub_update;

use super::Service;
use super::lifecycle::LifecycleCmd;
use super::status::Connectivity;

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);

impl Service {
    /// Start the active profile once on boot, if `autoStart` allows. Caller holds
    /// the lifecycle lock.
    pub(super) async fn maybe_auto_start(&self) {
        if self.auto_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(state) = read_json::<AppState>(&self.platform.paths().app_state).await else {
            return;
        };
        if state.active_id.is_none() || !state.settings.auto_start {
            return;
        }
        let _ = self.run_lifecycle(LifecycleCmd::Start(None)).await;
    }

    /// Restart the data-path if it's up or coming up — re-pinning routing and rebuilding
    /// the core after the network or system changed under it. Returns whether it ran, so
    /// a caller can fall back to the boot auto-start. Takes the lifecycle lock itself.
    async fn restart_if_up(&self) -> bool {
        let _g = self.serialize.lock().await;
        let coming_up = self
            .platform
            .service_state()
            .await
            .ok()
            .map(|s| s.engine.is_some() || s.state == RunState::Connecting)
            .unwrap_or(false);
        if coming_up {
            let _ = self.run_lifecycle(LifecycleCmd::Restart(None)).await;
        }
        coming_up
    }

    pub(super) fn spawn_network_watch(self: &Arc<Self>) {
        let Some(mut rx) = self.platform.watch_network_change() else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                // Re-pin if the data-path is up; otherwise try the boot auto-start.
                if !this.restart_if_up().await {
                    let _g = this.serialize.lock().await;
                    this.maybe_auto_start().await;
                    drop(_g);
                }
                this.emit_status().await;
            }
        });
    }

    /// Restart the data-path each time the machine wakes from suspend/hibernate: a core
    /// left running across a sleep can hold stale routing/DNS state, and the uplink
    /// watcher doesn't fire when the default route survives the sleep. Driven by the
    /// platform's resume signal (logind `PrepareForSleep(false)` on Linux, a power
    /// notification on Windows); `None` where the platform has no such signal.
    pub(super) fn spawn_resume_watch(self: &Arc<Self>) {
        let Some(mut rx) = self.platform.watch_system_resume() else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                if this.restart_if_up().await {
                    this.emit_status().await;
                }
            }
        });
    }

    pub(super) fn spawn_watchdog(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(WATCHDOG_INTERVAL).await;
                let up = this
                    .platform
                    .service_state()
                    .await
                    .map(|s| s.engine.is_some())
                    .unwrap_or(false);
                if !up {
                    if this.set_connectivity(Connectivity::Unknown) {
                        this.emit_status().await;
                    }
                    continue;
                }
                // A dead data-path (core/tun2socks pid gone) is torn down so the UI
                // doesn't show a zombie "connected".
                if this.platform.data_path_healthy().await == Some(false) {
                    let _g = this.serialize.lock().await;
                    let _ = this.platform.stop_data_path(StopDataPath::default()).await;
                    drop(_g);
                    this.note_data_path_stopped();
                    this.set_connectivity(Connectivity::Unknown);
                    this.emit_status().await;
                    continue;
                }
                // Process is up: probe end-to-end connectivity (outside the lifecycle
                // lock — it can take seconds) and re-emit only when the verdict changes.
                let verdict = this.probe_connectivity().await;
                if this.set_connectivity(verdict) {
                    this.emit_status().await;
                }
            }
        });
    }

    pub(super) fn spawn_sub_updater(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(sub_update::TICK).await;
                let events = this.events.clone();
                let on_applied = move |info: SubAppliedEvent| {
                    let _ = events.send(PushFrame::SubApplied { value: info });
                };
                let mut attempts = this.sub_attempts.lock().await;
                sub_update::tick(
                    &*this.platform,
                    this.as_ref(),
                    &this.serialize,
                    &mut attempts,
                    &on_applied,
                )
                .await;
            }
        });
    }

    pub(super) fn spawn_status_push(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut last = String::new();
            loop {
                tokio::time::sleep(STATUS_INTERVAL).await;
                if let Some(status) = this.current_status().await
                    && let Ok(json) = serde_json::to_string(&status)
                    && json != last
                {
                    last = json;
                    let _ = this.events.send(PushFrame::Status { value: status });
                }
            }
        });
    }
}
