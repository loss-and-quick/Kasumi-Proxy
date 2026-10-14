//! The background loops: boot auto-start, network/resume re-pin, watchdog,
//! sub-updater and the 1 Hz status push.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use kasumi_core::contract::{AssetsUpdatedEvent, PushFrame, RunState, SubAppliedEvent};

use kasumi_log::{Area, ks_warn};

use crate::platform::StopDataPath;
use crate::{asset_update, sub_update, updater};

use super::Service;
use super::lifecycle::LifecycleCmd;
use super::status::Connectivity;

const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);
/// How often a healthy connection is re-checked over the network. The local
/// process check stays on the 5 s watchdog tick; this one sends a request through
/// the proxy, so it runs rarely — a fixed few-second rhythm of tiny requests to the
/// server is a traffic pattern of its own and keeps a phone's radio awake.
const PROBE_INTERVAL: Duration = Duration::from_secs(60);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);
/// How often the log files are trimmed to `settings.log_rotate_max_kb`. A phone can
/// run for days between app launches, and nothing else bounds a log that only this
/// process writes.
const TRIM_INTERVAL: Duration = Duration::from_secs(300);

impl Service {
    /// Start the active profile once on boot, if `autoStart` allows. Caller holds
    /// the lifecycle lock.
    pub(super) async fn maybe_auto_start(&self) {
        if self.auto_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(state) = crate::state::read_state_shell(&self.platform.paths().app_state).await
        else {
            return;
        };
        if state.active_id.is_none() || !state.settings.auto_start {
            return;
        }
        // A boot-time start that fails is invisible otherwise: nothing else runs at
        // this point, and the UI only ever sees "stopped".
        if let Err(e) = self.run_lifecycle(LifecycleCmd::Start(None)).await {
            ks_warn!(Area::Service, "auto-start failed: {e}");
        }
    }

    /// Restart the data-path if it's up or coming up — re-pinning routing and rebuilding
    /// the core after the network or system changed under it. Returns whether it ran, so
    /// a caller can fall back to the boot auto-start. Takes the lifecycle lock itself.
    async fn restart_if_up(&self) -> bool {
        let _g = self.serialize.lock().await;
        let coming_up = self.data_path_up_or_coming().await;
        if coming_up && let Err(e) = self.run_lifecycle(LifecycleCmd::Restart(None)).await {
            ks_warn!(Area::Service, "restart after a change failed: {e}");
        }
        coming_up
    }

    /// Whether the data-path is up or coming up.
    async fn data_path_up_or_coming(&self) -> bool {
        self.platform
            .service_state()
            .await
            .ok()
            .is_some_and(|s| s.engine.is_some() || s.state == RunState::Connecting)
    }

    pub(super) fn spawn_network_watch(self: &Arc<Self>) {
        let Some(mut rx) = self.platform.watch_network_change() else {
            return;
        };
        let this = Arc::clone(self);
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                // Rebuild a running data-path where the platform needs it; otherwise
                // a new network is the moment to try the boot auto-start.
                let plan = this
                    .running_config
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|r| r.config.plan.clone());
                let handled = if this.platform.uplink_change_restarts(plan.as_ref()) {
                    this.restart_if_up().await
                } else {
                    this.data_path_up_or_coming().await
                };
                if !handled {
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
            let mut last_probe = None;
            let mut last_offload_bypass = false;
            loop {
                tokio::time::sleep(WATCHDOG_INTERVAL).await;
                let state = this.platform.service_state().await.ok();
                let up = state.as_ref().is_some_and(|s| s.engine.is_some());
                // The platform raises this on its own schedule; push it when it flips.
                let offload_bypass = state.is_some_and(|s| s.tether_offload_bypass);
                if offload_bypass != last_offload_bypass {
                    last_offload_bypass = offload_bypass;
                    this.emit_status().await;
                }
                if !up {
                    if this.reset_connectivity() {
                        this.emit_status().await;
                    }
                    continue;
                }
                // A dead data-path (core/tun2socks pid gone) is torn down so the UI
                // doesn't show a zombie "connected".
                if this.platform.data_path_healthy().await == Some(false) {
                    let _g = this.serialize.lock().await;
                    // Teardown that fails leaves the zombie the watchdog is here to
                    // clear, and nothing else would say so.
                    if let Err(e) = this.platform.stop_data_path(StopDataPath::default()).await {
                        ks_warn!(
                            Area::Lifecycle,
                            "could not tear the dead data path down: {e}"
                        );
                    }
                    drop(_g);
                    this.note_data_path_stopped();
                    this.emit_status().await;
                    continue;
                }
                // Process is up: probe end-to-end connectivity (outside the lifecycle
                // lock — it can take seconds) and re-emit only when the verdict changes.
                // Probe at once for a fresh core, every tick while it can't reach the
                // internet (so recovery shows quickly), and every PROBE_INTERVAL once
                // it can. Nothing is sent when the user turned the check off.
                let check = crate::state::read_state_shell(&this.platform.paths().app_state)
                    .await
                    .is_none_or(|s| s.settings.connectivity_check);
                if !check {
                    continue;
                }
                let due = match this.connectivity() {
                    Connectivity::Unknown | Connectivity::Unreachable(_) => true,
                    Connectivity::Reachable { .. } => {
                        last_probe.is_none_or(|t: Instant| t.elapsed() >= PROBE_INTERVAL)
                    }
                };
                if !due {
                    continue;
                }
                last_probe = Some(Instant::now());
                if this.probe_and_store().await.1 {
                    this.emit_status().await;
                }
            }
        });
    }

    pub(super) fn spawn_sub_updater(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(updater::TICK).await;
                let events = this.events.clone();
                let on_applied = move |info: SubAppliedEvent| {
                    let _ = events.send(PushFrame::SubApplied { value: info });
                };
                let mut attempts = this.sub_attempts.lock().await;
                sub_update::tick(
                    &*this.platform,
                    this.as_ref(),
                    &this.serialize,
                    &this.sub_cookies,
                    &mut attempts,
                    &on_applied,
                )
                .await;
            }
        });
    }

    /// Re-fetch the geo assets on the shared updater cadence. Runs on its own task
    /// (and its own backoff map) so a slow multi-megabyte download never delays the
    /// subscription pass; both take the lifecycle lock only to write or restart.
    pub(super) fn spawn_asset_updater(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(updater::TICK).await;
                let events = this.events.clone();
                let on_updated = move |info: AssetsUpdatedEvent| {
                    let _ = events.send(PushFrame::AssetsUpdated { value: info });
                };
                let mut attempts = this.asset_attempts.lock().await;
                asset_update::tick(
                    &*this.platform,
                    this.as_ref(),
                    &this.serialize,
                    &mut attempts,
                    &on_updated,
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

    /// Trim the log files to the configured cap on a slow tick. `Command::Log` and
    /// the shell scripts do the same, but only when someone looks — a log nobody
    /// opens still has to stay inside its cap.
    pub(super) fn spawn_log_trim(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TRIM_INTERVAL).await;
                let Some(state) = crate::state::read_app_state(&*this.platform).await else {
                    continue;
                };
                let limit = u64::try_from(state.settings.log_rotate_max_kb).unwrap_or(0) * 1024;
                for target in crate::commands::LOG_TARGETS {
                    let path = this.platform.paths().log(target);
                    if let Err(e) = kasumi_log::rotate::trim_in_place(&path, limit) {
                        ks_warn!(Area::Sys, "could not trim {}: {e}", path.display());
                    }
                }
            }
        });
    }
}
