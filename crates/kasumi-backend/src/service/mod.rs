//! The `Service`: one owner of the data-path lifecycle, shared by both shells.
//!
//! It serializes lifecycle jobs through a single lock so a restart can't interleave
//! with a concurrent start/stop, drives the headless sub-updater, auto-starts on
//! boot, re-pins on uplink changes, and watchdogs a dead data-path. There is no
//! control socket — lifecycle commands are in-process calls. It also owns the
//! status/`subApplied` event stream both
//! transports subscribe to (desktop re-emits via Tauri, Android over WS).

mod status;
mod watchers;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{Mutex, broadcast};

use kasumi_core::contract::PushFrame;
use kasumi_core::core_config::{CoreConfig, MutationEffect, mutation_effect};
use kasumi_core::state::{AppState, DEFAULT_LOCAL_SOCKS_PORT, ProxyMode};

use crate::commands::{self, Command, CommandError, Response};
use crate::fs::read_text;
use crate::lifecycle::resolve_and_write_config;
use crate::platform::{Platform, StopDataPath};
use crate::sub_update::{self, LifecycleControl};

use self::status::Connectivity;

const EVENT_CHANNEL_CAP: usize = 64;

/// The lifecycle operations, run directly (no locking) by [`Service`]. Callers that
/// need serialization take the lock first.
#[derive(Debug, Clone)]
enum LifecycleCmd {
    Start(Option<String>),
    Stop,
    Restart(Option<String>),
    ReloadAppFilter,
}

pub struct Service {
    platform: Arc<dyn Platform>,
    /// The single in-flight lifecycle chain; held across a start/stop/restart.
    serialize: Mutex<()>,
    /// Serializes `Mutate` writes so two concurrent edits (both transports dispatch
    /// each command on its own task) can't read-modify-write over each other.
    state_write: Mutex<()>,
    events: broadcast::Sender<PushFrame>,
    /// Installed core version labels, probed once at construction.
    cores: crate::platform::InstalledCores,
    /// Per-subscription last fetch attempt (ms), for the updater's backoff.
    sub_attempts: Mutex<HashMap<String, i64>>,
    auto_started: AtomicBool,
    /// Latest connectivity-probe result; the watchdog refreshes it, `current_status`
    /// overlays it onto a process-up state to tell Connected from NoInternet.
    connectivity: StdMutex<Connectivity>,
    /// The exact post-tune build + proxy mode the running data path was started
    /// with — the baseline settings mutations are diffed against. `None` while
    /// stopped. Deliberately in-memory (not the on-disk config): the start path
    /// may tune the written file further, so a disk diff would never settle.
    running_config: StdMutex<Option<(CoreConfig, ProxyMode)>>,
    /// Whether the running data path no longer matches the saved settings (one
    /// restart applies them). Recomputed on mutations and lifecycle edges only;
    /// `current_status` just reports it.
    pending_restart: AtomicBool,
}

impl Service {
    /// Build a service over `platform`, probing core versions once for status labels.
    pub async fn new(platform: Arc<dyn Platform>) -> Arc<Self> {
        let cores = platform
            .capabilities()
            .await
            .map(|c| c.cores)
            .unwrap_or_default();
        let (events, _) = broadcast::channel(EVENT_CHANNEL_CAP);
        Arc::new(Self {
            platform,
            serialize: Mutex::new(()),
            state_write: Mutex::new(()),
            events,
            cores,
            sub_attempts: Mutex::new(HashMap::new()),
            auto_started: AtomicBool::new(false),
            connectivity: StdMutex::new(Connectivity::Unknown),
            running_config: StdMutex::new(None),
            pending_restart: AtomicBool::new(false),
        })
    }

    pub fn platform(&self) -> &dyn Platform {
        &*self.platform
    }

    /// Run one command. Lifecycle commands go through the serialized chain; every
    /// other command is the stateless dispatch.
    pub async fn dispatch(&self, cmd: Command) -> Result<Response, CommandError> {
        match cmd {
            Command::Start { profile_id } => self.serialized(LifecycleCmd::Start(profile_id)).await,
            Command::Stop => self.serialized(LifecycleCmd::Stop).await,
            Command::Restart { profile_id } => {
                self.serialized(LifecycleCmd::Restart(profile_id)).await
            }
            Command::ReloadAppFilter => self.serialized(LifecycleCmd::ReloadAppFilter).await,
            Command::Mutate { intent } => {
                // Hold the state-write lock across the whole read-modify-write so
                // concurrent edits serialize into one consistent result.
                let _g = self.state_write.lock().await;
                let state = commands::run_mutation(&*self.platform, &intent).await?;
                // A mutation never restarts the data path; instead compare what
                // runs against what the new state would start (still under the
                // lock so a concurrent edit can't interleave its own recompute).
                self.refresh_pending_restart(&state).await;
                Ok(Response::State(Box::new(state)))
            }
            Command::ApplySubscription { sub_id } => {
                let state = sub_update::update_subscription(
                    &*self.platform,
                    self,
                    &self.serialize,
                    &sub_id,
                )
                .await
                .map_err(CommandError)?;
                self.emit_status().await;
                Ok(Response::State(Box::new(state)))
            }
            other => commands::dispatch(&*self.platform, other).await,
        }
    }

    /// Run a lifecycle command under the serializer, then emit the new status.
    async fn serialized(&self, lc: LifecycleCmd) -> Result<Response, CommandError> {
        {
            let _g = self.serialize.lock().await;
            self.run_lifecycle(lc).await.map_err(CommandError)?;
        }
        self.emit_status().await;
        Ok(Response::Ok)
    }

    /// The lifecycle switch, run without the lock (the caller holds it).
    async fn run_lifecycle(&self, cmd: LifecycleCmd) -> Result<(), String> {
        match cmd {
            LifecycleCmd::Start(id) | LifecycleCmd::Restart(id) => {
                self.platform
                    .stop_data_path(StopDataPath {
                        keep_service_state: true,
                    })
                    .await
                    .map_err(|e| e.to_string())?;
                let (opts, built) = resolve_and_write_config(&*self.platform, id.as_deref())
                    .await
                    .map_err(|e| e.0)?;
                let (mode, engine, socks_port) = (opts.mode, opts.engine, opts.socks_port);
                if let Err(e) = self.platform.start_data_path(opts).await {
                    // A failed bring-up must not leave a previously-set OS proxy
                    // pointing at a dead port.
                    self.platform.clear_os_proxy().await;
                    self.note_data_path_stopped();
                    return Err(e.to_string());
                }
                // With the data-path up, align the OS proxy with the mode (set for
                // system/pac, cleared otherwise — covers mode switches).
                self.platform.set_os_proxy(mode, engine, socks_port).await;
                self.note_data_path_started(built, mode);
                Ok(())
            }
            LifecycleCmd::Stop => {
                // A stopped core must never leave the OS pointed at a dead port.
                self.platform.clear_os_proxy().await;
                self.note_data_path_stopped();
                self.platform
                    .stop_data_path(StopDataPath::default())
                    .await
                    .map_err(|e| e.to_string())
            }
            LifecycleCmd::ReloadAppFilter => {
                // xray reloads per-uid rules live; sing-box bakes them into the
                // config and needs a full restart.
                let engine = read_text(&self.platform.paths().engine_file)
                    .await
                    .map(|s| s.trim().to_owned())
                    .unwrap_or_default();
                if engine == "sing-box" {
                    self.platform
                        .stop_data_path(StopDataPath {
                            keep_service_state: true,
                        })
                        .await
                        .map_err(|e| e.to_string())?;
                    let (opts, built) = resolve_and_write_config(&*self.platform, None)
                        .await
                        .map_err(|e| e.0)?;
                    let mode = opts.mode;
                    match self.platform.start_data_path(opts).await {
                        Ok(()) => {
                            self.note_data_path_started(built, mode);
                            Ok(())
                        }
                        Err(e) => {
                            self.note_data_path_stopped();
                            Err(e.to_string())
                        }
                    }
                } else if let Some(f) = self.platform.app_filter() {
                    f.reload_app_filter().await.map_err(|e| e.to_string())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Record a successful data-path start: the given build + mode become the
    /// baseline mutations are diffed against, and nothing is pending anymore.
    fn note_data_path_started(&self, built: CoreConfig, mode: ProxyMode) {
        *self.running_config.lock().unwrap() = Some((built, mode));
        self.pending_restart.store(false, Ordering::SeqCst);
    }

    /// Drop the running-config baseline: with nothing running there is nothing
    /// that could be stale, so the pending flag clears too.
    fn note_data_path_stopped(&self) {
        *self.running_config.lock().unwrap() = None;
        self.pending_restart.store(false, Ordering::SeqCst);
    }

    /// After a settings mutation, decide what it means for the running data path:
    /// nothing (stopped, or the mutated state doesn't build), a live OS-proxy
    /// re-point (mode moved within the non-tun family, identical build), or a
    /// flip of `pending_restart`. Emits a status frame when the flag changes so
    /// clients react immediately instead of waiting for the next push tick.
    async fn refresh_pending_restart(&self, state: &AppState) {
        // Clone the baseline out so no std lock is held across the build below.
        let Some((running_cfg, running_mode)) = self.running_config.lock().unwrap().clone() else {
            return;
        };
        let Some(active_id) = state.active_id.as_deref() else {
            return;
        };
        // A state that can't build (e.g. the active profile was just removed) says
        // nothing about the running path — leave the flag as it is.
        let Ok(next_cfg) = commands::build_profile_config(&*self.platform, active_id).await else {
            return;
        };
        // Same normalization as the start path: no proxy-mode support → tun.
        let next_mode = if self.platform.supports_proxy_modes() {
            state.settings.proxy_mode
        } else {
            ProxyMode::Tun
        };
        match mutation_effect(&running_cfg, running_mode, &next_cfg, next_mode) {
            MutationEffect::LiveModeSwitch(mode) => {
                let socks_port = state
                    .settings
                    .local_socks_port
                    .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
                self.platform
                    .set_os_proxy(mode, next_cfg.engine, socks_port)
                    .await;
                if let Some(running) = self.running_config.lock().unwrap().as_mut() {
                    running.1 = mode;
                }
            }
            MutationEffect::SetPending(pending) => {
                if self.pending_restart.swap(pending, Ordering::SeqCst) != pending {
                    self.emit_status().await;
                }
            }
        }
    }

    /// Spawn the daemon loops: auto-start, network re-pin, watchdog, sub-updater and
    /// the 1 Hz status push. Both shells call this after construction.
    pub fn spawn_background(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            {
                let _g = this.serialize.lock().await;
                this.maybe_auto_start().await;
            }
            this.emit_status().await;
        });

        self.spawn_network_watch();
        self.spawn_resume_watch();
        self.spawn_watchdog();
        self.spawn_sub_updater();
        self.spawn_status_push();
    }
}

#[async_trait::async_trait]
impl LifecycleControl for Service {
    async fn start(&self, profile_id: Option<String>) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::Start(profile_id)).await
    }
    async fn stop(&self) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::Stop).await
    }
    async fn restart(&self, profile_id: Option<String>) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::Restart(profile_id)).await
    }
    async fn reload_app_filter(&self) -> Result<(), String> {
        self.run_lifecycle(LifecycleCmd::ReloadAppFilter).await
    }
}
