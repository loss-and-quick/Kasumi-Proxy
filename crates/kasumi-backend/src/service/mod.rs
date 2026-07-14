//! The `Service`: one owner of the data-path lifecycle, shared by both shells.
//!
//! It serializes lifecycle jobs through a single lock so a restart can't interleave
//! with a concurrent start/stop, drives the headless sub-updater, auto-starts on
//! boot, re-pins on uplink changes, and watchdogs a dead data-path. There is no
//! control socket — lifecycle commands are in-process calls. It also owns the
//! status/`subApplied` event stream both
//! transports subscribe to (desktop re-emits via Tauri, Android over WS).

mod lifecycle;
mod status;
mod watchers;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{Mutex, broadcast};

use kasumi_core::contract::PushFrame;
use kasumi_core::core_config::CoreConfig;
use kasumi_core::state::ProxyMode;

use crate::commands::{self, Command, CommandError, Response};
use crate::platform::Platform;
use crate::sub_update;

use self::lifecycle::LifecycleCmd;
use self::status::Connectivity;

const EVENT_CHANNEL_CAP: usize = 64;

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
