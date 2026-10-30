//! The `Service`: one owner of the data-path lifecycle, shared by both shells.
//!
//! It serializes lifecycle jobs through a single lock so a restart can't interleave
//! with a concurrent start/stop, drives the headless sub- and asset-updaters, auto-starts on
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
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{Mutex, broadcast};

use kasumi_core::contract::PushFrame;
use kasumi_core::mutate::{Backup, MutationIntent};

use crate::commands::{self, BackupRestored, Command, CommandError, Response};
use crate::platform::Platform;
use crate::sub_cookies::SubCookies;
use crate::updater::LifecycleControl;
use crate::{asset_update, sub_update};

use self::lifecycle::{LifecycleCmd, RunningPath};
use self::status::ProbeVerdict;

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
    /// Per-asset last fetch attempt (ms), for the asset updater's backoff.
    asset_attempts: Mutex<HashMap<String, i64>>,
    auto_started: AtomicBool,
    /// Latest connectivity-probe result; the watchdog refreshes it, `current_status`
    /// overlays it onto a process-up state to tell Connected from NoInternet.
    connectivity: StdMutex<ProbeVerdict>,
    /// Bumped each time the data path stops or is replaced, so a probe that was in
    /// flight across the change drops its (now stale) verdict.
    data_path_generation: AtomicU64,
    /// A connectivity probe is running. It runs on its own task so the watchdog never
    /// waits on it; this keeps the next tick from starting a second probe.
    probe_in_flight: AtomicBool,
    /// Numbers each probe as it starts, and the number of the newest one whose verdict
    /// was stored. An explicit `ProbeConnection` can run alongside the watchdog's, and
    /// with a long timeout the one that started first can finish last: its answer is
    /// older, so it must not replace a verdict a later-started probe already gave.
    probe_seq: AtomicU64,
    stored_probe_seq: AtomicU64,
    /// The exact post-tune build, proxy mode and profile the running data path was
    /// started with — the baseline settings mutations are diffed against. `None` while
    /// stopped. Deliberately in-memory (not the on-disk config): the start path
    /// may tune the written file further, so a disk diff would never settle.
    running_config: StdMutex<Option<RunningPath>>,
    /// Whether the running data path no longer matches the saved settings (one
    /// restart applies them). Recomputed on mutations and lifecycle edges only;
    /// `current_status` just reports it.
    pending_restart: AtomicBool,
    /// Geo data the running core loaded at start changed on disk since; reported
    /// as a pending restart until the next start or stop.
    assets_stale: AtomicBool,
    /// Cookies providers set, shared by every subscription fetch and nothing else.
    sub_cookies: Arc<SubCookies>,
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
            asset_attempts: Mutex::new(HashMap::new()),
            auto_started: AtomicBool::new(false),
            connectivity: StdMutex::new(ProbeVerdict::default()),
            data_path_generation: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            probe_seq: AtomicU64::new(0),
            stored_probe_seq: AtomicU64::new(0),
            running_config: StdMutex::new(None),
            pending_restart: AtomicBool::new(false),
            assets_stale: AtomicBool::new(false),
            sub_cookies: Arc::default(),
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
            Command::ImportBackup { backup, mode } => {
                let _g = self.state_write.lock().await;
                let Backup {
                    state: incoming,
                    skipped_profiles,
                } = *backup;
                let intent = MutationIntent::ImportBackup {
                    incoming: Box::new(incoming),
                    mode,
                };
                let state = commands::run_mutation(&*self.platform, &intent).await?;
                self.refresh_pending_restart(&state).await;
                Ok(Response::BackupRestored(Box::new(BackupRestored {
                    state,
                    skipped_profiles,
                })))
            }
            Command::ApplySubscription { sub_id } => {
                let state = sub_update::update_subscription(
                    &*self.platform,
                    self,
                    &self.serialize,
                    &self.sub_cookies,
                    &sub_id,
                )
                .await
                .map_err(CommandError)?;
                self.emit_status().await;
                Ok(Response::State(Box::new(state)))
            }
            Command::DownloadAsset {
                filename,
                url,
                mode,
            } => {
                let body = asset_update::fetch_asset(&*self.platform, &filename, &url, mode)
                    .await
                    .map_err(CommandError)?;
                // As on the background update: the running core keeps the old data
                // until its next start, decided under the lifecycle lock with the write.
                let _g = self.serialize.lock().await;
                let changed = asset_update::apply_asset(&*self.platform, &filename, &body)
                    .await
                    .map_err(CommandError)?;
                if changed && asset_update::core_running(&*self.platform).await {
                    self.note_assets_changed().await;
                }
                Ok(Response::Ok)
            }
            Command::Status => Ok(Response::Status(
                self.current_status()
                    .await
                    .ok_or_else(|| CommandError("service state unavailable".into()))?
                    .service,
            )),
            Command::ProbeConnection => {
                // An explicit check through the running core — also when the
                // background check is off.
                let (verdict, changed) = self.probe_and_store().await;
                if changed {
                    self.emit_status().await;
                }
                Ok(Response::Probe(verdict.into()))
            }
            other => commands::dispatch(&*self.platform, other).await,
        }
    }

    /// Spawn the daemon loops: auto-start, network re-pin, watchdog, the sub- and
    /// asset-updaters and the 1 Hz status push. Both shells call this after construction.
    pub fn spawn_background(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            if let Some(state) = crate::state::read_app_state(&*this.platform).await {
                crate::jobs::sweep_orphan_test_logs(&*this.platform, &state).await;
            }
        });

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
        self.spawn_asset_updater();
        self.spawn_status_push();
        self.spawn_log_trim();
    }
}
