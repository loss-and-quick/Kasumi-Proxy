//! The lifecycle switch (start/stop/restart + OS-proxy alignment) and the
//! running-config baseline behind `pending_restart`.

use std::sync::atomic::Ordering;

use kasumi_core::core_config::{CoreConfig, MutationEffect, mutation_effect};
use kasumi_core::state::{AppState, DEFAULT_LOCAL_SOCKS_PORT, ProxyMode};

use crate::commands::{self, CommandError, Response};
use crate::fs::read_text;
use crate::lifecycle::resolve_and_write_config;
use crate::platform::StopDataPath;
use crate::sub_update::LifecycleControl;

use super::Service;

/// The lifecycle operations, run directly (no locking) by [`Service`]. Callers that
/// need serialization take the lock first.
#[derive(Debug, Clone)]
pub(super) enum LifecycleCmd {
    Start(Option<String>),
    Stop,
    Restart(Option<String>),
    ReloadAppFilter,
}

impl Service {
    /// Run a lifecycle command under the serializer, then emit the new status.
    pub(super) async fn serialized(&self, lc: LifecycleCmd) -> Result<Response, CommandError> {
        {
            let _g = self.serialize.lock().await;
            self.run_lifecycle(lc).await.map_err(CommandError)?;
        }
        self.emit_status().await;
        Ok(Response::Ok)
    }

    /// The lifecycle switch, run without the lock (the caller holds it).
    pub(super) async fn run_lifecycle(&self, cmd: LifecycleCmd) -> Result<(), String> {
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
    pub(super) fn note_data_path_stopped(&self) {
        *self.running_config.lock().unwrap() = None;
        self.pending_restart.store(false, Ordering::SeqCst);
    }

    /// After a settings mutation, decide what it means for the running data path:
    /// nothing (stopped, or the mutated state doesn't build), a live OS-proxy
    /// re-point (mode moved within the non-tun family, identical build), or a
    /// flip of `pending_restart`. Emits a status frame when the flag changes so
    /// clients react immediately instead of waiting for the next push tick.
    pub(super) async fn refresh_pending_restart(&self, state: &AppState) {
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
