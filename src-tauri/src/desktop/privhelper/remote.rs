//! `RemotePlatform`: the GUI's [`Platform`], privilege-separated.
//!
//! It wraps a local [`DesktopPlatform`] for everything unprivileged (path lookups,
//! config tuning, core-version probes, the netlink uplink watch, on-demand test
//! cores, asset conversion) and forwards only the privileged data-path methods to
//! the root helper over [`Client`]. The split mirrors the file-domain split in
//! `paths`: the GUI owns `datadir`, the helper owns `run_dir`, and data-path state
//! comes back in RPC replies rather than through root-owned files.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    AppFilterCapability, BackendPaths, Engine, Platform, PlatformCapabilities, StopDataPath,
    TestCore,
};
use kasumi_core::contract::ServiceState;
use kasumi_core::data_path_plan::{DataPathPlan, HostTraits};

use super::client::Client;
use super::proto::{PrivReply, PrivRequest};
use crate::desktop::DesktopPlatform;
use kasumi_log::{Area, ks_warn};

pub struct RemotePlatform {
    /// Unprivileged half: paths, config tuning, core probes, watcher.
    local: DesktopPlatform,
    /// Privileged half: the connection to the root helper. `Arc` so a spawned test
    /// core can hold its own reference to release itself.
    client: Arc<Client>,
}

impl RemotePlatform {
    /// Build the GUI-side platform over an already-connected helper `client`.
    /// Constructing the local half needs no privilege (it only resolves paths and
    /// the OS seam).
    pub fn new(client: Client) -> anyhow::Result<Self> {
        Ok(Self {
            local: DesktopPlatform::new()?,
            client: Arc::new(client),
        })
    }

    async fn call(&self, req: PrivRequest) -> anyhow::Result<PrivReply> {
        self.client.call(req).await
    }
}

#[async_trait]
impl Platform for RemotePlatform {
    fn paths(&self) -> &BackendPaths {
        self.local.paths()
    }

    // Deliberately answered by the local half, NOT forwarded: the OS proxy lives in
    // the logged-in user's session (gsettings/D-Bus/HKCU) — the GUI's, not the
    // helper's root/LocalSystem one.
    async fn set_os_proxy(&self, mode: kasumi_core::state::ProxyMode, plan: &DataPathPlan) {
        self.local.set_os_proxy(mode, plan).await;
    }

    async fn clear_os_proxy(&self) {
        self.local.clear_os_proxy().await;
    }

    async fn boot_init(&self) -> anyhow::Result<()> {
        // The GUI owns datadir (profiles, built configs); create it before the
        // Service writes there. The helper's BootInit creates run_dir + seeds the
        // lifecycle state on the root side.
        tokio::fs::create_dir_all(&self.local.paths().data_dir).await?;
        self.call(PrivRequest::BootInit).await?;
        Ok(())
    }

    async fn start_data_path(&self, plan: &DataPathPlan) -> anyhow::Result<()> {
        self.call(PrivRequest::StartDataPath { plan: plan.clone() })
            .await?;
        Ok(())
    }

    fn host_traits(&self) -> HostTraits {
        self.local.host_traits()
    }

    async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()> {
        self.call(PrivRequest::StopDataPath {
            keep_service_state: opts.keep_service_state,
        })
        .await?;
        Ok(())
    }

    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        match self.call(PrivRequest::ServiceState).await? {
            PrivReply::State(s) => Ok(s),
            other => anyhow::bail!("unexpected reply to ServiceState: {other:?}"),
        }
    }

    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
        // Unprivileged: running `<core> version` and checking /dev/net/tun need no
        // root, so answer locally and skip a socket round-trip on this hot path.
        self.local.capabilities().await
    }

    fn core_path(&self, engine: Engine) -> PathBuf {
        // On-demand test cores (ping / speed test) are plain SOCKS — no tun, so the
        // GUI spawns them unprivileged from the same bundled binaries.
        self.local.core_path(engine)
    }

    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
        match self.call(PrivRequest::ProxyStatus).await? {
            PrivReply::Proxy {
                running,
                socks_port,
                http_port,
                force_port,
            } => Ok(ProxyStatus {
                running,
                socks_port,
                http_port,
                force_port: force_port
                    .unwrap_or_else(|| kasumi_core::state::force_socks_port(socks_port, http_port)),
            }),
            other => anyhow::bail!("unexpected reply to ProxyStatus: {other:?}"),
        }
    }

    async fn convert_asset(&self, filename: &str) -> anyhow::Result<()> {
        self.local.convert_asset(filename).await
    }

    fn tune_config(&self, engine: Engine, config: &mut Value) {
        self.local.tune_config(engine, config);
    }

    fn app_filter(&self) -> Option<&dyn AppFilterCapability> {
        self.local.app_filter()
    }

    fn watch_network_change(&self) -> Option<mpsc::Receiver<()>> {
        // `ip monitor route` reads the netlink route group — unprivileged.
        self.local.watch_network_change()
    }

    async fn data_path_healthy(&self) -> Option<bool> {
        match self.call(PrivRequest::DataPathHealthy).await {
            Ok(PrivReply::Healthy { healthy }) => healthy,
            // A dropped/broken helper means the data-path can't be healthy.
            _ => Some(false),
        }
    }

    async fn spawn_test_core(
        &self,
        engine: Engine,
        cfg_path: &Path,
        log_path: &Path,
    ) -> anyhow::Result<Box<dyn TestCore>> {
        // Always run test cores in the root helper: it binds their outbound to the
        // physical uplink so they escape an active tun (needs CAP_NET_RAW), the same
        // way the active core already runs as root. No tun up ⇒ binding the uplink is
        // a no-op (it *is* the default route), so this one path covers both states.
        let handle = match self
            .call(PrivRequest::SpawnTestCore {
                engine,
                cfg_path: cfg_path.to_string_lossy().into_owned(),
                log_path: log_path.to_string_lossy().into_owned(),
            })
            .await?
        {
            PrivReply::TestCoreSpawned { handle } => handle,
            other => anyhow::bail!("unexpected reply to SpawnTestCore: {other:?}"),
        };
        Ok(Box::new(RemoteTestCore {
            client: self.client.clone(),
            handle,
            killed: false,
        }))
    }

    async fn tcp_ping(&self, host: &str, port: u16, timeout: Duration) -> Option<u64> {
        // Linux: the uplink bind needs CAP_NET_RAW, so the helper connects, the way
        // it runs test cores. A helper too old for the op falls back to the plain
        // connect below.
        #[cfg(unix)]
        {
            let req = PrivRequest::TcpPing {
                host: host.to_owned(),
                port,
                timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            };
            match self.client.call_oneshot(req).await {
                Ok(PrivReply::Latency { ms }) => return ms,
                Ok(other) => ks_warn!(Area::Helper, "unexpected reply to TcpPing: {other:?}"),
                Err(e) => ks_warn!(Area::Helper, "tcp-ping through the helper failed: {e}"),
            }
        }
        // Windows binds the uplink (`IP_UNICAST_IF`) without privilege.
        self.local.tcp_ping(host, port, timeout).await
    }
}

/// A test core living in the root helper, addressed by handle. `kill` releases it
/// over the wire; `Drop` is the cancel-safety backstop (a probe future dropped
/// before `kill` still frees the core), with the helper's orphan sweep behind that.
struct RemoteTestCore {
    client: Arc<Client>,
    handle: u64,
    killed: bool,
}

#[async_trait]
impl TestCore for RemoteTestCore {
    async fn kill(&mut self) {
        if self.killed {
            return;
        }
        self.killed = true;
        let _ = self
            .client
            .call(PrivRequest::KillTestCore {
                handle: self.handle,
            })
            .await;
    }
}

impl Drop for RemoteTestCore {
    fn drop(&mut self) {
        if self.killed {
            return;
        }
        let client = self.client.clone();
        let handle = self.handle;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = client.call(PrivRequest::KillTestCore { handle }).await;
            });
        }
    }
}
