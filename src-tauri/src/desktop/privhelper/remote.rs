//! `RemotePlatform`: the GUI's [`Platform`], privilege-separated.
//!
//! It wraps a local [`DesktopPlatform`] for everything unprivileged (path lookups,
//! config tuning, core-version probes, the netlink uplink watch, on-demand test
//! cores, asset conversion) and forwards only the privileged data-path methods to
//! the root helper over [`Client`]. The split mirrors the file-domain split in
//! `paths`: the GUI owns `datadir`, the helper owns `run_dir`, and data-path state
//! comes back in RPC replies rather than through root-owned files.

use std::path::PathBuf;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    AppFilterCapability, BackendPaths, Engine, Platform, PlatformCapabilities, StartDataPath,
    StopDataPath,
};
use kasumi_core::contract::ServiceState;

use super::client::Client;
use super::proto::{PrivReply, PrivRequest};
use crate::desktop::DesktopPlatform;

pub struct RemotePlatform {
    /// Unprivileged half: paths, config tuning, core probes, test cores, watcher.
    local: DesktopPlatform,
    /// Privileged half: the connection to the root helper.
    client: Client,
}

impl RemotePlatform {
    /// Build the GUI-side platform over an already-connected helper `client`.
    /// Constructing the local half needs no privilege (it only resolves paths and
    /// the OS seam).
    pub fn new(client: Client) -> anyhow::Result<Self> {
        Ok(Self {
            local: DesktopPlatform::new()?,
            client,
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

    async fn boot_init(&self) -> anyhow::Result<()> {
        // The GUI owns datadir (profiles, built configs); create it before the
        // Service writes there. The helper's BootInit creates run_dir + seeds the
        // lifecycle state on the root side.
        tokio::fs::create_dir_all(&self.local.paths().data_dir).await?;
        self.call(PrivRequest::BootInit).await?;
        Ok(())
    }

    async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
        self.call(PrivRequest::StartDataPath {
            engine: opts.engine,
            socks_port: opts.socks_port,
        })
        .await?;
        Ok(())
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
            } => Ok(ProxyStatus {
                running,
                socks_port,
                http_port,
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
}
