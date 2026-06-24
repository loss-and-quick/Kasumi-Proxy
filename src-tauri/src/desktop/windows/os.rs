//! The Windows [`DesktopOs`] seam: the parts of the desktop data-path that differ
//! from Linux — a wintun tun (needing the bundled `wintun.dll` for the external-tun path),
//! no per-interface byte counters, and the system sing-box stack.

use std::time::Duration;

use async_trait::async_trait;

use kasumi_backend::fs::exists;

use crate::desktop::paths::DesktopPaths;
use crate::desktop::platform::DesktopOs;

use super::routing::adapter_ifindex;

pub(crate) struct WindowsOs;

#[async_trait]
impl DesktopOs for WindowsOs {
    fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }

    async fn precheck_external_tun(&self, p: &DesktopPaths) -> anyhow::Result<()> {
        // tun2socks loads wintun.dll from its own directory (unlike sing-box, which
        // embeds it), so the external-tun path genuinely needs the bundled DLL on disk.
        if !exists(&p.wintun_dll).await {
            anyhow::bail!("wintun.dll missing — cannot create a tun");
        }
        Ok(())
    }

    async fn await_tun_up(&self, name: &str) -> anyhow::Result<()> {
        // tun2socks creates the wintun adapter asynchronously; it must appear before
        // we address/route it, else routing would target a non-existent interface.
        for _ in 0..40 {
            if adapter_ifindex(name).await.is_some() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        anyhow::bail!("tun adapter never came up — see tun2socks log")
    }

    async fn iface_traffic(&self, _iface: Option<&str>) -> (u64, u64) {
        // Per-interface byte counters aren't wired on Windows yet (no /proc/net/dev;
        // reading them needs iphlpapi) — report 0/0 rather than spawn PowerShell at
        // the 1 Hz status cadence.
        (0, 0)
    }

    async fn tun_capable(&self) -> bool {
        // sing-box embeds wintun, so a tun is always possible; the external-tun path
        // additionally needs the bundled wintun.dll (checked at start).
        true
    }

    fn singbox_stack(&self) -> &'static str {
        "system"
    }
}
