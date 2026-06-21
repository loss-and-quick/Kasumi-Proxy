//! The Linux [`DesktopOs`] seam: the parts of the desktop data-path that differ from
//! Windows — a native tun reachable via `ip`, `/proc/net/dev` byte counters, and the
//! gvisor sing-box stack for the root-binary tun path.

use std::time::Duration;

use async_trait::async_trait;

use kasumi_backend::fs::{exists, read_text};

use crate::desktop::paths::DesktopPaths;
use crate::desktop::platform::DesktopOs;
use crate::desktop::silent;

/// fwmark stamped on tun2socks' own upstream socket so it stays out of the tunnel.
pub(crate) const FWMARK: u32 = 0x1112;
/// The userspace tun's address; `/15` covers the CGNAT-ish 198.18/15 test net.
pub(crate) const TUN_ADDR: &str = "198.18.0.1/15";
pub(crate) const IP: &str = "ip";

pub(crate) struct LinuxOs;

/// RX/TX bytes for `iface` from /proc/net/dev, or (0, 0).
async fn iface_traffic(iface: Option<&str>) -> (u64, u64) {
    let Some(iface) = iface else {
        return (0, 0);
    };
    let Some(dev) = read_text("/proc/net/dev").await else {
        return (0, 0);
    };
    for line in dev.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        let rx = f.first().and_then(|x| x.parse().ok()).unwrap_or(0);
        let tx = f.get(8).and_then(|x| x.parse().ok()).unwrap_or(0);
        return (rx, tx);
    }
    (0, 0)
}

#[async_trait]
impl DesktopOs for LinuxOs {
    fn new() -> anyhow::Result<Self> {
        Ok(Self)
    }

    fn tun2socks_fwmark(&self) -> Option<u32> {
        Some(FWMARK)
    }

    async fn precheck_xray(&self, _p: &DesktopPaths) -> anyhow::Result<()> {
        Ok(())
    }

    async fn await_tun_up(&self, name: &str) -> anyhow::Result<()> {
        // Best-effort: tun2socks creates the device asynchronously. If it never
        // shows we still proceed — addressing/routing will simply no-op, matching
        // the original `ip` flow (no hard failure here).
        for _ in 0..20 {
            if silent(&[IP, "link", "show", name]).await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok(())
    }

    async fn iface_traffic(&self, iface: Option<&str>) -> (u64, u64) {
        iface_traffic(iface).await
    }

    async fn tun_capable(&self) -> bool {
        exists("/dev/net/tun").await
    }

    fn singbox_stack(&self) -> &'static str {
        "gvisor"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn iface_traffic_handles_absent_iface() {
        assert_eq!(iface_traffic(None).await, (0, 0));
        assert_eq!(iface_traffic(Some("definitely-not-an-iface")).await, (0, 0));
    }
}
