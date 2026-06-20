//! Active-uplink monitor (Windows). On a real uplink switch (e.g. ethernet ↔ wifi)
//! the default route's interface index changes; we notify the `Service`, which
//! restarts the data-path so routing re-pins onto the new uplink. The Linux side is
//! event-driven via `ip monitor route`; here we poll the default route — a few
//! seconds' latency before a re-pin is fine, and it avoids an iphlpapi callback.

use std::time::Duration;

use tokio::sync::mpsc;

use super::routing::read_default_route;

/// The interface index currently owning the default route, or `None`.
async fn active_uplink() -> Option<u32> {
    read_default_route().await.map(|(_, idx)| idx)
}

/// Poll for the active uplink changing and send `()` on each real switch. Runs
/// until the receiver is dropped.
pub async fn run_watcher(tx: mpsc::Sender<()>) {
    let mut last = active_uplink().await;
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let cur = active_uplink().await;
        // Only fire on a settled change to a real uplink — a transient `None`
        // (no default route mid-switch) must not trigger a spurious restart.
        if cur.is_some() && cur != last {
            last = cur;
            if tx.send(()).await.is_err() {
                return;
            }
        }
    }
}
