//! Active-uplink monitor. On a real uplink switch (e.g. ethernet ↔ wifi) the
//! default route's device changes; we notify the `Service`, which restarts the
//! data-path so routing re-pins onto the new uplink (sing-box re-detects its
//! interface; the xray path re-installs its bypass + split-default from the fresh
//! default route). Event-driven via `ip monitor route`, re-arming if it exits.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use super::paths::IP;
use super::routing::read_default_route;

/// The uplink device currently owning the default route, or `None`.
async fn active_uplink() -> Option<String> {
    read_default_route().await.map(|(_, dev)| dev)
}

/// Watch for the active uplink changing and send `()` on each real switch. Runs
/// until the process exits.
pub async fn run_watcher(tx: mpsc::Sender<()>) {
    let mut last = active_uplink().await;
    loop {
        let child = Command::new(IP)
            .args(["monitor", "route"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = child {
            if let Some(stdout) = child.stdout.take() {
                let mut lines = BufReader::new(stdout).lines();
                while let Ok(Some(_)) = lines.next_line().await {
                    // The new default route may not be installed yet — let it settle.
                    let mut cur = active_uplink().await;
                    for _ in 0..10 {
                        if cur.is_some() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        cur = active_uplink().await;
                    }
                    if let Some(cur) = cur {
                        if Some(&cur) != last.as_ref() {
                            last = Some(cur);
                            let _ = tx.send(()).await;
                        }
                    }
                }
            }
            let _ = child.kill().await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await; // re-arm the watcher
    }
}
