//! Active-uplink detection + network-change monitor. Reads `/sys/class/net`,
//! per-iface route tables, and watches `/data/misc/net` via busybox `inotifyd`
//! (event-driven) or a 5 s poll fallback. On each real uplink switch it re-pins the
//! proxy mark rule and notifies the `Service` (which restarts the data-path).

use std::time::Duration;

use kasumi_backend::fs::exists;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use super::paths::IP;
use super::routing::apply_mark_rule;
use super::run_out;

// Physical uplinks worth pinning the proxy mark to.
fn is_uplink(name: &str) -> bool {
    name == "wlan0"
        || name == "eth0"
        || name == "bt-pan"
        || name.starts_with("rmnet_data")
        || name.starts_with("r_rmnet_data")
        || name.starts_with("ccmni")
}

// Common busybox locations on rooted Android (KSU / Magisk / APatch).
const BUSYBOX_PATHS: [&str; 5] = [
    "/data/adb/ksu/bin/busybox",
    "/data/adb/magisk/busybox",
    "/data/adb/ap/bin/busybox",
    "/system/bin/busybox",
    "/system/xbin/busybox",
];

async fn find_busybox() -> Option<&'static str> {
    for p in BUSYBOX_PATHS {
        if exists(p).await {
            return Some(p);
        }
    }
    None
}

/// The uplink iface that currently owns a default route, or `None`.
async fn active_interface() -> Option<String> {
    let mut rd = tokio::fs::read_dir("/sys/class/net").await.ok()?;
    let mut names = Vec::new();
    while let Ok(Some(e)) = rd.next_entry().await {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    for name in names {
        if !is_uplink(&name) {
            continue;
        }
        let (_, out) = run_out(&[IP, "route", "show", "table", &name]).await;
        if out.lines().any(|l| l.starts_with("default ")) {
            return Some(name);
        }
    }
    None
}

async fn notify(tx: &mpsc::Sender<()>) {
    let _ = tx.send(()).await;
}

/// Pin the proxy mark to the current uplink, then monitor for network changes,
/// sending `()` on each real switch. Runs until the process exits.
pub async fn run_watcher(tx: mpsc::Sender<()>) {
    let mut last = active_interface().await;
    if let Some(l) = &last {
        apply_mark_rule(l).await;
    }

    if let Some(bb) = find_busybox().await {
        loop {
            if let Ok(mut child) = Command::new(bb)
                .args(["inotifyd", "-", "/data/misc/net::w"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                if let Some(stdout) = child.stdout.take() {
                    let mut lines = BufReader::new(stdout).lines();
                    while let Ok(Some(_)) = lines.next_line().await {
                        // After an event the new uplink may not be ready yet.
                        let mut cur = active_interface().await;
                        for _ in 0..10 {
                            if cur.is_some() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            cur = active_interface().await;
                        }
                        if let Some(cur) = cur
                            && Some(&cur) != last.as_ref()
                        {
                            last = Some(cur.clone());
                            notify(&tx).await;
                            apply_mark_rule(&cur).await;
                        }
                    }
                }
                let _ = child.kill().await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await; // re-arm the watcher
        }
    } else {
        // No busybox — poll every 5 s.
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Some(cur) = active_interface().await
                && Some(&cur) != last.as_ref()
            {
                last = Some(cur.clone());
                notify(&tx).await;
                apply_mark_rule(&cur).await;
            }
        }
    }
}
