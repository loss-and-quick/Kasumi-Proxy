//! Active-uplink detection + network-change monitor. The uplink is the device the
//! route lookup answers with, which follows Android's default network. A switch of
//! that network rewrites Android's ip rules, so the watcher listens to
//! `ip monitor rule` and looks again once a burst settles (a 5 s poll where the
//! monitor can't run). On each real uplink switch it notifies the `Service`, which
//! leaves a running data-path alone: nothing it installs names the uplink, the
//! cores leave as uid 0 through Android's default network, and sing-box follows
//! the default interface itself.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use super::paths::IP;
use super::{default_uplink, run_out};
use kasumi_log::{Area, ks_info};

/// How long the rule events of one switch keep coming before the watcher looks.
const SETTLE: Duration = Duration::from_millis(500);
const POLL: Duration = Duration::from_secs(5);

// Physical uplinks whose route tables the routing rules can name.
fn is_uplink(name: &str) -> bool {
    name == "wlan0"
        || name == "eth0"
        || name == "bt-pan"
        || name.starts_with("rmnet_data")
        || name.starts_with("r_rmnet_data")
        || name.starts_with("ccmni")
}

/// The physical uplink behind a routed device: a CLAT device `v4-<iface>` routes
/// through `<iface>`, whose table holds its route.
fn uplink_of(dev: &str) -> Option<String> {
    let base = dev.strip_prefix("v4-").unwrap_or(dev);
    is_uplink(base).then(|| base.to_owned())
}

/// The uplink Android currently routes through, or `None` while it has none.
/// Asking the route lookup follows Android's default network; any table with a
/// default route would also name the cellular link that lingers after Wi-Fi is
/// back.
async fn active_interface() -> Option<String> {
    match default_uplink().await {
        Some(dev) => uplink_of(&dev),
        None => interface_with_default_route().await,
    }
}

/// The first uplink whose own table has a default route.
async fn interface_with_default_route() -> Option<String> {
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

/// Tell the `Service` when the uplink moved.
async fn check(last: &mut Option<String>, tx: &mpsc::Sender<()>) {
    let Some(cur) = active_interface().await else {
        return;
    };
    if Some(&cur) != last.as_ref() {
        ks_info!(
            Area::Platform,
            "uplink: {} -> {cur}",
            last.as_deref().unwrap_or("none")
        );
        *last = Some(cur);
        let _ = tx.send(()).await;
    }
}

/// Monitor for uplink switches, sending `()` on each. Runs until the process exits.
pub async fn run_watcher(tx: mpsc::Sender<()>) {
    let mut last = active_interface().await;
    loop {
        let monitor = Command::new(IP)
            .args(["-o", "monitor", "rule"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let Ok(mut child) = monitor else {
            poll(&mut last, &tx).await;
        };
        // A switch may have happened while the monitor was down.
        check(&mut last, &tx).await;
        let mut heard = false;
        if let Some(stdout) = child.stdout.take() {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(_)) = lines.next_line().await {
                heard = true;
                while let Ok(Ok(Some(_))) = tokio::time::timeout(SETTLE, lines.next_line()).await {}
                check(&mut last, &tx).await;
            }
        }
        let _ = child.kill().await;
        // An `ip` without `monitor rule` exits at once: poll for good. A monitor
        // that worked and died is respawned no faster than the poll would look.
        if !heard {
            poll(&mut last, &tx).await;
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn poll(last: &mut Option<String>, tx: &mpsc::Sender<()>) -> ! {
    loop {
        tokio::time::sleep(POLL).await;
        check(last, tx).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routed_device_maps_to_its_uplink() {
        assert_eq!(uplink_of("wlan0").as_deref(), Some("wlan0"));
        assert_eq!(uplink_of("rmnet_data2").as_deref(), Some("rmnet_data2"));
        // CLAT on an IPv6-only mobile network.
        assert_eq!(uplink_of("v4-rmnet_data0").as_deref(), Some("rmnet_data0"));
        assert_eq!(uplink_of("tun0"), None);
        assert_eq!(uplink_of("lo"), None);
    }
}
