//! sysctl locking: a bind-mount over a `/proc/sys` file only shadows the
//! *readback* — the kernel keeps the last real write — so we write the value first,
//! then bind a stub holding the same value, so later writes by netd land on the
//! stub instead of reverting the kernel.

use std::os::unix::fs::MetadataExt;

use kasumi_backend::fs::{exists, read_text, write_text};

use super::{run_out, silent};

const STUB_DIR: &str = "/dev/sysctl_stubs";

/// Set up the tmpfs backing the sysctl stubs, plus the boot-time global locks
/// (forwarding on, rp_filter off). Idempotent.
pub async fn setup_sysctl_locks() {
    silent(&["rm", "-rf", STUB_DIR]).await;
    silent(&["mkdir", "-p", STUB_DIR]).await;
    silent(&[
        "mount",
        "-t",
        "tmpfs",
        "-o",
        "size=64k,mode=0755,context=u:object_r:proc_net:s0",
        "proc",
        STUB_DIR,
    ])
    .await;
    lock_sysctl("1", "/proc/sys/net/ipv4/ip_forward").await;
    lock_sysctl("1", "/proc/sys/net/ipv6/conf/all/forwarding").await;
    lock_sysctl("1", "/proc/sys/net/ipv6/conf/default/forwarding").await;
    lock_sysctl("0", "/proc/sys/net/ipv4/conf/all/rp_filter").await;
    lock_sysctl("0", "/proc/sys/net/ipv4/conf/default/rp_filter").await;
}

pub async fn lock_sysctl(value: &str, target_path: &str) {
    // Key the stub by the full path so distinct sysctls never collide on a shared
    // basename (conf/all/rp_filter vs conf/<tun>/rp_filter).
    let stub_file = format!("{STUB_DIR}/{}", target_path.replace('/', "_"));
    silent(&["mkdir", "-p", STUB_DIR]).await;

    // Drop any prior bind-mount first, else the real write below can't land.
    for _ in 0..8 {
        if silent(&["umount", target_path]).await != 0 {
            break;
        }
    }

    let valued = format!("{value}\n");
    let _ = write_text(target_path, &valued).await;
    // The readback reports the kernel truth; we don't surface it (best-effort lock).
    let _ = read_text(target_path).await;

    let _ = write_text(&stub_file, &valued).await;
    if let Ok(m) = std::fs::metadata(target_path) {
        let owner = format!("{}:{}", m.uid(), m.gid());
        silent(&["chown", &owner, &stub_file]).await;
    }
    let (_, ctx) = run_out(&["stat", "-Z", "-c", "%C", target_path]).await;
    let ctx = ctx.trim();
    if !ctx.is_empty() {
        silent(&["chcon", ctx, &stub_file]).await;
    }
    silent(&["mount", "-o", "bind", &stub_file, target_path]).await;
}

/// Drop stub files left by tun interfaces that no longer exist.
async fn prune_dead_tun_stubs() {
    let Ok(mut rd) = tokio::fs::read_dir(STUB_DIR).await else {
        return;
    };
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(iface) = name
            .strip_prefix("_proc_sys_net_ipv4_conf_")
            .and_then(|s| s.strip_suffix("_rp_filter"))
        else {
            continue;
        };
        if iface == "all" || iface == "default" {
            continue;
        }
        if exists(format!("/proc/sys/net/ipv4/conf/{iface}")).await {
            continue; // iface still up
        }
        silent(&[
            "umount",
            &format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter"),
        ])
        .await;
        silent(&["rm", "-f", &format!("{STUB_DIR}/{name}")]).await;
    }
}

/// Lock the tun interface's rp_filter to 0.
pub async fn lock_tun_iface(iface: &str) {
    if iface.is_empty() {
        return;
    }
    prune_dead_tun_stubs().await;
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
    if !exists(&path).await {
        return;
    }
    lock_sysctl("0", &path).await;
}
