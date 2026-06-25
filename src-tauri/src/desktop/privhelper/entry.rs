//! The `kasumi-helper` entry point: the privileged half of the desktop data-path.
//!
//! Spawned as root by the unprivileged GUI through pkexec/sudo (see [`super::spawn`]).
//! It takes the GUI's resolved dirs + cores dir + controlling pid as args, hosts a
//! [`DesktopPlatform`], and serves the [`super::proto`] requests over the unix
//! socket. It tears the data-path down and exits when the GUI goes away, so a dead
//! or crashed GUI never leaves the tunnel up.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kasumi_backend::platform::{Platform, StopDataPath};

use super::server;
use crate::desktop::paths::{
    ARG_BIN_DIR, ARG_DATADIR, ARG_RUNDIR, ENV_BIN_DIR, ENV_DATADIR, ENV_RUNDIR,
};
use crate::desktop::DesktopPlatform;

struct Args {
    socket: String,
    datadir: String,
    rundir: String,
    bin_dir: String,
    owner_uid: u32,
    gui_pid: u32,
}

/// Parse `--key value` pairs. Unknown keys are rejected so a wiring mistake is loud.
fn parse_args() -> anyhow::Result<Args> {
    let mut socket = None;
    let mut datadir = None;
    let mut rundir = None;
    let mut bin_dir = None;
    let mut owner_uid = None;
    let mut gui_pid = None;

    let mut it = std::env::args().skip(1);
    while let Some(key) = it.next() {
        let mut val = || {
            it.next()
                .ok_or_else(|| anyhow::anyhow!("missing value for {key}"))
        };
        match key.as_str() {
            "--socket" => socket = Some(val()?),
            ARG_DATADIR => datadir = Some(val()?),
            ARG_RUNDIR => rundir = Some(val()?),
            ARG_BIN_DIR => bin_dir = Some(val()?),
            "--owner-uid" => owner_uid = Some(val()?.parse()?),
            "--gui-pid" => gui_pid = Some(val()?.parse()?),
            other => anyhow::bail!("unknown argument {other}"),
        }
    }
    Ok(Args {
        socket: socket.ok_or_else(|| anyhow::anyhow!("--socket is required"))?,
        datadir: datadir.ok_or_else(|| anyhow::anyhow!("--datadir is required"))?,
        rundir: rundir.ok_or_else(|| anyhow::anyhow!("--rundir is required"))?,
        bin_dir: bin_dir.ok_or_else(|| anyhow::anyhow!("--bin-dir is required"))?,
        owner_uid: owner_uid.ok_or_else(|| anyhow::anyhow!("--owner-uid is required"))?,
        gui_pid: gui_pid.ok_or_else(|| anyhow::anyhow!("--gui-pid is required"))?,
    })
}

/// Stop the data-path and exit once the controlling GUI (pid `gui_pid`) is gone, so
/// a crashed GUI can't leave the tun + routes installed.
async fn watch_gui(gui_pid: u32, platform: Arc<dyn Platform>) -> ! {
    let proc = format!("/proc/{gui_pid}");
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if !Path::new(&proc).exists() {
            let _ = platform
                .stop_data_path(StopDataPath {
                    keep_service_state: false,
                })
                .await;
            std::process::exit(0);
        }
    }
}

/// `kasumi-helper` main. Never returns on success (serves until the GUI exits).
pub fn run_helper() -> ! {
    if let Err(e) = run() {
        // The logger may not be up yet (arg parse failed before init), so use stderr.
        eprintln!("kasumi-helper: {e}");
        log::error!("helper exited with error: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run() -> anyhow::Result<()> {
    let args = parse_args()?;
    super::hlog::init(Path::new(&args.rundir));
    log::info!(
        "helper starting: datadir={} rundir={} bin_dir={} gui_pid={}",
        args.datadir,
        args.rundir,
        args.bin_dir,
        args.gui_pid
    );
    if unsafe { libc::geteuid() } != 0 {
        log::warn!("not running as root — tun/routing will fail");
    }

    // Least privilege (Phase 2): still launched as root via pkexec, but stop
    // *holding* full root at runtime. Drop every capability from the bounding set
    // except the handful the data-path provably needs (NET_ADMIN, NET_RAW, CHOWN,
    // DAC_OVERRIDE); the bounding set is also the ceiling for every exec'd core /
    // tun2socks / `ip`, so this shrinks the helper and its children at once. A
    // failure is non-fatal — the worst case is running with full caps as before.
    if unsafe { libc::geteuid() } == 0 {
        match crate::desktop::capabilities::drop_unneeded_bounding() {
            Ok(dropped) => log::info!(
                "dropped {} caps from the bounding set (kept the data-path set)",
                dropped.len()
            ),
            Err(e) => log::warn!("could not drop the bounding set ({e}); running with full caps"),
        }
        // Phase 3: seed CAP_NET_RAW into the inheritable set so the ambient raise
        // the test cores get in their pre_exec (see platform.rs spawn_test_core)
        // succeeds — PR_CAP_AMBIENT_RAISE needs the cap in both permitted and
        // inheritable, and pkexec-root starts with an empty inheritable set. A
        // failure is non-fatal: the test-core ambient raise then fails closed and
        // the test core simply runs without the bind (the pre-root-bind state).
        if let Err(e) = crate::desktop::capabilities::seed_test_core_inheritable() {
            log::warn!("could not seed CAP_NET_RAW into the inheritable set ({e})");
        }
    }

    // Resolve paths to exactly what the GUI passed (pkexec scrubbed the env).
    std::env::set_var(ENV_DATADIR, &args.datadir);
    std::env::set_var(ENV_RUNDIR, &args.rundir);
    std::env::set_var(ENV_BIN_DIR, &args.bin_dir);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        // The run dir holds the socket + the helper-owned state; create it as root.
        tokio::fs::create_dir_all(&args.rundir).await?;

        let platform: Arc<dyn Platform> = Arc::new(DesktopPlatform::new()?);
        tokio::spawn(watch_gui(args.gui_pid, platform.clone()));
        server::serve(platform, &args.socket, Some(args.owner_uid)).await
    })
}
