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
use crate::desktop::DesktopPlatform;
use crate::desktop::paths::{
    ARG_BIN_DIR, ARG_DATADIR, ARG_RUNDIR, ENV_BIN_DIR, ENV_DATADIR, ENV_RUNDIR,
};

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
    if !crate::desktop::capabilities::is_privileged_data_path() {
        log::warn!("not holding the data-path caps (CAP_NET_ADMIN) — tun/routing will fail");
    }

    // Least privilege: stop *holding* more privilege than the data-path needs.
    // Drop every capability from the bounding set except the handful the data-path
    // provably needs (NET_ADMIN, NET_RAW, CHOWN, DAC_OVERRIDE); the bounding set is
    // also the ceiling for every exec'd core / tun2socks / `ip`, so this shrinks the
    // helper and its children at once. Gated on holding NET_ADMIN rather than
    // `geteuid()==0` so it also self-reduces under a non-root file-cap launcher
    // (NixOS `security.wrappers` setcap wrapper runs the helper as the GUI uid).
    // A failure is non-fatal — the worst case is running with full caps.
    if crate::desktop::capabilities::is_privileged_data_path() {
        match crate::desktop::capabilities::drop_unneeded_bounding() {
            Ok(dropped) => log::info!(
                "dropped {} caps from the bounding set (kept the data-path set)",
                dropped.len()
            ),
            Err(e) => log::warn!("could not drop the bounding set ({e}); running with full caps"),
        }
        // Seed CAP_NET_RAW + CAP_NET_ADMIN into the inheritable set — the precondition
        // for raising either into an ambient set (PR_CAP_AMBIENT_RAISE needs the cap in
        // both permitted and inheritable, and both a pkexec-root and a file-cap start
        // begin with an empty inheritable set). A failure is non-fatal but the ambient
        // raises below then fail too.
        if let Err(e) = crate::desktop::capabilities::seed_child_inheritable() {
            log::warn!("could not seed child caps into the inheritable set ({e})");
        }
        // Raise the data-path caps (NET_ADMIN + NET_RAW) into our own ambient set now,
        // on the main thread before the tokio runtime starts, so every core /
        // tun2socks / `ip` we later exec inherits them — under the caps-only launcher a
        // child gets no caps across exec otherwise, and the data path fails (sing-box
        // can't open its tun; a bridged core's uplink bind EPERMs). NET_ADMIN covers
        // tun/fwmark/`ip`, NET_RAW the `SO_BINDTODEVICE`/`bind_interface` escape.
        // Non-fatal: a failure just leaves the data path broken, as before.
        if let Err(e) = crate::desktop::capabilities::raise_data_path_caps_ambient() {
            log::warn!("could not raise the data-path caps into the ambient set ({e})");
        }
    }

    // Resolve paths to exactly what the GUI passed (pkexec scrubbed the env).
    std::env::set_var(ENV_DATADIR, &args.datadir);
    std::env::set_var(ENV_RUNDIR, &args.rundir);
    std::env::set_var(ENV_BIN_DIR, &args.bin_dir);

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        // The run dir holds the socket + the helper-owned state. Create it whether
        // the helper runs as root (pkexec) or as the GUI uid with caps (the wrapper /
        // self-setcap path); CAP_DAC_OVERRIDE covers a dir a prior root run left.
        tokio::fs::create_dir_all(&args.rundir).await?;

        let platform: Arc<dyn Platform> = Arc::new(DesktopPlatform::new()?);
        tokio::spawn(watch_gui(args.gui_pid, platform.clone()));
        server::serve(platform, &args.socket, Some(args.owner_uid)).await
    })
}
