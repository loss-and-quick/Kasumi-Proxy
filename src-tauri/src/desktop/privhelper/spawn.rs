//! GUI side: spawn the root helper through the elevator and connect to it.
//!
//! The GUI stays unprivileged and runs `pkexec`/`sudo` on the *small fixed helper*
//! (not the whole GUI). It hands the helper its already-resolved dirs + the cores
//! dir + the controlling pid as CLI args — pkexec scrubs the environment, so
//! re-deriving them root-side would drift; passing them keeps both halves in
//! lock-step. Nothing dangerous (no `LD_*`) crosses the boundary; the helper picks
//! its own trusted paths from these explicit, non-executable arguments.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;

use crate::desktop::elevate::find_elevator;
use crate::desktop::paths::{dir_of, DesktopPaths};

use super::client::Client;
use super::proto::{PrivReply, PrivRequest};

/// Path of the helper binary shipped beside the GUI (`KASUMI_HELPER_BIN` overrides
/// for dev). Under the Nix GApps wrapper `current_exe` is the real ELF in the
/// package's `bin/`, so the helper is its sibling.
fn helper_bin() -> anyhow::Result<PathBuf> {
    if let Some(p) = std::env::var_os("KASUMI_HELPER_BIN") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("locate current exe")?;
    let dir = exe.parent().context("current exe has no parent dir")?;
    Ok(dir.join("kasumi-helper"))
}

/// The unix socket the helper binds, inside the GUI-resolved run dir.
pub fn socket_path(paths: &DesktopPaths) -> String {
    format!("{}/helper.sock", paths.run_dir)
}

/// The cores directory the helper should use — exactly the one the GUI resolved
/// (the parent of the xray binary path).
fn bin_dir(paths: &DesktopPaths) -> String {
    dir_of(&paths.xray_bin)
}

/// Spawn the helper elevated and return a connected [`Client`]. Resolves once the
/// helper answers a `Ping`. The helper keeps running after this returns (it owns
/// the data-path); it exits on its own when the GUI (pid `gui_pid`) goes away.
pub async fn spawn_and_connect(paths: &DesktopPaths) -> anyhow::Result<Client> {
    let elevator = find_elevator().context("no pkexec/sudo found to elevate the helper")?;
    let helper = helper_bin()?;
    let socket = socket_path(paths);
    let gui_pid = std::process::id();
    let uid = unsafe { libc::geteuid() };

    // The helper owns run_dir (root) and clears any stale socket itself before
    // binding — the GUI can't unlink in that root-owned dir, so don't try here.

    let mut cmd = tokio::process::Command::new(elevator);
    cmd.arg(&helper)
        .arg("--socket")
        .arg(&socket)
        .arg("--datadir")
        .arg(&paths.datadir)
        .arg("--rundir")
        .arg(&paths.run_dir)
        .arg("--bin-dir")
        .arg(bin_dir(paths))
        .arg("--owner-uid")
        .arg(uid.to_string())
        .arg("--gui-pid")
        .arg(gui_pid.to_string());
    // Detach from the GUI's stdio; the helper logs to stderr inherited by the GUI.
    cmd.stdin(std::process::Stdio::null());
    cmd.spawn()
        .context("spawn the privilege helper via the elevator")?;

    // The elevator may show a prompt; wait (bounded) for the helper to bind + chown
    // the socket, then confirm it with a Ping.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(client) = Client::connect(&socket).await {
            if matches!(client.call(PrivRequest::Ping).await, Ok(PrivReply::Pong)) {
                return Ok(client);
            }
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("privilege helper did not become ready (elevation declined?)");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
