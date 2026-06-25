//! GUI side: spawn the root helper through the elevator and connect to it.
//!
//! The GUI stays unprivileged and runs `pkexec`/`sudo` on the *small fixed helper*
//! (not the whole GUI). It hands the helper its already-resolved dirs + the cores
//! dir + the controlling pid as CLI args — pkexec scrubs the environment, so
//! re-deriving them root-side would drift; passing them keeps both halves in
//! lock-step. Nothing dangerous (no `LD_*`) crosses the boundary; the helper picks
//! its own trusted paths from these explicit, non-executable arguments.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;

use crate::desktop::paths::{path_args, DesktopPaths};

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

/// Locate the elevator to run the helper through. Prefer a graphical pkexec (a
/// polkit dialog suits a GUI), then sudo. On NixOS the setuid wrappers live under
/// /run/wrappers/bin (the store pkexec is NOT setuid).
fn find_elevator() -> Option<PathBuf> {
    for c in [
        "/run/wrappers/bin/pkexec",
        "/usr/bin/pkexec",
        "/run/wrappers/bin/sudo",
        "/usr/bin/sudo",
    ] {
        if std::path::Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    None
}

/// A `kasumi-helper` that already holds the data-path file caps, so the GUI execs
/// it directly with no elevation or prompt. Checks the NixOS `security.wrappers`
/// entry first, then the sibling helper's own file caps — set either by the deb
/// postinst or by a prior one-time self-`setcap` (see [`self_setcap_target`]).
/// `None` → no capped helper yet; fall back to elevating via pkexec/sudo.
fn capped_helper() -> Option<PathBuf> {
    let wrapper = PathBuf::from("/run/wrappers/bin/kasumi-helper");
    if wrapper.exists() {
        return Some(wrapper);
    }
    let sibling = helper_bin().ok()?;
    has_file_caps(&sibling).then_some(sibling)
}

/// Whether `path` carries a `security.capability` xattr (i.e. file caps are set). A
/// presence check via `getxattr` with a zero-length buffer — which the helper then
/// validates for real at startup ([`capabilities::is_privileged_data_path`]), so
/// reading the exact cap bits here would be redundant.
fn has_file_caps(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // getxattr(.., size=0) returns the value's length (>0 if present), or -1 (ENODATA)
    // when the attribute is absent.
    let ret = unsafe {
        libc::getxattr(
            c_path.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    ret > 0
}

/// The on-disk helper a one-time `pkexec setcap` can grant file caps to, or `None`
/// when self-`setcap` can't or shouldn't run: a read-only `/nix/store` path (NixOS
/// uses the wrapper), inside an AppImage mount (FUSE + nosuid — caps wouldn't
/// persist), or a dev `KASUMI_HELPER_BIN` override.
fn self_setcap_target() -> Option<PathBuf> {
    if std::env::var_os("KASUMI_HELPER_BIN").is_some() || std::env::var_os("APPIMAGE").is_some() {
        return None;
    }
    let bin = helper_bin().ok()?;
    (!bin.starts_with("/nix/store")).then_some(bin)
}

/// Absolute `setcap` (libcap), searched where it actually ships — it's in `sbin`,
/// usually off the `$PATH` pkexec hands a child. `None` → libcap isn't installed.
fn find_setcap() -> Option<PathBuf> {
    for c in [
        "/usr/sbin/setcap",
        "/sbin/setcap",
        "/usr/bin/setcap",
        "/bin/setcap",
    ] {
        if Path::new(c).exists() {
            return Some(PathBuf::from(c));
        }
    }
    None
}

/// Grant the data-path file caps to `helper` via a single `pkexec setcap` (one
/// prompt). On success every later launch finds the capped helper and runs it
/// directly — no further prompts, mirroring the deb postinst for non-deb installs.
async fn grant_file_caps(elevator: &Path, setcap: &Path, helper: &Path) -> bool {
    let status = tokio::process::Command::new(elevator)
        .arg(setcap)
        .arg(crate::desktop::capabilities::file_caps_setcap_arg())
        .arg(helper)
        .status()
        .await;
    matches!(status, Ok(s) if s.success())
}

/// The unix socket the helper binds, inside the GUI-resolved run dir.
fn socket_path(paths: &DesktopPaths) -> String {
    format!("{}/helper.sock", paths.run_dir)
}

/// Spawn the helper elevated and return a connected [`Client`]. Resolves once the
/// helper answers a `Ping`. The helper keeps running after this returns (it owns
/// the data-path); it exits on its own when the GUI (pid `gui_pid`) goes away.
///
/// Launch paths, in preference order:
/// 1. a helper that already holds the data-path caps (NixOS wrapper, deb postinst,
///    or a prior self-`setcap`) → exec directly, no elevation, no prompt;
/// 2. first run without caps → one `pkexec setcap` to grant them, then exec the now-
///    capped helper directly (every later launch hits path 1);
/// 3. setcap unavailable / read-only path → elevate the helper as root per-launch.
pub async fn spawn_and_connect(paths: &DesktopPaths) -> anyhow::Result<Client> {
    let socket = socket_path(paths);
    let gui_pid = std::process::id();
    let uid = unsafe { libc::geteuid() };

    let mut cmd = if let Some(bin) = capped_helper() {
        log::info!("launching capped helper directly (no elevation): {}", bin.display());
        let mut c = tokio::process::Command::new(bin);
        c.arg("--socket").arg(&socket);
        c
    } else {
        let elevator = find_elevator().context("no pkexec/sudo found to elevate the helper")?;
        // First-run bootstrap: grant the helper its caps once so every later launch
        // runs capped + promptless. Best-effort — on failure (no setcap, read-only
        // FS) fall through to elevating the helper as root for this session.
        let target = self_setcap_target();
        let granted = match (&target, find_setcap()) {
            (Some(t), Some(setcap)) => {
                grant_file_caps(&elevator, &setcap, t).await && has_file_caps(t)
            }
            _ => false,
        };
        match (granted, target) {
            (true, Some(t)) => {
                log::info!("granted file caps to {}; launching directly", t.display());
                let mut c = tokio::process::Command::new(&t);
                c.arg("--socket").arg(&socket);
                c
            }
            _ => {
                let helper = helper_bin()?;
                log::info!(
                    "elevating helper {} via {} (socket {socket})",
                    helper.display(),
                    elevator.display()
                );
                let mut c = tokio::process::Command::new(&elevator);
                c.arg(&helper).arg("--socket").arg(&socket);
                c
            }
        }
    };
    for (flag, value) in path_args(paths) {
        cmd.arg(flag).arg(value);
    }
    cmd.arg("--owner-uid")
        .arg(uid.to_string())
        .arg("--gui-pid")
        .arg(gui_pid.to_string());
    // Detach from the GUI's stdio; the helper logs to stderr inherited by the GUI.
    cmd.stdin(std::process::Stdio::null());
    cmd.spawn()
        .context("spawn the privilege helper")?;

    // The elevator may show a prompt; wait (bounded) for the helper to bind + chown
    // the socket, then confirm it with a Ping.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let err = match Client::connect(&socket).await {
            Ok(client) => {
                if matches!(client.call(PrivRequest::Ping).await, Ok(PrivReply::Pong)) {
                    return Ok(client);
                }
                "helper did not answer Ping".to_string()
            }
            Err(e) => format!("{e:#}"),
        };
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("privilege helper did not become ready (elevation declined?): {err}");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}
