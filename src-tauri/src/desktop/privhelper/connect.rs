//! GUI side on Windows: reach the data-path service, installing it once (elevated)
//! and demand-starting it with the GUI's resolved paths, then connect to its pipe.
//!
//! The GUI stays unprivileged. The only elevation is a one-time `--install` (the
//! Windows analogue of the Linux pkexec prompt) that registers the service and
//! grants the user permission to start it; every later launch starts it without a
//! prompt. Mirrors [`super::spawn::spawn_and_connect`] on Linux.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;

use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::desktop::paths::{dir_of, DesktopPaths};

use super::client::Client;
use super::proto::{PrivReply, PrivRequest};
use super::service::{PIPE_NAME, SERVICE_NAME};

/// Path of the helper exe shipped beside the GUI (`KASUMI_HELPER_BIN` overrides for
/// dev). It is both the service binary and the install/uninstall entry point.
fn helper_bin() -> anyhow::Result<PathBuf> {
    if let Some(p) = std::env::var_os("KASUMI_HELPER_BIN") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("locate current exe")?;
    let dir = exe.parent().context("current exe has no parent dir")?;
    Ok(dir.join("kasumi-helper.exe"))
}

/// Connect to the data-path service, setting it up on first run. Resolves once the
/// service answers a `Ping` over its pipe.
pub async fn connect_service(paths: &DesktopPaths) -> anyhow::Result<Client> {
    // Fast path: a previous session left the service up — just connect.
    if let Ok(client) = connect_and_ping().await {
        return Ok(client);
    }

    if !is_installed() {
        // One-time elevated install (UAC). Registers + grants the user start rights.
        let helper = helper_bin()?;
        if !run_elevated(&helper, &[OsStr::new("--install")]) {
            anyhow::bail!("service install was declined — the data-path needs it to run");
        }
        wait_for(is_installed, Duration::from_secs(120))
            .context("service did not register (install declined?)")?;
    }

    start_with_paths(paths).context("start the data-path service")?;
    connect_with_retry().await
}

/// Whether the service is registered. A bare SCM connect is granted to all users.
fn is_installed() -> bool {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|m| m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS))
        .is_ok()
}

/// Demand-start the service with the GUI's paths (granted to the user, no UAC),
/// then wait for it to report running. A no-op if it is already up.
fn start_with_paths(paths: &DesktopPaths) -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open SCM")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .context("open service (user lacks start rights?)")?;

    let state = service
        .query_status()
        .context("query service")?
        .current_state;
    if matches!(state, ServiceState::Stopped | ServiceState::StopPending) {
        let bin_dir = dir_of(&paths.xray_bin);
        let args: [OsString; 6] = [
            OsString::from("--datadir"),
            OsString::from(&paths.datadir),
            OsString::from("--rundir"),
            OsString::from(&paths.run_dir),
            OsString::from("--bin-dir"),
            OsString::from(bin_dir),
        ];
        service.start(&args).context("start service")?;
    }

    wait_for(
        || {
            service
                .query_status()
                .map(|s| s.current_state == ServiceState::Running)
                .unwrap_or(false)
        },
        Duration::from_secs(30),
    )
    .context("service did not reach running")
}

/// Open the pipe and confirm the service with a `Ping`.
async fn connect_and_ping() -> anyhow::Result<Client> {
    let client = Client::connect(PIPE_NAME).await?;
    if matches!(client.call(PrivRequest::Ping).await, Ok(PrivReply::Pong)) {
        return Ok(client);
    }
    anyhow::bail!("service did not answer Ping")
}

/// Retry the pipe connect briefly while the freshly-started service binds it.
async fn connect_with_retry() -> anyhow::Result<Client> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(client) = connect_and_ping().await {
            return Ok(client);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("service started but its pipe never became ready");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Poll `cond` until true or `timeout`.
fn wait_for(mut cond: impl FnMut() -> bool, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    anyhow::bail!("timed out")
}

/// Run `exe args` elevated via UAC (`ShellExecuteW` with the `runas` verb), for the
/// one-time service install. Returns whether the elevated process was launched (the
/// user accepted the prompt); the caller waits for its effect. Only the tiny helper
/// elevates — never the GUI.
fn run_elevated(exe: &std::path::Path, args: &[&OsStr]) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    // One quoted command line (UAC launches a fresh process, not a fork).
    let params = args
        .iter()
        .map(|a| format!("\"{}\"", a.to_string_lossy().replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");

    let verb = wide("runas");
    let file: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
    let params = wide(&params);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    // ShellExecuteW returns > 32 on success (a declined prompt counts as failure).
    (result as usize) > 32
}

/// `s` as a NUL-terminated UTF-16 buffer for the Win32 `*W` APIs.
fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
