//! GUI side on Windows: reach the privileged data-path over a named pipe.
//!
//! Installed builds use the LocalSystem service: the GUI installs it once (a single
//! elevated `--install`, the Windows analogue of the Linux pkexec prompt) granting
//! the user start rights, then demand-starts and connects with no further prompt.
//!
//! Portable builds keep nothing installed: the GUI runs the helper transiently under
//! UAC on each launch (`--serve`), serving one session over a per-GUI pipe and exiting
//! with the GUI — the exact mirror of [`super::spawn::spawn_and_connect`] on Linux.
//! The GUI itself never elevates in either case.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;

use windows_service::service::{ServiceAccess, ServiceState};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::desktop::paths::{path_args, DesktopPaths};

use super::client::Client;
use super::proto::{PrivReply, PrivRequest};
use super::service::{wide, PIPE_NAME, SERVICE_NAME};

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
    // Portable: no installed service — run the helper transiently under UAC (the
    // mirror of the Linux pkexec helper), leaving nothing behind.
    if paths.portable {
        log::info!("portable build: starting transient elevated helper");
        return connect_transient(paths).await;
    }

    // Fast path: a previous session left the service up — just connect.
    if let Ok(client) = connect_and_ping(PIPE_NAME).await {
        log::info!("reusing already-running data-path service");
        return Ok(client);
    }

    if !is_installed() {
        // One-time elevated install (UAC). Registers + grants the user start rights.
        log::info!("data-path service not installed; requesting elevated install");
        let helper = helper_bin()?;
        if !run_elevated(&helper, &[OsStr::new("--install")]) {
            anyhow::bail!("service install was declined — the data-path needs it to run");
        }
        wait_for(is_installed, Duration::from_secs(120))
            .context("service did not register (install declined?)")?;
    }

    log::info!("demand-starting the data-path service");
    start_with_paths(paths).context("start the data-path service")?;
    connect_with_retry(PIPE_NAME).await
}

/// Portable path: spawn the helper elevated (one UAC) to serve a single session over
/// a per-GUI pipe, then connect. The unique pipe name keeps a portable run from
/// colliding with an installed service's fixed pipe; the helper exits with this GUI.
async fn connect_transient(paths: &DesktopPaths) -> anyhow::Result<Client> {
    let pipe = format!(r"\\.\pipe\kasumi-proxy-helper-{}", std::process::id());
    let helper = helper_bin()?;
    log::info!("transient helper {} over pipe {pipe}", helper.display());
    let pairs = path_args(paths);
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("--serve"),
        OsStr::new("--pipe"),
        OsStr::new(&pipe),
    ];
    for (flag, value) in &pairs {
        args.push(OsStr::new(flag));
        args.push(OsStr::new(value));
    }
    if !run_elevated(&helper, &args) {
        log::warn!(
            "ShellExecuteW runas failed or was declined for {}",
            helper.display()
        );
        anyhow::bail!("elevation declined — the data-path needs admin");
    }
    log::info!("elevated helper launched; connecting to its pipe");
    connect_with_retry(&pipe).await
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
        let args: Vec<OsString> = path_args(paths)
            .into_iter()
            .flat_map(|(flag, value)| [OsString::from(flag), OsString::from(value)])
            .collect();
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

/// Open `pipe` and confirm the helper with a `Ping`.
async fn connect_and_ping(pipe: &str) -> anyhow::Result<Client> {
    let client = Client::connect(pipe).await?;
    if matches!(client.call(PrivRequest::Ping).await, Ok(PrivReply::Pong)) {
        return Ok(client);
    }
    anyhow::bail!("helper did not answer Ping")
}

/// Retry the pipe connect briefly while the freshly-started helper binds `pipe`.
async fn connect_with_retry(pipe: &str) -> anyhow::Result<Client> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_err = String::from("no attempt completed");
    loop {
        match connect_and_ping(pipe).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                let s = format!("{e:#}");
                if s != last_err {
                    log::debug!("pipe {pipe} not ready: {s}");
                }
                last_err = s;
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("helper bound {pipe} but the GUI could not reach it: {last_err}");
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
        .map(|&a| quote_arg(a))
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

/// Quote one argument for a Win32 command line per the `CommandLineToArgvW` rules:
/// backslashes are literal except before a `"`, where each must be doubled. Windows
/// paths can't contain `"`, but a value ending in `\` (e.g. a drive-root dir) would
/// otherwise escape the closing quote and swallow the next argument.
fn quote_arg(arg: &OsStr) -> String {
    let s = arg.to_string_lossy();
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push('\\');
            }
            '"' => {
                // Double the run of backslashes preceding the quote, then escape it.
                for _ in 0..=backslashes {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Double a trailing backslash run so it can't escape the closing quote.
    for _ in 0..backslashes {
        out.push('\\');
    }
    out.push('"');
    out
}
#[cfg(test)]
mod tests {
    use super::quote_arg;
    use std::ffi::OsStr;

    #[test]
    fn quotes_plain_args() {
        assert_eq!(quote_arg(OsStr::new("plain")), r#""plain""#);
        assert_eq!(
            quote_arg(OsStr::new(r"C:\Program Files\x")),
            r#""C:\Program Files\x""#
        );
    }

    #[test]
    fn doubles_trailing_backslashes() {
        // A value ending in `\` must not escape the closing quote (the bug this guards).
        assert_eq!(quote_arg(OsStr::new(r"C:\")), r#""C:\\""#);
        assert_eq!(quote_arg(OsStr::new(r"a\\")), r#""a\\\\""#);
    }

    #[test]
    fn escapes_embedded_quotes() {
        assert_eq!(quote_arg(OsStr::new(r#"a"b"#)), r#""a\"b""#);
        // Backslashes before a quote are doubled, then the quote itself escaped.
        assert_eq!(quote_arg(OsStr::new(r#"a\"b"#)), r#""a\\\"b""#);
    }
}
