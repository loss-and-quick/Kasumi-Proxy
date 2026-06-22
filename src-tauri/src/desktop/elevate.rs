//! Root elevation for the data-path: creating a tun device and editing the `ip`
//! routing table need `CAP_NET_ADMIN`.
//!
//! On Linux the GUI stays unprivileged and spawns a small root helper for the
//! data-path (see [`super::privhelper`]); this module only locates the elevator.
//! Windows still re-execs the whole process under UAC (no privsep there yet);
//! macOS has no elevation path.

/// Prefer a graphical pkexec (a polkit dialog suits a GUI), then sudo. On NixOS the
/// setuid wrappers live under /run/wrappers/bin (the store pkexec is NOT setuid).
#[cfg(target_os = "linux")]
pub(crate) fn find_elevator() -> Option<std::path::PathBuf> {
    use std::path::Path;
    for c in [
        "/run/wrappers/bin/pkexec",
        "/usr/bin/pkexec",
        "/run/wrappers/bin/sudo",
        "/usr/bin/sudo",
    ] {
        if Path::new(c).exists() {
            return Some(Path::new(c).to_path_buf());
        }
    }
    None
}

/// Re-exec the process elevated via UAC if it isn't already. `ShellExecuteW` with
/// the `runas` verb spawns the elevated copy and returns; the unprivileged original
/// then exits so only the elevated process remains — mirroring the Linux pkexec
/// whole-process model. Must run before any Tauri init.
#[cfg(target_os = "windows")]
pub fn ensure_elevated() {
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    // Already elevated, or the caller opted out (CI / just exercising the UI).
    if unsafe { IsUserAnAdmin() } != 0 || std::env::var_os("KASUMI_SKIP_ELEVATION").is_some() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    // Forward our args as one quoted command line (UAC re-launches a fresh process,
    // not a fork, so they must be passed through explicitly).
    let params = std::env::args_os()
        .skip(1)
        .map(|a| format!("\"{}\"", a.to_string_lossy().replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");

    let verb = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&params);
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };

    // ShellExecuteW returns a value > 32 on success. A failure (including the user
    // declining the UAC prompt) leaves us unprivileged — the data-path then fails
    // loudly at start, which the UI surfaces.
    if (result as usize) > 32 {
        std::process::exit(0);
    }
    eprintln!("kasumi-proxy: elevation declined or failed — tun/routing needs admin");
}

/// `s` as a NUL-terminated UTF-16 buffer for the Win32 `*W` APIs.
#[cfg(target_os = "windows")]
fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Other desktops (macOS) have no elevation path yet; run as-is.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn ensure_elevated() {}
