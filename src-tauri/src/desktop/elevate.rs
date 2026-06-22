//! Elevation seam for the data-path: creating a tun device and editing the routing
//! table need `CAP_NET_ADMIN` (Linux) / administrator (Windows).
//!
//! The GUI itself stays unprivileged on both. This module only *locates* or *invokes*
//! the elevator the privilege helper needs: `find_elevator` for the Linux pkexec/sudo
//! spawn, `run_elevated` for the one-time Windows service install. macOS has no
//! elevation path yet.

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

/// Run `exe args` elevated via UAC (`ShellExecuteW` with the `runas` verb), used for
/// the one-time service install. Returns whether the elevated process was launched
/// (the user accepted the prompt); the caller waits for its effect. Unlike the old
/// whole-process model this never re-execs the GUI — only the tiny helper elevates.
#[cfg(target_os = "windows")]
pub(crate) fn run_elevated(exe: &std::path::Path, args: &[&std::ffi::OsStr]) -> bool {
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
    // ShellExecuteW returns > 32 on success (including a declined prompt as failure).
    (result as usize) > 32
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
#[cfg(target_os = "macos")]
pub fn ensure_elevated() {}
