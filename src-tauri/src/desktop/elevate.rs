//! Root elevation for the data-path: creating a tun device and editing the `ip`
//! routing table need `CAP_NET_ADMIN`. On Linux the app re-execs itself under a
//! setuid elevator (pkexec/sudo), carrying the invoking user's display + XDG dirs
//! across the privilege boundary (the elevator scrubs the env), so the elevated
//! instance can still open its window and reads/writes where the user expects.
//!
//! This is the single elevation seam; Windows UAC / macOS Authorization plug in
//! here later. Whether running the GUI itself as root (vs. a privileged data-path
//! sidecar) is the right long-term shape is an open question — for now it mirrors
//! the experiment, which ran the whole data-path elevated.

/// Display/runtime env the elevated GUI needs, plus the path overrides that point
/// the root instance back at the user's data. The elevator drops everything else.
#[cfg(target_os = "linux")]
const PASS_ENV: &[&str] = &[
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "HOME",
    // GTK/WebKit runtime paths set by the Nix GApps wrapper — the elevator scrubs
    // them, so the root GUI would otherwise lose its schemas / typelibs / loaders
    // (and dlopen'd libs like libayatana-appindicator). Forward them through.
    "XDG_DATA_DIRS",
    "LD_LIBRARY_PATH",
    "GI_TYPELIB_PATH",
    "GIO_EXTRA_MODULES",
    "GDK_PIXBUF_MODULE_FILE",
    "GSETTINGS_SCHEMA_DIR",
    "WEBKIT_DISABLE_DMABUF_RENDERER",
    "GDK_BACKEND",
    "KASUMI_DATA_HOME",
    "KASUMI_RUNTIME_DIR",
    "KASUMI_BIN_DIR",
    // The Nix wrapper points this at iproute2; pkexec scrubs PATH (no `ip` on
    // NixOS), so the elevated data-path needs the absolute `ip` dir forwarded.
    "KASUMI_IP_DIR",
    "KASUMI_WEBROOT",
    "KASUMI_SKIP_ELEVATION",
];

/// Re-exec the process as root if it isn't already. Returns on the elevated side
/// (or when no elevator is available — the data-path then fails loudly at start,
/// which the UI surfaces). Must run before any GTK/Tauri init.
#[cfg(target_os = "linux")]
pub fn ensure_elevated() {
    use std::os::unix::process::CommandExt;

    // Already root, or the caller opted out (already privileged via a service
    // wrapper / granted CAP_NET_ADMIN / just exercising the UI): skip the re-exec.
    if unsafe { libc::geteuid() } == 0 || std::env::var_os("KASUMI_SKIP_ELEVATION").is_some() {
        return;
    }
    let Some(elevator) = find_elevator() else {
        eprintln!(
            "kasumi-proxy: no setuid pkexec/sudo found — tun/routing needs root and will fail"
        );
        return;
    };
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    // `<elevator> env KEY=VAL... <exe> <args>`: the elevator runs `env` as root,
    // which restores our vars and then execs us. (pkexec/sudo both scrub the env.)
    let mut cmd = std::process::Command::new(elevator);
    cmd.arg("env");
    for key in PASS_ENV {
        if let Ok(val) = std::env::var(key) {
            cmd.arg(format!("{key}={val}"));
        }
    }
    cmd.arg(exe);
    cmd.args(std::env::args_os().skip(1));

    // `exec` replaces this image, so on success we never return; the elevated copy
    // takes over from main(). Only a spawn failure (or user-cancelled prompt) falls
    // through.
    let err = cmd.exec();
    eprintln!("kasumi-proxy: elevation failed: {err}");
    std::process::exit(1);
}

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
