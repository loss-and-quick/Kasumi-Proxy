//! Desktop `Platform`: OS-neutral helpers plus the per-OS implementation. The
//! native tun + routing live in [`linux`] / [`windows`]; the shared command
//! helpers below and the DNS/address utilities ([`net`]) are reused by both.
//! Neutral lifecycle steps (config build, geo sync, core/tun2socks spawn, liveness
//! verify) come from `kasumi-backend`.

pub mod net;
pub mod singbox;

// Linux capability handling for the least-privilege data-path helper (drop the
// bounding set to the caps the data-path needs; grant test cores an ambient
// CAP_NET_RAW). cfg(linux) — `caps` is Linux-only and the helper is Linux-only.
#[cfg(target_os = "linux")]
pub mod capabilities;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod paths;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod platform;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use platform::DesktopPlatform;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{network, resume, routing, LinuxOs as OsSeam};

// Privilege separation: the GUI stays unprivileged, a privileged process owns the
// data-path — a root helper on Linux, a LocalSystem service on Windows.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod privhelper;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use windows::{network, resume, routing, WindowsOs as OsSeam};

use kasumi_backend::proc::{run, RunOpts};

/// Run a command, discarding output and returning its exit code. The desktop path
/// shells out to the OS routing tools (`ip` on Linux, `route`/`netsh` on Windows),
/// so a `&str`-slice wrapper over the process layer keeps the call sites readable.
pub(crate) async fn silent(args: &[&str]) -> i32 {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let code = kasumi_backend::proc::silent(&argv).await;
    if code != 0 {
        log::debug!("command exited {code}: {}", argv.join(" "));
    }
    code
}

/// Run a command, returning `(exit_code, stdout)`.
pub(crate) async fn run_out(args: &[&str]) -> (i32, String) {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    match run(&argv, RunOpts::default()).await {
        Ok(r) => (r.code, r.stdout),
        Err(e) => {
            log::debug!("command failed to run ({e}): {}", argv.join(" "));
            (-1, String::new())
        }
    }
}
