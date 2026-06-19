//! Linux desktop `Platform`: the OS-specific half of the data-path, owning native
//! tun + `ip` routing ([`routing`]) and the active-uplink monitor ([`network`]).
//! Neutral lifecycle steps (config build, geo sync, core/tun2socks spawn, liveness
//! verify) come from `kasumi-backend`. No Magisk, no per-uid app filter.

pub mod elevate;
pub mod net;
pub mod network;
pub mod paths;
pub mod platform;
pub mod routing;
pub mod singbox;

pub use platform::DesktopPlatform;

use kasumi_backend::proc::{run, RunOpts};

/// Run a command, discarding output and returning its exit code. The desktop path
/// shells out to `ip`, so a `&str`-slice wrapper over the process layer keeps the
/// call sites readable.
pub(crate) async fn silent(args: &[&str]) -> i32 {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    kasumi_backend::proc::silent(&argv).await
}

/// Run a command, returning `(exit_code, stdout)`.
pub(crate) async fn run_out(args: &[&str]) -> (i32, String) {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    match run(&argv, RunOpts::default()).await {
        Ok(r) => (r.code, r.stdout),
        Err(_) => (-1, String::new()),
    }
}
