//! Android (Magisk/KernelSU/APatch) `Platform`: the OS-specific half of the
//! data-path. Neutral lifecycle steps (config build, geo sync, sing-box iface
//! injection, core/tun2socks spawn, liveness verify) come from `kasumi-backend`;
//! this owns routing ([`routing`]), sysctl locks ([`sysctl`]), `/dev/net/tun`, and
//! the per-uid app filter ([`platform`]).

pub mod network;
pub mod paths;
pub mod platform;
pub mod routing;
pub mod sysctl;

pub use platform::AndroidPlatform;

use kasumi_backend::proc::{RunOpts, run};

/// Run a shell command, discarding output and returning its exit code. The Android
/// platform shells out to `ip`/`iptables`/`pm`/etc., so a tiny `&str`-slice wrapper
/// over the backend's process layer keeps the call sites readable.
pub(crate) async fn silent(args: &[&str]) -> i32 {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    kasumi_backend::proc::silent(&argv).await
}

/// Run a shell command, returning `(exit_code, stdout)`.
pub(crate) async fn run_out(args: &[&str]) -> (i32, String) {
    let argv: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    match run(&argv, RunOpts::default()).await {
        Ok(r) => (r.code, r.stdout),
        Err(_) => (-1, String::new()),
    }
}

/// The interface owning the default route to `1.1.1.1` (`ip route get … dev <if>`).
pub(crate) async fn default_uplink() -> Option<String> {
    let (_, out) = run_out(&[paths::IP, "route", "get", "1.1.1.1"]).await;
    parse_dev(&out)
}

/// Pull the `dev <iface>` token out of an `ip route` line.
fn parse_dev(out: &str) -> Option<String> {
    let toks: Vec<&str> = out.split_whitespace().collect();
    toks.windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dev_token() {
        assert_eq!(
            parse_dev("1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.5 uid 0"),
            Some("wlan0".to_string())
        );
        assert_eq!(parse_dev("unreachable"), None);
    }
}
