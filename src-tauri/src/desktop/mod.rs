//! Desktop `Platform`: OS-neutral helpers plus the per-OS implementation. The
//! native tun + routing live in [`linux`] / [`windows`]; the shared command
//! helpers below and the DNS/address utilities ([`net`]) are reused by both.
//! Neutral lifecycle steps (config build, geo sync, core/tun2socks spawn, liveness
//! verify) come from `kasumi-backend`.

pub mod net;
pub mod pac;
pub mod singbox;
pub mod sysproxy;

// Linux capability handling for the least-privilege data-path helper (drop the
// bounding set to the caps the data-path needs; raise an ambient CAP_NET_ADMIN so
// exec'd children inherit it; grant test cores an ambient CAP_NET_RAW). cfg(linux) —
// `caps` is Linux-only and the helper is Linux-only.
#[cfg(target_os = "linux")]
pub mod capabilities;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod paths;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod platform;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod tun_engine;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub use platform::DesktopPlatform;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{LinuxOs as OsSeam, network, resume, routing};

// Privilege separation: the GUI stays unprivileged, a privileged process owns the
// data-path — a root helper on Linux, a LocalSystem service on Windows.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod privhelper;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub(crate) use windows::{WindowsOs as OsSeam, network, resume, routing};

use kasumi_backend::proc::{RunOpts, run};
use kasumi_core::state::ProxyMode;

/// Align the OS-level proxy with the active `mode`: `system` points the OS proxy at
/// the core's local inbound, `pac` starts the PAC server and points the OS at it;
/// every other mode clears any previously-set one, so a mode switch can't leave a
/// stale OS proxy behind. Runs in the GUI process (the logged-in user's session —
/// see [`sysproxy`]), never in the privileged helper.
///
/// The first apply snapshots the pre-existing OS proxy into an ownership record so a
/// later clear restores it rather than blanking a proxy the user set by hand.
pub async fn apply_os_proxy(mode: ProxyMode, socks_port: u16, http_port: u16, pac_port: u16) {
    match mode {
        ProxyMode::System => {
            pac::stop().await;
            sysproxy::set_system_proxy(socks_port, http_port).await;
        }
        ProxyMode::Pac => {
            if let Some(url) = pac::start(pac_port, http_port, socks_port).await {
                sysproxy::set_pac(&url).await;
            } else {
                // The PAC port is taken — leave the OS un-proxied rather than
                // pointed at someone else's server.
                log::error!("pac server failed to bind; OS proxy left cleared");
                sysproxy::clear_system_proxy().await;
            }
        }
        ProxyMode::Tun | ProxyMode::ProxyOnly => clear_os_proxy().await,
    }
}

/// The persisted proxy mode, read as a bare field from `<datadir>/app-state.json`,
/// defaulting to [`ProxyMode::Tun`] on any failure (unresolvable paths, missing file,
/// parse error, absent key). Deliberately a bare-field read — not the full [`AppState`]
/// schema/migration — so a legacy or foreign document still answers sanely; the safe
/// default matches the always-privileged behaviour, so a bad read never silently drops
/// the helper for a tun user.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn saved_proxy_mode() -> ProxyMode {
    let Ok(paths) = paths::DesktopPaths::resolve() else {
        return ProxyMode::Tun;
    };
    let Ok(text) = std::fs::read_to_string(&paths.backend.app_state) else {
        return ProxyMode::Tun;
    };
    proxy_mode_from_state(&text)
}

/// Pull `settings.proxyMode` out of a raw `app-state.json` document, falling back to
/// [`ProxyMode::Tun`] when the JSON is unparseable, the key is absent, or the value
/// isn't one of the four modes.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn proxy_mode_from_state(text: &str) -> ProxyMode {
    let extract = || -> Option<ProxyMode> {
        let doc: serde_json::Value = serde_json::from_str(text).ok()?;
        let field = doc.get("settings")?.get("proxyMode")?.clone();
        serde_json::from_value::<ProxyMode>(field).ok()
    };
    extract().unwrap_or(ProxyMode::Tun)
}

/// Undo [`apply_os_proxy`]: stop the PAC server, then restore the OS proxy from the
/// ownership record and drop it. With no record the current OS proxy isn't ours and
/// is left untouched. Idempotent — safe whatever mode was (or wasn't) active.
pub async fn clear_os_proxy() {
    pac::stop().await;
    sysproxy::clear_system_proxy().await;
}

/// Run a command, discarding output and returning its exit code. The desktop path
/// shells out to the OS routing tools (`ip` on Linux, `route`/`netsh` on Windows),
/// so a `&str`-slice wrapper over the process layer keeps the call sites readable.
///
/// The mutating `ip` calls need `CAP_NET_ADMIN`; under the caps-only launcher the
/// exec'd `ip` inherits it from the helper's ambient set (raised once at startup in
/// `capabilities::raise_net_admin_ambient`), so no per-call cap handling here.
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

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod tests {
    use super::*;

    #[test]
    fn proxy_mode_reads_each_value() {
        for (wire, expected) in [
            ("tun", ProxyMode::Tun),
            ("proxy-only", ProxyMode::ProxyOnly),
            ("system", ProxyMode::System),
            ("pac", ProxyMode::Pac),
        ] {
            let doc = format!(r#"{{"settings":{{"proxyMode":"{wire}"}}}}"#);
            assert_eq!(proxy_mode_from_state(&doc), expected, "for {wire}");
        }
    }

    #[test]
    fn proxy_mode_defaults_to_tun_on_bad_input() {
        // Corrupt JSON, absent key, wrong-typed value and an unknown mode all fall
        // back to the safe always-privileged default.
        assert_eq!(proxy_mode_from_state("{ not json"), ProxyMode::Tun);
        assert_eq!(proxy_mode_from_state("{}"), ProxyMode::Tun);
        assert_eq!(proxy_mode_from_state(r#"{"settings":{}}"#), ProxyMode::Tun);
        assert_eq!(
            proxy_mode_from_state(r#"{"settings":{"proxyMode":42}}"#),
            ProxyMode::Tun
        );
        assert_eq!(
            proxy_mode_from_state(r#"{"settings":{"proxyMode":"bogus"}}"#),
            ProxyMode::Tun
        );
    }
}
