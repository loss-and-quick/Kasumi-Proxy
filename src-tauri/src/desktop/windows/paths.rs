//! Windows desktop on-disk layout and OS binaries. Neutral primitives (fs,
//! pid/process, tun-name, geo-sync, core spawn) live in `kasumi-backend`; this is
//! only the desktop specifics.
//!
//! Two layouts. **Portable** (a `portable.dat` marker sits next to the exe, as the
//! portable zip ships): all state lives in a `kasumi-proxy/` folder next to the exe
//! — nothing touches the user profile or registry, so it runs from a USB stick.
//! **Installed** (NSIS/MSI, no marker): the data dir honours `%APPDATA%` (roaming),
//! the runtime dir `%LOCALAPPDATA%`. `KASUMI_DATA_HOME` / `KASUMI_RUNTIME_DIR`
//! override either. The app runs elevated (one process — see
//! [`elevate`](crate::desktop::elevate)), so unlike the Linux pkexec split there is
//! no cross-user dir hand-off: the elevated process keeps the invoking user's env.

use std::path::{Path, PathBuf};

use kasumi_backend::BackendPaths;

/// The userspace tun's address + mask; `/15` covers the 198.18/15 test net.
pub const TUN_ADDR: &str = "198.18.0.1";
pub const TUN_MASK: &str = "255.254.0.0";

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Directory holding `path`, or `path` itself if it has no parent.
fn dir_of(path: &str) -> String {
    Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.to_string())
}

/// Resolved desktop paths. Built once at platform construction (the env/exe lookups
/// are stable for the process lifetime).
pub struct DesktopPaths {
    pub backend: BackendPaths,
    pub datadir: String,
    pub run_dir: String,
    pub pidfile: String,
    pub tun2socks_pidfile: String,
    /// Records the routes we installed (server bypass + split-default) so teardown
    /// is exact and idempotent.
    pub route_state_file: String,
    pub socks_port_file: String,
    pub engine_file: String,
    pub tun_iface_file: String,
    /// No force-proxy tun on desktop, but `inject_singbox_ifaces` still wants a path.
    pub tun2_iface_file: String,
    pub service_state_file: String,
    pub service_started_file: String,
    pub xray_bin: String,
    pub singbox_bin: String,
    pub tun2socks_bin: String,
    pub geodat2srs_bin: String,
    /// The wintun driver DLL bundled next to the cores. tun2socks loads it from
    /// disk (the xray path needs it); sing-box embeds its own copy.
    pub wintun_dll: String,
}

impl DesktopPaths {
    pub fn resolve() -> anyhow::Result<Self> {
        // Cores/tun2socks ship next to the app exe; KASUMI_BIN_DIR overrides for dev.
        let exe = std::env::current_exe()?.to_string_lossy().into_owned();
        let bin = env("KASUMI_BIN_DIR").unwrap_or_else(|| dir_of(&exe));
        let webroot = env("KASUMI_WEBROOT");

        // Portable build: a marker next to the exe pins all state beside the app
        // (run-from-anywhere, nothing in %APPDATA%/registry). Installed builds have
        // no marker and fall back to the roaming/local profile dirs.
        let exe_dir = dir_of(&exe);
        let portable = Path::new(&exe_dir).join("portable.dat").exists();
        let data_home = env("KASUMI_DATA_HOME")
            .or_else(|| portable.then(|| exe_dir.clone()))
            .or_else(|| env("APPDATA"))
            .ok_or_else(|| {
                anyhow::anyhow!("APPDATA is not set (and no KASUMI_DATA_HOME override)")
            })?;
        let runtime_base = env("KASUMI_RUNTIME_DIR")
            .or_else(|| portable.then(|| exe_dir.clone()))
            .or_else(|| env("LOCALAPPDATA"))
            .unwrap_or_else(|| data_home.clone());

        // Normalize the bases too, in case an override used forward slashes.
        let norm = |s: &str| s.replace('/', r"\");
        let bin = norm(&bin);
        let data_home = norm(&data_home);
        let runtime_base = norm(&runtime_base);

        let datadir = format!(r"{data_home}\kasumi-proxy");
        let run_dir = format!(r"{runtime_base}\kasumi-proxy\run");

        let backend = BackendPaths {
            data_dir: PathBuf::from(&datadir),
            srs_dir: PathBuf::from(&datadir),
            dat_dir: PathBuf::from(&datadir),
            app_state: PathBuf::from(format!(r"{datadir}\app-state.json")),
            profiles: PathBuf::from(format!(r"{datadir}\profiles.json")),
            xray_config: PathBuf::from(format!(r"{datadir}\config.json")),
            singbox_config: PathBuf::from(format!(r"{datadir}\singbox.json")),
            engine_file: PathBuf::from(format!(r"{datadir}\engine")),
            run_dir: PathBuf::from(&run_dir),
            ws_info: PathBuf::from(format!(r"{run_dir}\ws.json")),
            // The Tauri webview loads the UI natively (no loopback HTTP server), so
            // the backend serves no webroot. `KASUMI_WEBROOT` only matters for the
            // standalone daemon path, kept for parity.
            webroot: webroot.map(PathBuf::from),
        };

        Ok(Self {
            datadir: datadir.clone(),
            run_dir: run_dir.clone(),
            pidfile: format!(r"{run_dir}\core.pid"),
            tun2socks_pidfile: format!(r"{run_dir}\tun2socks.pid"),
            route_state_file: format!(r"{run_dir}\desktop-route.json"),
            socks_port_file: format!(r"{datadir}\local-socks-port"),
            engine_file: format!(r"{datadir}\engine"),
            tun_iface_file: format!(r"{datadir}\tun-iface"),
            tun2_iface_file: format!(r"{datadir}\tun2-iface"),
            service_state_file: format!(r"{datadir}\service-state"),
            service_started_file: format!(r"{datadir}\service-started"),
            xray_bin: format!(r"{bin}\xray.exe"),
            singbox_bin: format!(r"{bin}\sing-box.exe"),
            tun2socks_bin: format!(r"{bin}\tun2socks.exe"),
            geodat2srs_bin: format!(r"{bin}\geodat2srs.exe"),
            wintun_dll: format!(r"{bin}\wintun.dll"),
            backend,
        })
    }

    /// Core binaries a running pid may match.
    pub fn core_bins(&self) -> Vec<String> {
        vec![self.xray_bin.clone(), self.singbox_bin.clone()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_of_strips_last_segment() {
        assert_eq!(
            dir_of(r"C:\Program Files\Kasumi\kasumi.exe"),
            r"C:\Program Files\Kasumi"
        );
        assert_eq!(dir_of("kasumi.exe"), "kasumi.exe");
    }

    #[test]
    fn resolve_honours_data_home_override() {
        std::env::set_var("KASUMI_DATA_HOME", r"C:\kasumi-test-home");
        std::env::set_var("KASUMI_RUNTIME_DIR", r"C:\kasumi-test-run");
        let p = DesktopPaths::resolve().unwrap();
        assert_eq!(p.datadir, r"C:\kasumi-test-home\kasumi-proxy");
        assert_eq!(p.run_dir, r"C:\kasumi-test-run\kasumi-proxy\run");
        assert!(p.xray_bin.ends_with(r"\xray.exe"));
        std::env::remove_var("KASUMI_DATA_HOME");
        std::env::remove_var("KASUMI_RUNTIME_DIR");
    }
}
