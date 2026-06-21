//! Linux desktop on-disk layout and OS binaries. Neutral primitives (fs,
//! pid/process, tun-name, geo-sync, core spawn) live in `kasumi-backend`; this is
//! only the desktop specifics.
//!
//! The data dir honours `KASUMI_DATA_HOME` / `XDG_DATA_HOME`, the runtime dir
//! `KASUMI_RUNTIME_DIR` / `XDG_RUNTIME_DIR` — the launcher passes the invoking
//! user's dirs through `pkexec`, so the elevated daemon writes where the UI reads.
//!
//! **Portable** (a `portable.dat` marker sits next to the exe, as the portable zip
//! ships): all state lives in a `kasumi-proxy/` folder beside the exe — nothing
//! touches the user profile, so it runs from a USB stick. Both the unprivileged and
//! the re-exec'd root process resolve the same marker via `current_exe()`, so no env
//! hand-off is needed across the elevation seam.

use std::path::{Path, PathBuf};

use kasumi_backend::BackendPaths;

/// fwmark stamped on tun2socks' own upstream socket so it stays out of the tunnel.
pub const FWMARK: u32 = 0x1112;
/// The userspace tun's address; `/15` covers the CGNAT-ish 198.18/15 test net.
pub const TUN_ADDR: &str = "198.18.0.1/15";
pub const IP: &str = "ip";

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
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
}

impl DesktopPaths {
    pub fn resolve() -> anyhow::Result<Self> {
        // Cores/tun2socks ship next to the app binary; KASUMI_BIN_DIR overrides for dev.
        let exe = std::env::current_exe()?.to_string_lossy().into_owned();
        let exe_dir = dir_of(&exe);
        let bin = env("KASUMI_BIN_DIR").unwrap_or_else(|| exe_dir.clone());
        let webroot = env("KASUMI_WEBROOT");

        // Portable build: a marker next to the exe pins all state beside the app
        // (run-from-anywhere, nothing in the user profile). Installed builds have no
        // marker and fall back to the XDG/home dirs.
        let portable = Path::new(&exe_dir).join("portable.dat").exists();
        let data_home = env("KASUMI_DATA_HOME")
            .or_else(|| portable.then(|| exe_dir.clone()))
            .or_else(|| env("XDG_DATA_HOME"))
            .or_else(|| env("HOME").map(|h| format!("{h}/.local/share")))
            .ok_or_else(|| {
                anyhow::anyhow!("HOME is not set (and no KASUMI_DATA_HOME/XDG_DATA_HOME override)")
            })?;
        let runtime_base = env("KASUMI_RUNTIME_DIR")
            .or_else(|| portable.then(|| exe_dir.clone()))
            .or_else(|| env("XDG_RUNTIME_DIR"))
            .unwrap_or_else(|| data_home.clone());

        let datadir = format!("{data_home}/kasumi-proxy");
        let run_dir = format!("{runtime_base}/kasumi-proxy/run");

        let backend = BackendPaths {
            data_dir: PathBuf::from(&datadir),
            srs_dir: PathBuf::from(&datadir),
            dat_dir: PathBuf::from(&datadir),
            app_state: PathBuf::from(format!("{datadir}/app-state.json")),
            profiles: PathBuf::from(format!("{datadir}/profiles.json")),
            xray_config: PathBuf::from(format!("{datadir}/config.json")),
            singbox_config: PathBuf::from(format!("{datadir}/singbox.json")),
            engine_file: PathBuf::from(format!("{datadir}/engine")),
            run_dir: PathBuf::from(&run_dir),
            ws_info: PathBuf::from(format!("{run_dir}/ws.json")),
            // The Tauri webview loads the UI natively (no loopback HTTP server), so
            // the backend serves no webroot. `KASUMI_WEBROOT` only matters for the
            // standalone daemon path, kept for parity.
            webroot: webroot.map(PathBuf::from),
        };

        Ok(Self {
            datadir: datadir.clone(),
            run_dir: run_dir.clone(),
            pidfile: format!("{run_dir}/core.pid"),
            tun2socks_pidfile: format!("{run_dir}/tun2socks.pid"),
            route_state_file: format!("{run_dir}/desktop-route.json"),
            socks_port_file: format!("{datadir}/local-socks-port"),
            engine_file: format!("{datadir}/engine"),
            tun_iface_file: format!("{datadir}/tun-iface"),
            tun2_iface_file: format!("{datadir}/tun2-iface"),
            service_state_file: format!("{datadir}/service-state"),
            service_started_file: format!("{datadir}/service-started"),
            xray_bin: format!("{bin}/xray"),
            singbox_bin: format!("{bin}/sing-box"),
            tun2socks_bin: format!("{bin}/tun2socks"),
            geodat2srs_bin: format!("{bin}/geodat2srs"),
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
        assert_eq!(dir_of("/usr/lib/kasumi/kasumi"), "/usr/lib/kasumi");
        assert_eq!(dir_of("/kasumi"), "/");
        assert_eq!(dir_of("kasumi"), "/");
    }

    #[test]
    fn resolve_honours_data_home_override() {
        // Set a deterministic data home; resolve must place the datadir under it.
        std::env::set_var("KASUMI_DATA_HOME", "/tmp/kasumi-test-home");
        std::env::set_var("KASUMI_RUNTIME_DIR", "/tmp/kasumi-test-run");
        let p = DesktopPaths::resolve().unwrap();
        assert_eq!(p.datadir, "/tmp/kasumi-test-home/kasumi-proxy");
        assert_eq!(p.run_dir, "/tmp/kasumi-test-run/kasumi-proxy/run");
        assert!(p.xray_bin.ends_with("/xray"));
        std::env::remove_var("KASUMI_DATA_HOME");
        std::env::remove_var("KASUMI_RUNTIME_DIR");
    }
}
