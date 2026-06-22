//! Desktop on-disk layout and OS binaries, shared by Linux and Windows. The struct
//! and `core_bins()` are identical across both; only `resolve()` (env bases, path
//! separator) and the Windows-only `wintun_dll` are OS-specific, gated by `cfg`.
//! Neutral primitives (fs, pid/process, tun-name, geo-sync, core spawn) live in
//! `kasumi-backend`; this is only the desktop specifics.
//!
//! **Portable** (a `portable.dat` marker sits next to the exe, as the portable zip
//! ships): all state lives in a `kasumi-proxy/` folder beside the exe — nothing
//! touches the user profile, so it runs from a USB stick. Installed builds have no
//! marker and fall back to the XDG/home (Linux) or `%APPDATA%`/`%LOCALAPPDATA%`
//! (Windows) dirs. `KASUMI_DATA_HOME` / `KASUMI_RUNTIME_DIR` override either.

use std::path::PathBuf;

use kasumi_backend::BackendPaths;

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
    /// The wintun driver DLL bundled next to the cores. tun2socks loads it from disk
    /// (the xray path needs it); sing-box embeds its own copy.
    #[cfg(target_os = "windows")]
    pub wintun_dll: String,
}

impl DesktopPaths {
    /// Core binaries a running pid may match.
    pub fn core_bins(&self) -> Vec<String> {
        vec![self.xray_bin.clone(), self.singbox_bin.clone()]
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// Directory holding `path`, or `path` itself if it has no parent.
#[cfg(target_os = "windows")]
fn dir_of(path: &str) -> String {
    std::path::Path::new(path)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.to_string())
}

#[cfg(target_os = "linux")]
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
        let portable = std::path::Path::new(&exe_dir).join("portable.dat").exists();
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
            // Ephemeral data-path runtime state, written only by the data-path owner
            // (the privileged helper under privilege separation) — keep it in run_dir,
            // not the user's datadir, so it never lands as root-owned files there and
            // resets between sessions. `engine_file` and the configs stay in datadir:
            // the unprivileged GUI builds them, the helper only reads them.
            socks_port_file: format!("{run_dir}/local-socks-port"),
            engine_file: format!("{datadir}/engine"),
            tun_iface_file: format!("{run_dir}/tun-iface"),
            tun2_iface_file: format!("{run_dir}/tun2-iface"),
            service_state_file: format!("{run_dir}/service-state"),
            service_started_file: format!("{run_dir}/service-started"),
            xray_bin: format!("{bin}/xray"),
            singbox_bin: format!("{bin}/sing-box"),
            tun2socks_bin: format!("{bin}/tun2socks"),
            geodat2srs_bin: format!("{bin}/geodat2srs"),
            backend,
        })
    }
}

#[cfg(target_os = "windows")]
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
        let portable = std::path::Path::new(&exe_dir).join("portable.dat").exists();
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
            // Ephemeral data-path runtime state lives in run_dir (see the Linux
            // resolve for the rationale); engine_file + configs stay in datadir.
            socks_port_file: format!(r"{run_dir}\local-socks-port"),
            engine_file: format!(r"{datadir}\engine"),
            tun_iface_file: format!(r"{run_dir}\tun-iface"),
            tun2_iface_file: format!(r"{run_dir}\tun2-iface"),
            service_state_file: format!(r"{run_dir}\service-state"),
            service_started_file: format!(r"{run_dir}\service-started"),
            xray_bin: format!(r"{bin}\xray.exe"),
            singbox_bin: format!(r"{bin}\sing-box.exe"),
            tun2socks_bin: format!(r"{bin}\tun2socks.exe"),
            geodat2srs_bin: format!(r"{bin}\geodat2srs.exe"),
            wintun_dll: format!(r"{bin}\wintun.dll"),
            backend,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
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
        // Privilege-domain split: ephemeral data-path state (helper-written) under
        // run_dir; GUI-written inputs (engine + configs) under datadir.
        for f in [
            &p.socks_port_file,
            &p.service_state_file,
            &p.service_started_file,
            &p.tun_iface_file,
            &p.tun2_iface_file,
            &p.route_state_file,
            &p.pidfile,
        ] {
            assert!(f.starts_with(&p.run_dir), "{f} should live under run_dir");
        }
        assert!(p.engine_file.starts_with(&p.datadir));
        assert!(p.backend.xray_config.starts_with(&p.datadir));
        std::env::remove_var("KASUMI_DATA_HOME");
        std::env::remove_var("KASUMI_RUNTIME_DIR");
    }
}

#[cfg(all(test, target_os = "windows"))]
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
