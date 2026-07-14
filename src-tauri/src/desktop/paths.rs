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

/// Env-var contract between the GUI and the privilege helper across the privilege
/// boundary (pkexec args on Linux, the service launch arguments on Windows): the
/// helper is handed these verbatim so both sides resolve identically. Read in
/// [`DesktopPaths::resolve`], set by the helper/service entry point.
pub(crate) const ENV_DATADIR: &str = "KASUMI_DATADIR";
pub(crate) const ENV_RUNDIR: &str = "KASUMI_RUNDIR";
pub(crate) const ENV_BIN_DIR: &str = "KASUMI_BIN_DIR";

/// CLI flags carrying the same three dirs across the privilege boundary (the value
/// the helper re-exports into [`ENV_DATADIR`] etc). One source so the producers (the
/// Linux pkexec spawn, the Windows service/transient launch) and the helper parsers
/// can't drift apart on a flag name.
pub(crate) const ARG_DATADIR: &str = "--datadir";
pub(crate) const ARG_RUNDIR: &str = "--rundir";
pub(crate) const ARG_BIN_DIR: &str = "--bin-dir";

/// Leaf name of the privilege helper's own log, under `run_dir`. One source so the
/// helper's logger and the owner hand-off (which chowns it back to the GUI user)
/// name the same file.
pub(crate) const HELPER_LOG_FILE: &str = "kasumi-helper.log";

/// The `(flag, value)` triple every privilege-boundary launch passes so the helper
/// resolves the GUI's exact dirs. Producer-side single source (the bin dir is the
/// parent of the resolved xray path); the helper parses the same flags back.
pub(crate) fn path_args(paths: &DesktopPaths) -> [(&'static str, String); 3] {
    [
        (ARG_DATADIR, paths.datadir.clone()),
        (ARG_RUNDIR, paths.run_dir.clone()),
        (ARG_BIN_DIR, dir_of(&paths.xray_bin)),
    ]
}

/// Resolved desktop paths. Built once at platform construction (the env/exe lookups
/// are stable for the process lifetime).
pub struct DesktopPaths {
    pub backend: BackendPaths,
    pub datadir: String,
    pub run_dir: String,
    /// A portable build (a `portable.dat` marker beside the exe): state lives beside
    /// the app and the privileged helper runs transiently rather than as an installed
    /// service (Windows), so nothing is left behind.
    pub portable: bool,
    pub pidfile: String,
    pub tun2socks_pidfile: String,
    /// Records the routes we installed (server bypass + split-default) so teardown
    /// is exact and idempotent.
    pub route_state_file: String,
    pub socks_port_file: String,
    pub engine_file: String,
    /// Records the resolved TUN engine of the running data-path (its wire label),
    /// so teardown + the watchdog know which helper (if any) to expect.
    pub tun_engine_file: String,
    pub tun_iface_file: String,
    /// No force-proxy tun on desktop, but `inject_singbox_ifaces` still wants a path.
    pub tun2_iface_file: String,
    pub service_state_file: String,
    pub service_started_file: String,
    pub xray_bin: String,
    pub singbox_bin: String,
    pub tun2socks_bin: String,
    /// hev-socks5-tunnel helper binary (the alternative external TUN engine).
    pub hev_bin: String,
    /// Where hev's generated YAML config is written at bring-up (run_dir).
    pub hev_config: String,
    /// Where tun2socks' generated YAML config is written at bring-up (run_dir).
    pub tun2socks_config: String,
    /// Where the sidecar sing-box (SingboxTun engine on a non-sing-box core) writes
    /// its generated bridge config at bring-up (run_dir).
    pub singbox_bridge_config: String,
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

    /// External TUN helper binaries a running pid may match. Used to guard teardown:
    /// a stale helper pidfile whose pid was recycled by an unrelated process must not
    /// be signalled (the data-path runs privileged). Covers every engine's helper —
    /// tun2socks, hev, and the sidecar sing-box (`singbox_bin`, which is also a core
    /// binary; the helper pidfile only ever holds the sidecar's pid) — so an orphaned
    /// helper of any engine is still reaped. New engines add their binary here
    /// alongside their [`tun_engine::helper_bin`] arm.
    pub fn helper_bins(&self) -> Vec<String> {
        vec![
            self.tun2socks_bin.clone(),
            self.hev_bin.clone(),
            self.singbox_bin.clone(),
        ]
    }
}

/// Runtime files the privileged data-path owner creates and that must be handed to
/// the unprivileged GUI user, so an unprivileged in-process owner can later operate
/// over the same paths. Every entry is a regular file derived from a
/// [`DesktopPaths`]/[`BackendPaths`] field — the ephemeral run-dir state and engine
/// configs the data-path writes, the core logs its children write under datadir, and
/// the helper's own log. Excludes GUI-written inputs (`engine_file`, the built core
/// configs, `daemon.log`); the containing directories are handed over separately
/// (see [`DesktopPaths::helper_owned_dirs`]).
#[cfg(target_os = "linux")]
impl DesktopPaths {
    pub(crate) fn helper_owned_files(&self) -> Vec<PathBuf> {
        use kasumi_core::contract::LogTarget;
        vec![
            PathBuf::from(&self.pidfile),
            PathBuf::from(&self.tun2socks_pidfile),
            PathBuf::from(&self.route_state_file),
            PathBuf::from(&self.socks_port_file),
            PathBuf::from(&self.tun_engine_file),
            PathBuf::from(&self.tun_iface_file),
            PathBuf::from(&self.tun2_iface_file),
            PathBuf::from(&self.service_state_file),
            PathBuf::from(&self.service_started_file),
            PathBuf::from(&self.hev_config),
            PathBuf::from(&self.tun2socks_config),
            PathBuf::from(&self.singbox_bridge_config),
            self.backend.log(LogTarget::Xray),
            self.backend.log(LogTarget::Singbox),
            self.backend.log(LogTarget::TunEngine),
            self.backend.run_dir.join(HELPER_LOG_FILE),
        ]
    }

    /// The app-owned directory inodes the privileged data-path owner may have
    /// created (root-side `create_dir_all` at boot): `run_dir` itself and its
    /// `kasumi-proxy` parent when that is our namespace level. Chowning the file
    /// list alone grants content-write but not create/unlink — those live on the
    /// containing directory — so these two inodes are handed over as well, still
    /// strictly non-recursive: nothing beneath them is touched by this list.
    pub(crate) fn helper_owned_dirs(&self) -> Vec<PathBuf> {
        let run = PathBuf::from(&self.run_dir);
        let mut dirs = vec![run.clone()];
        if let Some(parent) = run.parent()
            && parent.file_name().is_some_and(|n| n == "kasumi-proxy")
        {
            dirs.push(parent.to_path_buf());
        }
        dirs
    }
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// Directory holding `path`, or `/` if it has no parent.
#[cfg(target_os = "linux")]
pub(crate) fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// Directory holding `path`, or `path` itself if it has no parent.
#[cfg(target_os = "windows")]
pub(crate) fn dir_of(path: &str) -> String {
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
        let bin = env(ENV_BIN_DIR).unwrap_or_else(|| exe_dir.clone());
        let webroot = env("KASUMI_WEBROOT");

        // Portable build: a marker next to the exe pins all state beside the app
        // (run-from-anywhere, nothing in the user profile). Installed builds have no
        // marker and fall back to the XDG/home dirs.
        let portable = std::path::Path::new(&exe_dir).join("portable.dat").exists();

        // The privilege helper is handed the GUI's already-resolved dirs verbatim
        // (KASUMI_DATADIR / KASUMI_RUNDIR), so both sides agree exactly across the
        // pkexec boundary — which scrubs HOME/XDG, so re-deriving them would drift
        // or fail. When set, they win and short-circuit the base lookups below.
        let datadir_override = env(ENV_DATADIR);
        let rundir_override = env(ENV_RUNDIR);

        let datadir = match &datadir_override {
            Some(d) => d.clone(),
            None => {
                let data_home = env("KASUMI_DATA_HOME")
                    .or_else(|| portable.then(|| exe_dir.clone()))
                    .or_else(|| env("XDG_DATA_HOME"))
                    .or_else(|| env("HOME").map(|h| format!("{h}/.local/share")))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "HOME is not set (and no KASUMI_DATA_HOME/XDG_DATA_HOME override)"
                        )
                    })?;
                format!("{data_home}/kasumi-proxy")
            }
        };
        let run_dir = match &rundir_override {
            Some(r) => r.clone(),
            None => {
                let runtime_base = env("KASUMI_RUNTIME_DIR")
                    .or_else(|| portable.then(|| exe_dir.clone()))
                    .or_else(|| env("XDG_RUNTIME_DIR"))
                    .unwrap_or_else(|| dir_of(&datadir));
                format!("{runtime_base}/kasumi-proxy/run")
            }
        };

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
            portable,
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
            tun_engine_file: format!("{run_dir}/tun-engine"),
            tun_iface_file: format!("{run_dir}/tun-iface"),
            tun2_iface_file: format!("{run_dir}/tun2-iface"),
            service_state_file: format!("{run_dir}/service-state"),
            service_started_file: format!("{run_dir}/service-started"),
            xray_bin: format!("{bin}/xray"),
            singbox_bin: format!("{bin}/sing-box"),
            tun2socks_bin: format!("{bin}/tun2socks"),
            hev_bin: format!("{bin}/hev-socks5-tunnel"),
            hev_config: format!("{run_dir}/hev.yml"),
            tun2socks_config: format!("{run_dir}/tun2socks.yml"),
            singbox_bridge_config: format!("{run_dir}/singbox-bridge.json"),
            geodat2srs_bin: format!("{bin}/geodat2srs"),
            backend,
        })
    }
}

#[cfg(target_os = "windows")]
impl DesktopPaths {
    pub fn resolve() -> anyhow::Result<Self> {
        // Cores/tun2socks ship next to the app exe; KASUMI_BIN_DIR overrides for dev
        // and is how the GUI hands the service its bin dir across the service boundary.
        let exe = std::env::current_exe()?.to_string_lossy().into_owned();
        let bin = env(ENV_BIN_DIR).unwrap_or_else(|| dir_of(&exe));
        let webroot = env("KASUMI_WEBROOT");

        // Portable build: a marker next to the exe pins all state beside the app
        // (run-from-anywhere, nothing in %APPDATA%/registry). Installed builds have
        // no marker and fall back to the roaming/local profile dirs.
        let exe_dir = dir_of(&exe);
        let portable = std::path::Path::new(&exe_dir).join("portable.dat").exists();

        // The service is handed the GUI's already-resolved dirs as launch arguments
        // (KASUMI_DATADIR / KASUMI_RUNDIR), so SYSTEM lands on the GUI user's dirs
        // rather than its own profile. When set, they win and are used verbatim.
        let datadir_override = env(ENV_DATADIR);
        let rundir_override = env(ENV_RUNDIR);

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

        let datadir = match &datadir_override {
            Some(d) => norm(d),
            None => format!(r"{data_home}\kasumi-proxy"),
        };
        let run_dir = match &rundir_override {
            Some(r) => norm(r),
            None => format!(r"{runtime_base}\kasumi-proxy\run"),
        };

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
            portable,
            pidfile: format!(r"{run_dir}\core.pid"),
            tun2socks_pidfile: format!(r"{run_dir}\tun2socks.pid"),
            route_state_file: format!(r"{run_dir}\desktop-route.json"),
            // Ephemeral data-path runtime state lives in run_dir (see the Linux
            // resolve for the rationale); engine_file + configs stay in datadir.
            socks_port_file: format!(r"{run_dir}\local-socks-port"),
            engine_file: format!(r"{datadir}\engine"),
            tun_engine_file: format!(r"{run_dir}\tun-engine"),
            tun_iface_file: format!(r"{run_dir}\tun-iface"),
            tun2_iface_file: format!(r"{run_dir}\tun2-iface"),
            service_state_file: format!(r"{run_dir}\service-state"),
            service_started_file: format!(r"{run_dir}\service-started"),
            xray_bin: format!(r"{bin}\xray.exe"),
            singbox_bin: format!(r"{bin}\sing-box.exe"),
            tun2socks_bin: format!(r"{bin}\tun2socks.exe"),
            hev_bin: format!(r"{bin}\hev-socks5-tunnel.exe"),
            hev_config: format!(r"{run_dir}\hev.yml"),
            tun2socks_config: format!(r"{run_dir}\tun2socks.yml"),
            singbox_bridge_config: format!(r"{run_dir}\singbox-bridge.json"),
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
        let _env = crate::env_test_guard();
        // Set a deterministic data home; resolve must place the datadir under it.
        // SAFETY (Rust 1.95): set_var/remove_var are unsafe because concurrent env
        // access is UB. These env-mutating tests pre-date that and were never safe
        // under cargo's parallel runner — the mutations are kept local + bracketed
        // (set, assert, restore) so each test is self-consistent.
        unsafe {
            std::env::set_var("KASUMI_DATA_HOME", "/tmp/kasumi-test-home");
            std::env::set_var("KASUMI_RUNTIME_DIR", "/tmp/kasumi-test-run");
        }
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

        // The owner hand-off list: only regular files under run_dir/datadir covering
        // the helper-written run-dir state, engine configs, core logs and helper log.
        let owned = p.helper_owned_files();
        for f in &owned {
            let s = f.to_string_lossy();
            assert!(
                s.starts_with(&p.run_dir) || s.starts_with(&p.datadir),
                "{s} should live under run_dir or datadir"
            );
        }
        let names: std::collections::HashSet<&str> = owned
            .iter()
            .map(|f| f.file_name().unwrap().to_str().unwrap())
            .collect();
        for expected in [
            "core.pid",
            "tun2socks.pid",
            "desktop-route.json",
            "local-socks-port",
            "tun-engine",
            "tun-iface",
            "tun2-iface",
            "service-state",
            "service-started",
            "hev.yml",
            "tun2socks.yml",
            "singbox-bridge.json",
            "xray.log",
            "singbox.log",
            "tun-engine.log",
            "kasumi-helper.log",
        ] {
            assert!(names.contains(expected), "hand-off list missing {expected}");
        }
        // GUI-written inputs stay out — they are already the user's.
        assert!(!names.contains("engine"), "engine marker is GUI-written");
        assert!(!names.contains("daemon.log"), "daemon.log is GUI-written");
        assert!(!names.contains("config.json"), "config.json is GUI-written");

        // The directory hand-off: run_dir itself plus its kasumi-proxy namespace
        // parent, and nothing else (never datadir — the GUI creates that).
        let dirs = p.helper_owned_dirs();
        assert_eq!(dirs[0], std::path::PathBuf::from(&p.run_dir));
        assert!(
            dirs.iter()
                .all(|d| d.to_string_lossy().starts_with(&p.run_dir)
                    || d.file_name().is_some_and(|n| n == "kasumi-proxy")),
            "only run_dir and its namespace parent are handed over"
        );
        assert!(
            !dirs.iter().any(|d| d.as_os_str() == p.datadir.as_str()),
            "datadir inode must stay untouched"
        );

        // SAFETY: see the note on the first `set_var` in this test.
        unsafe {
            std::env::remove_var("KASUMI_DATA_HOME");
            std::env::remove_var("KASUMI_RUNTIME_DIR");
        }

        // Verbatim overrides: what the GUI hands the privilege helper across the
        // pkexec boundary — exact dirs, used as-is (no "/kasumi-proxy" suffix), with
        // HOME absent (pkexec scrubs it). Same test so the env mutations stay
        // sequential (tests in a file otherwise run in parallel).
        let home = std::env::var("HOME").ok();
        // SAFETY: see the note on the first `set_var` in this test.
        unsafe {
            std::env::remove_var("HOME");
            std::env::remove_var("XDG_DATA_HOME");
            std::env::set_var("KASUMI_DATADIR", "/var/lib/kasumi-proxy");
            std::env::set_var("KASUMI_RUNDIR", "/run/kasumi-proxy/run");
        }
        let p = DesktopPaths::resolve().unwrap();
        assert_eq!(p.datadir, "/var/lib/kasumi-proxy");
        assert_eq!(p.run_dir, "/run/kasumi-proxy/run");
        assert!(p.service_state_file.starts_with("/run/kasumi-proxy/run"));
        assert!(p.engine_file.starts_with("/var/lib/kasumi-proxy"));
        // SAFETY: see the note on the first `set_var` in this test.
        unsafe {
            std::env::remove_var("KASUMI_DATADIR");
            std::env::remove_var("KASUMI_RUNDIR");
            if let Some(h) = home {
                std::env::set_var("HOME", h);
            }
        }
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
        let _env = crate::env_test_guard();
        // SAFETY (Rust 1.95): set_var/remove_var are unsafe; this test is the only
        // env-touching one in the module and the mutations are bracketed.
        unsafe {
            std::env::set_var("KASUMI_DATA_HOME", r"C:\kasumi-test-home");
            std::env::set_var("KASUMI_RUNTIME_DIR", r"C:\kasumi-test-run");
        }
        let p = DesktopPaths::resolve().unwrap();
        assert_eq!(p.datadir, r"C:\kasumi-test-home\kasumi-proxy");
        assert_eq!(p.run_dir, r"C:\kasumi-test-run\kasumi-proxy\run");
        assert!(p.xray_bin.ends_with(r"\xray.exe"));
        // SAFETY: see the matching `set_var` above.
        unsafe {
            std::env::remove_var("KASUMI_DATA_HOME");
            std::env::remove_var("KASUMI_RUNTIME_DIR");
        }
    }
}
