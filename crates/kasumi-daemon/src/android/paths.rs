//! Android (Magisk/KernelSU/APatch) on-disk layout and OS binaries. Neutral
//! primitives (fs, pid/process, tun-name, geo-sync, core spawn) live in
//! `kasumi-backend`; this is only the module-specific paths.

use std::path::PathBuf;

use kasumi_backend::BackendPaths;

pub const MODDIR: &str = "/data/adb/modules/kasumi-proxy";
pub const DATADIR: &str = "/data/adb/kasumi-proxy";
pub const BIN: &str = "/data/adb/modules/kasumi-proxy/bin";
pub const RUN_DIR: &str = "/data/adb/kasumi-proxy/run";

/// The daemon's own pid, written on startup so `kasumi-proxy stop` (run by
/// `uninstall.sh`) can terminate it and trigger its graceful data-path teardown.
pub const DAEMON_PIDFILE: &str = "/data/adb/kasumi-proxy/run/daemon.pid";
pub const PIDFILE: &str = "/data/adb/kasumi-proxy/run/core.pid";
pub const TUN2SOCKS_PIDFILE: &str = "/data/adb/kasumi-proxy/run/tun2socks.pid";
pub const TUN2SOCKS2_PIDFILE: &str = "/data/adb/kasumi-proxy/run/tun2socks2.pid";

pub const SOCKS_PORT_FILE: &str = "/data/adb/kasumi-proxy/local-socks-port";
pub const ENGINE_FILE: &str = "/data/adb/kasumi-proxy/engine";
pub const TUN_IFACE_FILE: &str = "/data/adb/kasumi-proxy/tun-iface";
/// Records the running data-path's TUN engine (its wire label) so teardown and the
/// watchdog resolve the matching helper binary, mirroring the desktop marker.
pub const TUN_ENGINE_FILE: &str = "/data/adb/kasumi-proxy/run/tun-engine";
pub const TUN2_IFACE_FILE: &str = "/data/adb/kasumi-proxy/tun2-iface";
pub const SERVICE_STATE_FILE: &str = "/data/adb/kasumi-proxy/service-state";
pub const SERVICE_STARTED_FILE: &str = "/data/adb/kasumi-proxy/service-started";

pub const XRAY_BIN: &str = "/data/adb/modules/kasumi-proxy/bin/xray";
pub const SINGBOX_BIN: &str = "/data/adb/modules/kasumi-proxy/bin/sing-box";
pub const TUN2SOCKS_BIN: &str = "/data/adb/modules/kasumi-proxy/bin/tun2socks";
pub const GEODAT2SRS_BIN: &str = "/data/adb/modules/kasumi-proxy/bin/geodat2srs";
/// Core binaries a running pid may match.
pub const CORE_BINS: [&str; 2] = [XRAY_BIN, SINGBOX_BIN];

pub const IP: &str = "/system/bin/ip";
pub const IPTABLES: &str = "/system/bin/iptables";
pub const IP6TABLES: &str = "/system/bin/ip6tables";

/// The backend's on-disk locations for the Android module.
pub fn backend_paths() -> BackendPaths {
    let d = PathBuf::from(DATADIR);
    BackendPaths {
        data_dir: d.clone(),
        srs_dir: d.clone(),
        dat_dir: d.clone(),
        app_state: d.join("app-state.json"),
        profiles: d.join("profiles.json"),
        xray_config: d.join("config.json"),
        singbox_config: d.join("singbox.json"),
        engine_file: PathBuf::from(ENGINE_FILE),
        run_dir: PathBuf::from(RUN_DIR),
        ws_info: PathBuf::from(RUN_DIR).join("ws.json"),
        // The KSU manager renders this bundle natively; the daemon also serves it
        // over loopback HTTP so action.sh can open the same UI in a browser.
        webroot: Some(PathBuf::from(MODDIR).join("webroot")),
    }
}
