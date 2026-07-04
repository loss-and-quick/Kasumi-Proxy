//! The one place that knows how each desktop TUN engine is identified, launched
//! and torn down. Adding a new engine means a new arm in [`helper_bin`]/[`spawn`]
//! (plus its binary in [`DesktopPaths`]); the marker label is single-sourced from
//! core, and the data-path orchestration in `platform` stays engine-agnostic.

use std::path::Path;

use tokio::process::Child;

use kasumi_backend::lifecycle::{TunSpawn, spawn_tun_engine};
use kasumi_core::enums::{TunEngine, tun_marker};
// TUN_IPV4 is the address a self-addressing engine (hev) assigns to the tun it
// creates; sourced from core so it can't drift from what the routing layer assigns.
use kasumi_core::tun::{TUN_IPV4, TunOptions};

use super::paths::DesktopPaths;

/// Wire label persisted to the tun-engine marker file (single-sourced from core's
/// serde value via [`tun_marker`]).
pub fn marker(tun: TunEngine) -> String {
    tun_marker(tun)
}

/// Whether the engine runs as an external helper process in front of a socks-only
/// core, vs the sing-box core owning its tun natively.
pub fn is_external(tun: TunEngine) -> bool {
    !matches!(tun, TunEngine::SingboxTun)
}

/// The external helper binary for `tun`, or `None` when the core owns the tun
/// (so teardown/the watchdog know which process, if any, to match).
pub fn helper_bin(tun: TunEngine, p: &DesktopPaths) -> Option<&str> {
    match tun {
        TunEngine::Tun2socks => Some(&p.tun2socks_bin),
        TunEngine::Hev => Some(&p.hev_bin),
        TunEngine::SingboxTun => None,
    }
}

/// Spawn the external helper for `tun`, bridging `iface` to the local SOCKS port.
/// Only valid for external engines ([`is_external`]). The desktop external-tun path
/// is IPv4-only, so no IPv6 is handed to a self-addressing engine.
pub async fn spawn(
    tun: TunEngine,
    p: &DesktopPaths,
    iface: &str,
    socks_port: u16,
    log: &Path,
    fwmark: Option<u32>,
    opts: &TunOptions,
) -> std::io::Result<Child> {
    // A helper-less (native `SingboxTun`) engine shouldn't reach here — callers gate
    // on `is_external` — but a corrupt marker could route it in. Error out rather
    // than panic: this runs in the privileged helper, whose crash strands the tun.
    let bin = helper_bin(tun, p).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "spawn called for a helper-less (native) engine",
        )
    })?;
    let spawn = TunSpawn {
        bin,
        iface,
        ipv4: TUN_IPV4,
        ipv6: None,
        socks_port,
        log_path: log,
        fwmark,
        cfg_path: Path::new(&p.hev_config),
        opts,
    };
    spawn_tun_engine(tun, &spawn).await
}
