//! The one place that knows how each desktop TUN engine is identified, launched
//! and torn down. Adding a new engine means a new arm in [`helper_bin`]/[`spawn`]
//! (plus its binary in [`DesktopPaths`]); the marker label is single-sourced from
//! core, and the data-path orchestration in `platform` stays engine-agnostic.

use std::path::Path;

use tokio::process::Child;

use kasumi_backend::lifecycle::spawn_tun_engine;
use kasumi_core::enums::{TunEngine, tun_from_marker, tun_marker};

use super::paths::DesktopPaths;

/// Wire label persisted to the tun-engine marker file (single-sourced from core's
/// serde value via [`tun_marker`]).
pub fn marker(tun: TunEngine) -> String {
    tun_marker(tun)
}

/// Parse a marker label back to its engine (`None` for unknown/legacy markers).
pub fn from_marker(s: &str) -> Option<TunEngine> {
    tun_from_marker(s)
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
        TunEngine::SingboxTun => None,
    }
}

/// Spawn the external helper for `tun`, bridging `iface` to the local SOCKS port.
/// Only valid for external engines ([`is_external`]).
pub async fn spawn(
    tun: TunEngine,
    p: &DesktopPaths,
    iface: &str,
    socks_port: u16,
    log: &Path,
    fwmark: Option<u32>,
) -> std::io::Result<Child> {
    let bin = helper_bin(tun, p).expect("spawn called for a helper-less (native) engine");
    spawn_tun_engine(tun, bin, iface, socks_port, log, fwmark).await
}
