//! The one place that knows how each desktop TUN engine is identified, launched
//! and torn down. Adding a new engine means a new arm in [`helper_bin`]/[`spawn`]
//! (plus its binary in [`DesktopPaths`]); the marker label is single-sourced from
//! core, and the data-path orchestration in `platform` stays engine-agnostic.

use std::path::Path;

use tokio::process::Child;

use kasumi_backend::lifecycle::{TunSpawn, spawn_tun_engine};
use kasumi_core::enums::TunEngine;
// TUN_IPV4 is the address a self-addressing engine (hev) assigns to the tun it
// creates; sourced from core so it can't drift from what the routing layer assigns.
use kasumi_core::tun::{TUN_IPV4, TunOptions};

use super::paths::DesktopPaths;

/// The external helper binary a running `tun` engine uses. `SingboxTun` here means a
/// *sidecar* sing-box fronting a non-sing-box core (the native sing-box path never
/// reaches this — see `kasumi_core::core::owns_native_tun`), so its binary is
/// sing-box itself. `None` only for a mapping error.
pub fn helper_bin(tun: TunEngine, p: &DesktopPaths) -> Option<&str> {
    Some(match tun {
        TunEngine::Tun2socks => &p.tun2socks_bin,
        TunEngine::Hev => &p.hev_bin,
        TunEngine::SingboxTun => &p.singbox_bin,
    })
}

/// The config file the engine writes at bring-up (tun2socks/hev YAML, sidecar
/// sing-box JSON).
fn cfg_path(tun: TunEngine, p: &DesktopPaths) -> &str {
    match tun {
        TunEngine::Hev => &p.hev_config,
        TunEngine::SingboxTun => &p.singbox_bridge_config,
        TunEngine::Tun2socks => &p.tun2socks_config,
    }
}

/// Spawn the external helper for `tun`, bridging `iface` to the local SOCKS port.
/// The desktop external-tun path is IPv4-only, so no IPv6 is handed to a
/// self-addressing engine. `stack` is the sing-box tun stack (only the sidecar
/// sing-box reads it).
#[allow(clippy::too_many_arguments)]
pub async fn spawn(
    tun: TunEngine,
    p: &DesktopPaths,
    iface: &str,
    socks_port: u16,
    log: &Path,
    fwmark: Option<u32>,
    stack: &str,
    opts: &TunOptions,
) -> std::io::Result<Child> {
    let bin = helper_bin(tun, p).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no helper binary for the resolved tun engine",
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
        cfg_path: Path::new(cfg_path(tun, p)),
        stack,
        opts,
    };
    spawn_tun_engine(tun, &spawn).await
}
