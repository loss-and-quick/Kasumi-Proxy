//! Linux desktop `Platform`: the OS-specific half of the data-path, owning native
//! tun + `ip` routing ([`routing`]) and the active-uplink monitor ([`network`]).
//! Neutral lifecycle steps (config build, geo sync, core/tun2socks spawn, liveness
//! verify) come from `kasumi-backend`. No Magisk, no per-uid app filter. Shared
//! command helpers and DNS/address utilities live one level up in [`super`].

mod network;
mod paths;
mod platform;
mod routing;

pub use platform::DesktopPlatform;
