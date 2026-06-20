//! Windows desktop `Platform`: the OS-specific half of the data-path, owning a
//! wintun tun + `route`/`netsh` routing ([`routing`]) and the active-uplink monitor
//! ([`network`]). Neutral lifecycle steps (config build, geo sync, core/tun2socks
//! spawn, liveness verify) come from `kasumi-backend`; sing-box config finalisation
//! is shared with Linux in [`super::singbox`].

mod network;
mod paths;
mod platform;
mod routing;

pub use platform::DesktopPlatform;
