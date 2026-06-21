//! Windows desktop specifics: the OS-specific half of the data-path, owning a wintun
//! tun + `route`/`netsh` routing ([`routing`]) and the active-uplink monitor
//! ([`network`]), plus the [`DesktopOs`](crate::desktop::platform::DesktopOs) seam
//! ([`os`]). The shared `Platform` impl, paths and command/DNS helpers live one level
//! up in [`super`].

pub(crate) mod network;
mod os;
pub(crate) mod routing;

pub(crate) use os::WindowsOs;
