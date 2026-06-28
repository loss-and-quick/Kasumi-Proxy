//! Linux desktop specifics: the OS-specific half of the data-path, owning native
//! tun + `ip` routing ([`routing`]) and the active-uplink monitor ([`network`]),
//! plus the [`DesktopOs`](crate::desktop::platform::DesktopOs) seam ([`os`]). The
//! shared `Platform` impl, paths and command/DNS helpers live one level up in
//! [`super`]. No Magisk, no per-uid app filter.

pub(crate) mod network;
mod os;
pub(crate) mod resume;
pub(crate) mod routing;

pub(crate) use os::LinuxOs;
