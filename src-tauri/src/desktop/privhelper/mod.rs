//! Privilege separation for the Linux desktop data-path.
//!
//! Instead of re-execing the whole WebKit GUI as root, the GUI stays unprivileged
//! and spawns a small root helper that owns the data-path. They speak [`proto`]
//! over a unix socket. See [`super::elevate`] for the (current) whole-process
//! model this is migrating away from.

pub mod client;
pub mod proto;
pub mod server;
