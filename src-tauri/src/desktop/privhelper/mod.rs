//! Privilege separation for the Linux desktop data-path.
//!
//! Instead of re-execing the whole WebKit GUI as root, the GUI stays unprivileged
//! and spawns a small root helper that owns the data-path. They speak [`proto`]
//! over a unix socket. See [`super::elevate`] for the (current) whole-process
//! model this is migrating away from.

pub mod client;
pub mod entry;
pub mod proto;
pub mod remote;
pub mod server;
pub mod spawn;

pub use client::Client;
pub use entry::run_helper;
pub use remote::RemotePlatform;
pub use spawn::spawn_and_connect;
