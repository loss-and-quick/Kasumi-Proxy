//! Privilege separation for the Linux desktop data-path.
//!
//! Instead of re-execing the whole WebKit GUI as root, the GUI stays unprivileged
//! and spawns a small root helper that owns the data-path. They speak [`proto`]
//! over a unix socket. See [`super::elevate`] for the (current) whole-process
//! model this is migrating away from.

pub mod client;
pub mod proto;
pub mod remote;
pub mod server;
pub mod transport;

pub use client::Client;
pub use remote::RemotePlatform;

// Linux: the GUI spawns the root helper through pkexec/sudo and it exits with the
// GUI. Windows hosts the same data-path in a LocalSystem service under the SCM.
#[cfg(target_os = "linux")]
pub mod entry;
#[cfg(target_os = "linux")]
pub mod spawn;
#[cfg(target_os = "linux")]
pub use entry::run_helper;
#[cfg(target_os = "linux")]
pub use spawn::spawn_and_connect;
