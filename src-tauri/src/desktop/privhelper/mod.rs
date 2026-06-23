//! Privilege separation for the desktop data-path.
//!
//! Instead of running the whole WebKit GUI elevated, the GUI stays unprivileged and
//! drives a small privileged process that owns the data-path. They speak [`proto`]
//! over an OS transport ([`transport`]): a unix socket to a pkexec'd root helper on
//! Linux, a named pipe to a LocalSystem service on Windows. The request loop
//! ([`server`]), the client ([`client`]) and the GUI-side [`RemotePlatform`] are
//! shared; only the transport and the launch/lifecycle differ per OS.

pub mod client;
pub mod proto;
pub mod remote;
pub mod server;
pub mod transport;

pub use client::Client;
pub use remote::RemotePlatform;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod hlog;

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

#[cfg(target_os = "windows")]
pub mod connect;
#[cfg(target_os = "windows")]
pub mod service;
#[cfg(target_os = "windows")]
pub use connect::connect_service;
