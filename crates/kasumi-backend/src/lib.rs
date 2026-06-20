//! Kasumi backend — the transport-neutral orchestration layer.
//!
//! Above [`kasumi_core`]'s pure domain logic, this crate owns everything that
//! touches the host: the [`Platform`] trait (OS operations each shell supplies),
//! process/filesystem/network primitives, and — landing in later Phase 2 slices —
//! the typed command dispatch, the data-path lifecycle and the `Service` that owns
//! it. Desktop wraps these as Tauri commands; the Android module's daemon exposes
//! them over a token-gated WS. Both call the same code; there is no control socket.

pub mod commands;
pub mod fs;
pub mod fsjson;
pub mod jobs;
pub mod lifecycle;
pub mod net;
pub mod platform;
pub mod proc;
pub mod service;
pub mod state;
pub mod sub_update;

#[cfg(test)]
mod testutil;

pub use commands::{dispatch, Command, CommandError, Response};
pub use platform::{AppInfo, BackendPaths, Engine, Platform, PlatformCapabilities};
pub use service::Service;
pub use sub_update::LifecycleControl;
