//! Tauri 2 app shell for Kasumi Proxy (desktop now, mobile-ready).
//!
//! On desktop the Tauri process *is* the backend: it holds one [`Service`] (the
//! data-path owner, watchers and headless sub-updater) in managed state, exposes
//! the whole typed command surface through a single `dispatch` command, and
//! re-emits the Service's status / `subApplied` stream as typed Tauri events.
//! The neutral [`kasumi_backend`] code is shared verbatim with the Android daemon;
//! only the [`desktop::DesktopPlatform`] (native tun + `ip` routing) is desktop-only.
//!
//! tauri-specta generates the frontend's TS bindings + Zod (`frontend/src/generated`)
//! from the command + the typed events below, so the Rust types are the single
//! source of truth on both transports.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tauri_specta::{collect_commands, collect_events, Builder, Event};

use kasumi_backend::platform::Platform;
use kasumi_backend::{Command, Response, Service};
use kasumi_core::contract::{PushFrame, ServiceStatus, SubAppliedEvent};

pub mod defaults;
pub mod desktop;
pub mod schemas;

use desktop::DesktopPlatform;

/// Live service status pushed to the UI (the 1 Hz + on-change stream).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, Event)]
pub struct StatusChanged(pub ServiceStatus);

/// A subscription the headless updater fetched and applied; the UI reloads state.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, Event)]
pub struct SubscriptionApplied(pub SubAppliedEvent);

/// Returns the app version, for an "About" panel / update check.
#[tauri::command]
#[specta::specta]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// The single entry every UI action funnels through: run one typed [`Command`] and
/// return its typed [`Response`]. Lifecycle commands serialize inside the Service;
/// everything else is the stateless dispatch. Mirrors the daemon's WS envelope, so
/// the desktop and Android frontends share one command list.
#[tauri::command]
#[specta::specta]
async fn dispatch(
    cmd: Command,
    service: tauri::State<'_, Arc<Service>>,
) -> Result<Response, String> {
    service.dispatch(cmd).await.map_err(|e| e.0)
}

/// Build the desktop [`Service`] (boot init → probe cores → background loops). Run
/// on the app's async runtime during setup.
async fn build_service(platform: Arc<dyn Platform>) -> Arc<Service> {
    if let Err(e) = platform.boot_init().await {
        log::error!("boot init failed: {e}");
    }
    let service = Service::new(platform).await;
    service.spawn_background();
    service
}

/// Assemble the typed command + event surface. Shared by `run` and the bindings
/// export so the generated TS always matches what's mounted.
fn specta_builder() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new()
        .commands(collect_commands![app_version, dispatch])
        .events(collect_events![StatusChanged, SubscriptionApplied])
        // Wire numbers are JSON numbers; the UI wants `number`, not `bigint`.
        .dangerously_cast_bigints_to_number()
}

/// Regenerate every committed codegen artifact under `frontend/src/generated`
/// from the Rust types — TS bindings, Zod schemas, runtime defaults. One entry
/// point so the debug build, the `codegen` bin, and the drift test stay in
/// lock-step (run it with `cargo run -p kasumi-desktop --bin codegen`).
pub fn export_generated() {
    specta_builder()
        .export(
            specta_typescript::Typescript::default(),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../frontend/src/generated/bindings.ts"
            ),
        )
        .expect("export typescript bindings");
    std::fs::write(schemas::SCHEMAS_PATH, schemas::render()).expect("export zod schemas");
    std::fs::write(defaults::DEFAULTS_PATH, defaults::render()).expect("export defaults");
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // The data-path needs root (tun + ip routing); re-exec elevated before any GTK
    // init. No-op on mobile and when already root.
    #[cfg(not(mobile))]
    desktop::elevate::ensure_elevated();

    let builder = specta_builder();

    // Regenerate the frontend's generated files on every debug build, so a Rust
    // type/default change fails `tsc` until the frontend is updated.
    #[cfg(debug_assertions)]
    export_generated();

    tauri::Builder::default()
        .invoke_handler(builder.invoke_handler())
        .setup(move |app| {
            builder.mount_events(app);

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let platform: Arc<dyn Platform> = Arc::new(
                DesktopPlatform::new()
                    .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?,
            );
            let service = tauri::async_runtime::block_on(build_service(platform));

            // Re-emit the Service's status / subApplied frames as typed events.
            let handle = app.handle().clone();
            let mut rx = service.subscribe();
            tauri::async_runtime::spawn(async move {
                while let Ok(frame) = rx.recv().await {
                    let _ = match frame {
                        PushFrame::Status { value } => StatusChanged(value).emit(&handle),
                        PushFrame::SubApplied { value } => SubscriptionApplied(value).emit(&handle),
                    };
                }
            });

            app.manage(service);
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_backend::Command;

    /// Regenerate every committed codegen artifact from the Rust types, keeping
    /// `frontend/src/generated/{bindings,schemas,defaults}.ts` in lock-step (a
    /// drift then fails the frontend's `tsc`). Same entry point as the `codegen`
    /// bin and the debug build.
    #[test]
    fn export_generated() {
        super::export_generated();
    }

    #[tokio::test]
    async fn service_over_desktop_platform_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("KASUMI_DATA_HOME", dir.path());
        std::env::set_var("KASUMI_RUNTIME_DIR", dir.path());
        let platform: Arc<dyn Platform> = Arc::new(DesktopPlatform::new().unwrap());
        platform.boot_init().await.unwrap();
        let service = Service::new(platform).await;

        // Capabilities is stateless and always answers; the cores just aren't installed.
        let resp = service.dispatch(Command::Capabilities).await.unwrap();
        assert!(matches!(resp, Response::Capabilities(_)));

        std::env::remove_var("KASUMI_DATA_HOME");
        std::env::remove_var("KASUMI_RUNTIME_DIR");
    }
}
