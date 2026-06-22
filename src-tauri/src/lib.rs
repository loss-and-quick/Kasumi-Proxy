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

/// Show + focus the main window (from the tray, or a second-launch attempt).
#[cfg(desktop)]
fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// A system tray with show/quit, so closing the window only hides it — the
/// data-path daemon has to keep running in the background.
#[cfg(desktop)]
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let show = MenuItem::with_id(app, "show", "Show Kasumi Proxy", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Kasumi Proxy")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
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

/// The desktop [`Platform`]. The GUI is unprivileged and drives the data-path
/// through a privileged helper it reaches over a transport: a root helper it spawns
/// on Linux, a LocalSystem service it installs/starts on Windows.
/// `KASUMI_SKIP_ELEVATION` opts out for CI/dev, running the data-path in-process.
#[cfg(any(target_os = "linux", target_os = "windows"))]
async fn build_platform() -> anyhow::Result<Arc<dyn Platform>> {
    use desktop::privhelper::RemotePlatform;
    if std::env::var_os("KASUMI_SKIP_ELEVATION").is_some() {
        return Ok(Arc::new(DesktopPlatform::new()?));
    }
    let paths = desktop::paths::DesktopPaths::resolve()?;
    #[cfg(target_os = "linux")]
    let client = desktop::privhelper::spawn_and_connect(&paths).await?;
    #[cfg(target_os = "windows")]
    let client = desktop::privhelper::connect_service(&paths).await?;
    Ok(Arc::new(RemotePlatform::new(client)?))
}

/// macOS has no elevation path yet; run the data-path in-process.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
async fn build_platform() -> anyhow::Result<Arc<dyn Platform>> {
    Ok(Arc::new(DesktopPlatform::new()?))
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
    // The GUI process never elevates itself: on Linux and Windows it sets up its
    // privileged data-path helper later (in setup, via build_platform); mobile and
    // the unsupported desktops have no elevation path.
    let builder = specta_builder();

    // Regenerate the frontend's generated files on every debug build, so a Rust
    // type/default change fails `tsc` until the frontend is updated.
    #[cfg(debug_assertions)]
    export_generated();

    #[allow(unused_mut)]
    let mut tb = tauri::Builder::default();

    // Desktop UX plugins. single-instance MUST be registered first: a second
    // launch focuses the running window instead of starting a second backend.
    #[cfg(desktop)]
    {
        tb = tb
            .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
                show_main(app);
            }))
            .plugin(tauri_plugin_window_state::Builder::default().build())
            .plugin(tauri_plugin_autostart::init(
                tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                None,
            ))
            .plugin(tauri_plugin_updater::Builder::new().build());
    }

    tb.invoke_handler(builder.invoke_handler())
        .on_window_event(|window, event| {
            // Closing the window must NOT exit: the data-path daemon keeps running.
            // Hide to the tray instead; the tray's Quit really exits.
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
            #[cfg(not(desktop))]
            let _ = (window, event);
        })
        .setup(move |app| {
            builder.mount_events(app);

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            #[cfg(desktop)]
            setup_tray(app)?;

            let service = tauri::async_runtime::block_on(async {
                let platform = build_platform().await?;
                anyhow::Ok(build_service(platform).await)
            })
            .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?;

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
