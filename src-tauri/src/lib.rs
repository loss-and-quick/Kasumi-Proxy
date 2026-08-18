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
use tauri_specta::{Builder, Event, collect_commands, collect_events};

use kasumi_backend::platform::Platform;
use kasumi_backend::{Command, Response, Service};
use kasumi_core::contract::{PushFrame, RunState, ServiceStatus, SubAppliedEvent};
use kasumi_core::enums::wire_value;
use kasumi_core::state::RoutingMode;

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

/// A tray menu action for the webview to handle: `"restart"` / `"start"` / `"stop"`,
/// `"activate:<id>"`, or `"routing:<mode>"`. `show`/`quit` never reach here — they're
/// handled in Rust directly.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, Event)]
pub struct TrayAction(pub String);

/// One profile entry the UI wants in the tray's quick-switch list.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct TrayProfile {
    pub id: String,
    pub name: String,
    pub active: bool,
}

/// Localized tray strings (the menu is native, so the UI owns the wording).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct TrayLabels {
    pub show: String,
    pub quit: String,
    pub start: String,
    pub stop: String,
    pub restart: String,
    pub recent: String,
    /// "Routing mode" submenu title, then its three radio entries.
    pub routing: String,
    pub routing_global: String,
    pub routing_custom: String,
    pub routing_rules: String,
}

/// Rebuild the tray menu from the UI's current profiles + active selection. The UI
/// calls this on hydrate and whenever the active/recent profiles or language
/// change; clicks come back as [`TrayAction`] events (or `show`/`quit`).
#[tauri::command]
#[specta::specta]
fn update_tray(
    app: tauri::AppHandle,
    profiles: Vec<TrayProfile>,
    labels: TrayLabels,
    running: bool,
    connected: bool,
    routing_mode: RoutingMode,
) -> Result<(), String> {
    #[cfg(desktop)]
    {
        rebuild_tray_menu(&app, &profiles, &labels, running, connected, routing_mode)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(desktop))]
    let _ = (app, profiles, labels, running, connected, routing_mode);
    Ok(())
}

/// Update only the tray tooltip + state icon (not the menu). Called on every status
/// tick, so it stays cheap: the menu is rebuilt separately via [`update_tray`] only
/// when its own contents change. (Tooltips are honoured on Windows/macOS; the Linux
/// app-indicator ignores them, but the state icon still updates there.)
#[tauri::command]
#[specta::specta]
fn set_tray_status(app: tauri::AppHandle, tooltip: String, state: RunState) -> Result<(), String> {
    #[cfg(desktop)]
    if let Some(tray) = app.tray_by_id("main") {
        // Tooltip is cheap, refresh it every tick (live traffic). The icon only
        // changes on a state transition — swapping it each tick would needlessly
        // rewrite the Linux app-indicator's temp icon file.
        tray.set_tooltip(Some(&tooltip))
            .map_err(|e| e.to_string())?;
        use std::sync::atomic::{AtomicU8, Ordering};
        static LAST_ICON: AtomicU8 = AtomicU8::new(u8::MAX);
        let idx = state as u8;
        if LAST_ICON.load(Ordering::Relaxed) != idx
            && let Some(icon) = tray_icon(state)
        {
            tray.set_icon(Some(icon)).map_err(|e| e.to_string())?;
            LAST_ICON.store(idx, Ordering::Relaxed);
        }
    }
    #[cfg(not(desktop))]
    let _ = (app, tooltip, state);
    Ok(())
}

/// Returns the app version, for an "About" panel / update check. Reads it from the
/// runtime package info (sourced from the Tauri config) rather than the compile-time
/// `CARGO_PKG_VERSION`: the real product version lives in `module/module.prop` and is
/// injected at build time via `tauri build --config "{version: …}"`, which overrides
/// the config but not the binary's baked-in `CARGO_PKG_VERSION` (a 0.0.0 placeholder).
#[tauri::command]
#[specta::specta]
fn app_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

/// The single entry every UI action funnels through: run one typed [`Command`] and
/// return its typed [`Response`]. Lifecycle commands serialize inside the Service;
/// everything else is the stateless dispatch. Mirrors the daemon's WS envelope, so
/// the desktop and Android frontends share one command list.
#[tauri::command]
#[specta::specta]
async fn dispatch(
    cmd: Command,
    service: tauri::State<'_, ServiceHandle>,
) -> Result<Response, String> {
    service.get().await.dispatch(cmd).await.map_err(|e| e.0)
}

/// Managed handle to the [`Service`], which is built **off** the `setup` thread.
///
/// The privileged data-path bring-up (UAC prompt + helper handshake) takes seconds,
/// but the window — and its webview — is created from the config before `setup`
/// runs, so the first `dispatch` from the loading UI would otherwise race ahead of
/// `app.manage` and fail, wedging the UI on its loading screen forever. Instead the
/// Service is published through a watch channel once it's ready and `dispatch` awaits
/// it, so the UI just shows its normal loading state until the data-path is up.
#[derive(Clone)]
struct ServiceHandle(tokio::sync::watch::Receiver<Option<Arc<Service>>>);

impl ServiceHandle {
    /// Resolve the Service, waiting if the background bring-up is still in flight.
    /// The watch retains its last value, so a call after bring-up returns at once.
    async fn get(&self) -> Arc<Service> {
        let mut rx = self.0.clone();
        loop {
            if let Some(service) = rx.borrow_and_update().clone() {
                return service;
            }
            if rx.changed().await.is_err() {
                // Sender dropped with no Service — bring-up failed and the app is
                // exiting via the error dialog; park until that takes effect.
                std::future::pending::<()>().await;
            }
        }
    }
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
            // Dynamic items (restart / activate:<id>) are handled by the webview.
            other => {
                let _ = TrayAction(other.to_string()).emit(app);
            }
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

/// Replace the tray menu: state action(s), the recent-profile quick-switch list
/// (active one checked), the routing-mode radio (current one checked), then
/// Show / Quit. Item ids drive [`setup_tray`]'s `on_menu_event`.
#[cfg(desktop)]
fn rebuild_tray_menu(
    app: &tauri::AppHandle,
    profiles: &[TrayProfile],
    labels: &TrayLabels,
    running: bool,
    connected: bool,
    routing_mode: RoutingMode,
) -> tauri::Result<()> {
    use strum::IntoEnumIterator;
    use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};

    let Some(tray) = app.tray_by_id("main") else {
        return Ok(());
    };

    let show = MenuItem::with_id(app, "show", &labels.show, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", &labels.quit, true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let menu = Menu::new(app)?;

    // State-dependent actions: Start | Stop / Stop + Restart
    if running {
        let stop = MenuItem::with_id(app, "stop", &labels.stop, true, None::<&str>)?;
        menu.append(&stop)?;
        if connected {
            let restart = MenuItem::with_id(app, "restart", &labels.restart, true, None::<&str>)?;
            menu.append(&restart)?;
        }
    } else {
        let start = MenuItem::with_id(app, "start", &labels.start, true, None::<&str>)?;
        menu.append(&start)?;
    }

    // Quick-switch + routing group.
    menu.append(&sep1)?;
    if !profiles.is_empty() {
        // A submenu keeps the root tidy when there are many profiles.
        let recent = Submenu::with_id(app, "recent", &labels.recent, true)?;
        for p in profiles {
            let item = CheckMenuItem::with_id(
                app,
                format!("activate:{}", p.id),
                &p.name,
                true,
                p.active,
                None::<&str>,
            )?;
            recent.append(&item)?;
        }
        menu.append(&recent)?;
    }

    // Routing-mode radio: exactly the current mode is checked. Tauri has no native
    // radio item, so — like v2rayN's tray — we use check marks; clicks come back as
    // `routing:<mode>` TrayActions the webview applies to `settings.routingMode`.
    // Ids come from each variant's wire value, and the match below is exhaustive, so
    // a new RoutingMode variant fails to compile until it is given a label here.
    let routing = Submenu::with_id(app, "routing", &labels.routing, true)?;
    for mode in RoutingMode::iter() {
        let label = match mode {
            RoutingMode::Rules => &labels.routing_rules,
            RoutingMode::Global => &labels.routing_global,
            RoutingMode::Custom => &labels.routing_custom,
        };
        let item = CheckMenuItem::with_id(
            app,
            format!("routing:{}", wire_value(&mode)),
            label,
            true,
            mode == routing_mode,
            None::<&str>,
        )?;
        routing.append(&item)?;
    }
    menu.append(&routing)?;

    menu.append(&sep2)?;
    menu.append(&show)?;
    menu.append(&quit)?;
    tray.set_menu(Some(menu))?;
    Ok(())
}

/// A tray icon for the current state, derived at runtime from the bundled app icon so
/// we ship no extra art: full colour when connected, desaturated + dimmed when off,
/// and a muted tone while connecting / no-internet. Each variant is decoded and
/// converted once, then cached. `None` if the bundled icon won't decode — the caller
/// keeps whatever icon the tray already has rather than taking the process down.
#[cfg(desktop)]
fn tray_icon(state: RunState) -> Option<tauri::image::Image<'static>> {
    use std::sync::OnceLock;
    use tauri::image::Image;

    const BASE_PNG: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/icons/128x128.png"));

    fn base() -> Option<&'static Image<'static>> {
        static ICON: OnceLock<Option<Image<'static>>> = OnceLock::new();
        ICON.get_or_init(|| Image::from_bytes(BASE_PNG).ok())
            .as_ref()
    }
    // Blend each pixel toward its luminance by `1 - sat` (0 = greyscale) and scale
    // alpha by `alpha` (dim it). The bundled icon is always decoded to RGBA8.
    fn recolour(sat: f32, alpha: f32) -> Option<Image<'static>> {
        let src = base()?;
        let (w, h) = (src.width(), src.height());
        let mut rgba = src.rgba().to_vec();
        for px in rgba.chunks_exact_mut(4) {
            let (r, g, b) = (px[0] as f32, px[1] as f32, px[2] as f32);
            let lum = 0.299 * r + 0.587 * g + 0.114 * b;
            px[0] = (r * sat + lum * (1.0 - sat)).round() as u8;
            px[1] = (g * sat + lum * (1.0 - sat)).round() as u8;
            px[2] = (b * sat + lum * (1.0 - sat)).round() as u8;
            px[3] = (f32::from(px[3]) * alpha).round() as u8;
        }
        Some(Image::new_owned(rgba, w, h))
    }
    fn off() -> Option<&'static Image<'static>> {
        static ICON: OnceLock<Option<Image<'static>>> = OnceLock::new();
        ICON.get_or_init(|| recolour(0.0, 0.55)).as_ref()
    }
    fn pending() -> Option<&'static Image<'static>> {
        static ICON: OnceLock<Option<Image<'static>>> = OnceLock::new();
        ICON.get_or_init(|| recolour(0.4, 0.9)).as_ref()
    }

    match state {
        RunState::Connected => base().cloned(),
        RunState::Connecting | RunState::NoInternet => pending().cloned(),
        RunState::Stopped | RunState::Failed => off().cloned(),
    }
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
    use kasumi_core::state::ProxyMode;
    if std::env::var_os("KASUMI_SKIP_ELEVATION").is_some() {
        log::info!("KASUMI_SKIP_ELEVATION set; running the data-path in-process");
        return Ok(Arc::new(DesktopPlatform::new()?));
    }
    // Only tun mode needs the privileged data-path. When the saved mode is a non-tun
    // one, run the data-path in-process and unprivileged — no helper spawn, no elevation
    // prompt, no service install/connect. A later live switch to tun is refused with a
    // restart-required error (the gated platform can't bring a tun up). An unreadable
    // saved mode defaults to tun, keeping the privileged path.
    let mode = desktop::saved_proxy_mode();
    if mode != ProxyMode::Tun {
        log::info!(
            "saved proxy mode {mode:?} needs no privileges; running the data-path in-process"
        );
        return Ok(Arc::new(DesktopPlatform::new_gated()?));
    }
    let paths = desktop::paths::DesktopPaths::resolve()?;
    log::info!(
        "bringing up privileged data-path: portable={} datadir={} run_dir={}",
        paths.portable,
        paths.datadir,
        paths.run_dir
    );
    #[cfg(target_os = "linux")]
    let client = desktop::privhelper::spawn_and_connect(&paths).await?;
    #[cfg(target_os = "windows")]
    let client = desktop::privhelper::connect_service(&paths).await?;
    log::info!("privileged helper connected");
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
        .commands(collect_commands![
            app_version,
            dispatch,
            update_tray,
            set_tray_status
        ])
        .events(collect_events![
            StatusChanged,
            SubscriptionApplied,
            TrayAction
        ])
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
            .plugin(tauri_plugin_updater::Builder::new().build())
            // A native error modal for a fatal startup failure (see the setup hook),
            // plus the open/save file pickers the UI uses for backup & routing
            // import-export.
            .plugin(tauri_plugin_dialog::init())
            // Read/write the user-picked backup & routing-rules files (the dialog
            // only returns a path; fs does the IO, scoped to $HOME in capabilities).
            .plugin(tauri_plugin_fs::init())
            // Native clipboard for the UI's copy / paste helpers (with a
            // navigator.clipboard fallback in the non-Tauri shells).
            .plugin(tauri_plugin_clipboard_manager::init());
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

            #[allow(unused_mut)]
            let mut log_builder = tauri_plugin_log::Builder::default()
                .level(log::LevelFilter::Info)
                .level_for("kasumi_desktop_lib", log::LevelFilter::Debug);
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            if let Ok(paths) = desktop::paths::DesktopPaths::resolve() {
                use tauri_plugin_log::{Target, TargetKind};
                // Write the app log to <datadir>/daemon.log, beside the core logs.
                // Desktop has no separate daemon process, so the in-app log viewer's
                // `Daemon` target — which reads <datadir>/daemon.log — would otherwise
                // show an empty file while these lines went to the OS log dir.
                log_builder = log_builder.targets([
                    Target::new(TargetKind::Stdout),
                    Target::new(TargetKind::Folder {
                        path: std::path::PathBuf::from(&paths.datadir),
                        file_name: Some("daemon".into()),
                    }),
                ]);
            }
            app.handle().plugin(log_builder.build())?;

            #[cfg(desktop)]
            setup_tray(app)?;

            // Publish the Service through a watch channel and bring it up off-thread:
            // `setup` must not block on the privileged data-path (UAC + helper), or the
            // already-loading webview's first `dispatch` would race `manage` and wedge
            // the UI. `dispatch` awaits the channel; the UI shows its loading state
            // until the data-path is ready. See [`ServiceHandle`].
            let (tx, rx) = tokio::sync::watch::channel::<Option<Arc<Service>>>(None);
            app.manage(ServiceHandle(rx));

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let build = async {
                    let platform = build_platform().await?;
                    // A surviving ownership record at GUI start means the previous run
                    // exited without clearing (a hard crash) — the privileged helper
                    // already reaped its data-path, so the record is an orphan. Restore
                    // the user's OS proxy from it before bringing the data-path up.
                    platform.clear_os_proxy().await;
                    anyhow::Ok(build_service(platform).await)
                };
                let built =
                    match tokio::time::timeout(std::time::Duration::from_secs(90), build).await {
                        Ok(result) => result,
                        Err(_) => Err(anyhow::anyhow!(
                            "the privileged data-path helper did not become ready within 90s"
                        )),
                    };
                let service = match built {
                    Ok(service) => service,
                    Err(e) => {
                        let msg = e.to_string();
                        log::error!("startup failed: {msg}");
                        // Surface the reason in a native modal, then quit on dismissal.
                        #[cfg(desktop)]
                        {
                            use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
                            let h = handle.clone();
                            handle
                                .dialog()
                                .message(msg)
                                .title("Kasumi Proxy — startup failed")
                                .kind(MessageDialogKind::Error)
                                .show(move |_| h.exit(1));
                        }
                        return;
                    }
                };

                // Re-emit the Service's status / subApplied frames as typed events.
                let emit_handle = handle.clone();
                let mut frames = service.subscribe();
                tauri::async_runtime::spawn(async move {
                    while let Ok(frame) = frames.recv().await {
                        let _ = match frame {
                            PushFrame::Status { value } => StatusChanged(value).emit(&emit_handle),
                            PushFrame::SubApplied { value } => {
                                SubscriptionApplied(value).emit(&emit_handle)
                            }
                        };
                    }
                });

                // Publish; the watch retains it, so even after `tx` drops here every
                // `ServiceHandle::get` returns it.
                let _ = tx.send(Some(service));
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            // On real process exit (the tray's Quit, not a window close), restore the
            // OS proxy we set from its ownership record so the system isn't left
            // pointing at a dead local port. Idempotent + a no-op with no record.
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            if let tauri::RunEvent::Exit = event {
                tauri::async_runtime::block_on(desktop::clear_os_proxy());
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            let _ = event;
        });
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

    fn tempdir_paths(dir: &std::path::Path) -> desktop::paths::DesktopPaths {
        let join = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let (data, run) = (join("data"), join("run"));
        desktop::paths::DesktopPaths::from_bases(data, run, &join("bin"), false, None)
    }

    #[tokio::test]
    async fn service_over_desktop_platform_dispatches() {
        let dir = tempfile::tempdir().unwrap();
        let platform: Arc<dyn Platform> =
            Arc::new(DesktopPlatform::with_paths(tempdir_paths(dir.path()), false).unwrap());
        platform.boot_init().await.unwrap();
        let service = Service::new(platform).await;

        // Capabilities is stateless and always answers; the cores just aren't installed.
        let resp = service.dispatch(Command::Capabilities).await.unwrap();
        assert!(matches!(resp, Response::Capabilities(_)));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[tokio::test]
    async fn gated_platform_refuses_tun_but_admits_non_tun() {
        use kasumi_backend::platform::StartDataPath;
        use kasumi_core::contract::RunState;
        use kasumi_core::enums::{CoreEngine, TunEngine};
        use kasumi_core::state::{AdvancedSettings, ProxyMode};

        const RESTART: &str =
            "tun mode needs an app restart (the privileged helper is not running)";

        let dir = tempfile::tempdir().unwrap();
        let platform = DesktopPlatform::with_paths(tempdir_paths(dir.path()), true).unwrap();
        platform.boot_init().await.unwrap();

        let start = |mode| StartDataPath {
            engine: CoreEngine::Xray,
            tun: TunEngine::Tun2socks,
            tun_opts: AdvancedSettings::default().tun_options(),
            socks_port: 10800,
            mode,
        };

        // Tun is refused at the gate with the restart-required reason, and the failure
        // is recorded in the service state.
        let err = platform
            .start_data_path(start(ProxyMode::Tun))
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), RESTART);
        let state = platform.service_state().await.unwrap();
        assert_eq!(state.state, RunState::Failed);
        assert_eq!(state.error.as_deref(), Some(RESTART));

        // A non-tun mode passes the gate; with no core binary installed it fails later
        // with a different reason, proving the gate is mode-selective.
        let err = platform
            .start_data_path(start(ProxyMode::ProxyOnly))
            .await
            .unwrap_err();
        assert_ne!(err.to_string(), RESTART);
        assert_eq!(err.to_string(), "core binary missing");
    }
}
