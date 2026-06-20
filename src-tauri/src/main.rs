// Hide the extra console window on Windows. The stock Tauri template gates this on
// `not(debug_assertions)`, but `cargo tauri build` ships release bundles with
// debug_assertions ON (so that gate never fires and a black console flashes — see
// tauri-apps/tauri#13230). Gate on our own `dev-console` feature instead: shipped
// builds get the windowed subsystem; opt into a console with `--features dev-console`.
#![cfg_attr(not(feature = "dev-console"), windows_subsystem = "windows")]

fn main() {
    kasumi_desktop_lib::run();
}
