// Prevents an extra console window on Windows in release. DO NOT REMOVE.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kasumi_desktop_lib::run();
}
