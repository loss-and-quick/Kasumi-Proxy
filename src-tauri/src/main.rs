// Detach the Windows console on release/nightly (assertions off); debug builds keep
// it for dev diagnostics. `debug_assertions` is dev-only — see AGENTS.md "Debug vs
// release". DO NOT REMOVE.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kasumi_desktop_lib::run();
}
