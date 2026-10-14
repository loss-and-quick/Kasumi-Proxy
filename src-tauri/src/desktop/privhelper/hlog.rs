//! File logging for the privileged helper process.
//!
//! The helper is a separate process from the GUI, so it cannot go through the GUI's
//! Tauri setup and installs the shared facade itself instead. The result is the same
//! record format and the same level rules as the GUI and the daemon, which is what
//! makes the shared data-path code (`DesktopPlatform`, the request loop) trace
//! identically wherever it runs.
//!
//! The log lands in `<run_dir>/kasumi-helper.log`: run_dir is helper-owned ephemeral
//! state, so this never drops privileged-owned files into the user's datadir (and a
//! portable build's run_dir sits beside the exe). Records also go to stderr, which
//! the Linux GUI inherits from the pkexec'd child.

use std::path::Path;

use kasumi_log::LogConfig;

/// Install the helper's logger under `run_dir`. Best-effort and idempotent-safe: a
/// logging failure (or a second call) is swallowed so it can never stop the helper.
/// Call once, as early as the run dir is known.
pub fn init(run_dir: &Path) {
    // The helper runs the same fetch path as the daemon, so the dependency that
    // prints provider cookies stays pinned here too.
    kasumi_log::pin_module(COOKIE_STORE, log::LevelFilter::Info);
    kasumi_log::init(
        &LogConfig::default().with_file(run_dir.join(crate::desktop::paths::HELPER_LOG_FILE)),
    );
}

/// A dependency whose debug output carries credentials, so no directive may raise it.
const COOKIE_STORE: &str = "cookie_store";
