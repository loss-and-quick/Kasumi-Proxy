//! File logging for the privileged helper process.
//!
//! The helper is a separate process from the GUI, so it can't use
//! `tauri-plugin-log` (that needs an `AppHandle`). It installs its own [`fern`] sink
//! instead — the same backend the plugin wraps — so both processes log through the
//! one `log` facade and the shared data-path code (`DesktopPlatform`, the request
//! loop) traces identically wherever it runs.
//!
//! The log lands in `<run_dir>/kasumi-helper.log`: run_dir is helper-owned ephemeral
//! state, so this never drops privileged-owned files into the user's datadir (and a
//! portable build's run_dir sits beside the exe). Records also go to stderr, which
//! the Linux GUI inherits from the pkexec'd child.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Install the helper's file + stderr logger under `run_dir`. Best-effort and
/// idempotent-safe: a logging failure (or a second call) is swallowed so it can
/// never stop the helper. Call once, as early as the run dir is known.
pub fn init(run_dir: &Path) {
    let _ = std::fs::create_dir_all(run_dir);
    let dispatch = fern::Dispatch::new()
        .level(log::LevelFilter::Debug)
        .format(|out, message, record| {
            let millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            out.finish(format_args!(
                "{millis} [{}] {} {}",
                record.level(),
                record.target(),
                message
            ))
        })
        .chain(std::io::stderr());
    let dispatch = match fern::log_file(run_dir.join("kasumi-helper.log")) {
        Ok(file) => dispatch.chain(file),
        Err(_) => dispatch,
    };
    let _ = dispatch.apply();
}
