//! The logging facade every Kasumi process shares.
//!
//! Three processes write diagnostics — the Android daemon, the desktop GUI and the
//! privileged helper — and they used to disagree on format, level source, rotation
//! and whether a record landed on disk at all. This crate is the single place that
//! decides those things, so a lifecycle line looks the same no matter which process
//! produced it.
//!
//! It sits on the `log` facade rather than replacing it: the crate is a leaf with no
//! IO of its own beyond the sink it installs, and every existing `log::` call site
//! keeps working. What this crate adds on top is the part no logging library
//! provides — the area taxonomy, the one record format, the redaction helpers and
//! the in-memory tail that survives the moment before the log file exists.
//!
//! Layering:
//!
//! - [`ks_error!`] / [`ks_warn!`] / [`ks_info!`] / [`ks_debug!`] tag a record with an
//!   [`Area`], which becomes the `log` target, so `RUST_LOG=info,kasumi::lifecycle=debug`
//!   selects by area instead of by module path.
//! - [`init`] installs the sink (stderr and/or a file). It is idempotent and cannot
//!   fail: a second call is a no-op, because `log::set_boxed_logger` only ever
//!   succeeds once per process and a logger that panics at startup is worse than one
//!   that stays quiet.
//! - [`set_level`] changes verbosity of a running process. Re-`init` cannot do that,
//!   which is why the filter is read per record through an atomic swap.
//! - [`redact`] is where the credentials go: subscription URLs carry tokens, profiles
//!   carry passwords, and both end up inside error chains.
//! - [`buffer`] keeps the last N records in memory so early-boot failures — before the
//!   file sink opened — are still readable.
//! - [`rotate`] trims a log file in place, keeping its tail. Renaming to `*.1` is not
//!   an option: the in-app log viewer only ever reads the base file name.

pub mod buffer;
pub mod redact;
pub mod rotate;

use std::path::PathBuf;
use std::sync::Once;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Instant;

use log::{Level, LevelFilter, Metadata, Record};

/// The subsystem a record belongs to. The variant becomes the `log` target
/// (`kasumi::<area>`), which is what the level directives and the in-app filters
/// match against — so an area is a routing decision, not a comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// Data-path bring-up/teardown: start, stop, restart, profile and mode switches.
    Lifecycle,
    /// The `Service` itself: command dispatch, watchers, background ticks.
    Service,
    /// The `Platform` implementations: routes, sysctl, OS proxy, privileges.
    Platform,
    /// State and config files on disk: reads, writes, migrations.
    State,
    /// Latency/speed probes and their throwaway test cores.
    Jobs,
    /// Connectivity probing and outbound requests.
    Net,
    /// Subscription fetching and applying.
    Sub,
    /// Geo asset fetching and conversion.
    Asset,
    /// Process spawning, liveness checks, exit codes.
    Proc,
    /// The daemon's HTTP/WS server and the desktop bridges.
    Ws,
    /// The frontend bridge boundary.
    Ui,
    /// The privileged helper process.
    Helper,
    /// The logger and the process itself (panics, install failures).
    Sys,
}

impl Area {
    /// The `log` target for this area.
    pub const fn target(self) -> &'static str {
        match self {
            Area::Lifecycle => "kasumi::lifecycle",
            Area::Service => "kasumi::service",
            Area::Platform => "kasumi::platform",
            Area::State => "kasumi::state",
            Area::Jobs => "kasumi::jobs",
            Area::Net => "kasumi::net",
            Area::Sub => "kasumi::sub",
            Area::Asset => "kasumi::asset",
            Area::Proc => "kasumi::proc",
            Area::Ws => "kasumi::ws",
            Area::Ui => "kasumi::ui",
            Area::Helper => "kasumi::helper",
            Area::Sys => "kasumi::sys",
        }
    }
}

/// Longest message kept in one record. A core log tail can be kilobytes; a single
/// runaway record must not cost more than a screenful of the log viewer.
pub const MAX_MESSAGE_CHARS: usize = 4096;

/// How one process wants to log.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Baseline level, used when neither `directives` nor `RUST_LOG` says otherwise.
    pub level: LevelFilter,
    /// Full directive string (`info,kasumi::lifecycle=debug`). Overrides `level`.
    pub directives: Option<String>,
    /// Mirror records to stderr. The Android daemon keeps this on: the module's
    /// shell redirects stderr into `daemon.log`, which also captures panics and
    /// anything printed outside the facade.
    pub to_stderr: bool,
    /// Append records to this file, in the same format. `None` for the daemon.
    pub file: Option<PathBuf>,
    /// How many records [`buffer`] keeps. `0` disables it.
    pub buffer: usize,
    /// Route panics through the facade, so they keep the same format and file.
    pub panic_hook: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LevelFilter::Info,
            directives: None,
            to_stderr: true,
            file: None,
            buffer: 512,
            panic_hook: true,
        }
    }
}

impl LogConfig {
    /// Append to `path` in addition to whatever sinks are already configured.
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file = Some(path.into());
        self
    }

    /// Override the whole directive string.
    pub fn with_directives(mut self, directives: impl Into<String>) -> Self {
        self.directives = Some(directives.into());
        self
    }

    /// Set the number of records [`buffer`] keeps.
    pub fn with_buffer(mut self, capacity: usize) -> Self {
        self.buffer = capacity;
        self
    }

    /// Mirror to stderr (on by default).
    pub fn with_stderr(mut self, to_stderr: bool) -> Self {
        self.to_stderr = to_stderr;
        self
    }
}

/// Install the shared sink. Best effort and idempotent: a second call (or a call in
/// a process that already has a logger) is a no-op, so no caller has to check
/// whether it was the first. Call once, as early as the log file is known.
pub fn init(config: &LogConfig) {
    static INIT: Once = Once::new();
    INIT.call_once(|| install(config));
}

fn install(config: &LogConfig) {
    STARTED.get_or_init(Instant::now);
    buffer::configure(config.buffer);
    set_directives(&directives_for(config));

    // The dispatcher itself stays at Trace; the real filter is consulted per record
    // so that `set_level` can change verbosity of a running process.
    let mut dispatch = fern::Dispatch::new()
        .level(LevelFilter::Trace)
        .filter(enabled)
        .format(|out, _message, record| {
            let line = render(record);
            buffer::push(line.clone());
            out.finish(format_args!("{line}\n"));
        });

    if config.to_stderr {
        dispatch = dispatch.chain(std::io::stderr());
    }
    if let Some(path) = &config.file
        && let Some(parent) = path.parent()
    {
        // A log directory that cannot be created must not stop the process; the
        // record still reaches stderr.
        let _ = std::fs::create_dir_all(parent);
    }
    if let Some(path) = &config.file
        // Nothing can report a failure here: the logger is the thing that failed,
        // and records still reach stderr.
        && let Ok(file) = fern::log_file(path)
    {
        dispatch = dispatch.chain(file);
    }

    let _ = dispatch.apply();
    if config.panic_hook {
        set_panic_hook();
    }
}

/// Directives in effect: explicit config, then `RUST_LOG`, then the configured level.
fn directives_for(config: &LogConfig) -> String {
    config
        .directives
        .clone()
        .or_else(|| std::env::var("RUST_LOG").ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| level_directives(config.level))
}

/// Directives are written lowercase so the effective configuration reads the same
/// whether it came from settings or from `RUST_LOG`.
fn level_directives(level: LevelFilter) -> String {
    level.to_string().to_lowercase()
}

/// Replace the live filter. An unparsable string falls back to "log everything the
/// dispatcher was built for" rather than silencing the process.
pub fn set_directives(directives: &str) {
    let filter = match env_filter::Builder::new().try_parse(directives) {
        Ok(builder) => builder.build(),
        Err(_) => env_filter::Builder::new().parse("trace").build(),
    };
    if let Ok(mut slot) = filter_slot().write() {
        *slot = filter;
    }
}

/// Set verbosity of a running process from the app settings. The GUI applies this
/// when the user changes the level; every process reads the same setting at startup.
/// `RUST_LOG` is the boot-time default and this call overrides it.
pub fn set_level(level: LevelFilter) {
    set_directives(&level_directives(level));
}

fn enabled(metadata: &Metadata) -> bool {
    // Fail open: a poisoned filter must not silently stop all diagnostics.
    filter_slot()
        .read()
        .map(|filter| filter.enabled(metadata))
        .unwrap_or(true)
}

/// Route panics through the facade so they carry the same format and land in the
/// same file as everything else — on the desktop there is no shell redirect that
/// would catch them. The previous hook still runs, so the default panic message
/// reaches stderr too.
pub fn set_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            ks_error!(Area::Sys, "panic: {info}");
            previous(info);
        }));
    });
}

/// The last `n` buffered records, oldest first.
pub fn recent(n: usize) -> Vec<String> {
    buffer::recent(n)
}

static STARTED: OnceLock<Instant> = OnceLock::new();
static FILTER: OnceLock<RwLock<env_filter::Filter>> = OnceLock::new();

fn filter_slot() -> &'static RwLock<env_filter::Filter> {
    FILTER.get_or_init(|| RwLock::new(env_filter::Builder::new().parse("info").build()))
}

/// One record as one line. Records must stay single-line: the log viewer reverses
/// the file line by line, and a multi-line record would be counted twice.
fn render(record: &Record) -> String {
    format_line(
        &timestamp(),
        started().elapsed().as_secs_f64(),
        record.level(),
        record.target(),
        &record.args().to_string(),
    )
}

/// The record format: `<rfc3339> +<elapsed> <LEVEL> <target> <message>`.
pub fn format_line(
    timestamp: &str,
    elapsed_secs: f64,
    level: Level,
    target: &str,
    message: &str,
) -> String {
    format!(
        "{timestamp} +{elapsed_secs:.3}s {level:<5} {target} {}",
        escape(message)
    )
}

fn timestamp() -> String {
    chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false)
}

fn started() -> Instant {
    *STARTED.get_or_init(Instant::now)
}

/// Flatten a message into one line and cap its length. Core logs and error chains
/// arrive with embedded newlines and, occasionally, a megabyte of them.
fn escape(message: &str) -> String {
    let mut out = String::with_capacity(message.len().min(MAX_MESSAGE_CHARS) + 16);
    for ch in message.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 && c != '\t' => out.push(' '),
            c => out.push(c),
        }
        if out.chars().count() >= MAX_MESSAGE_CHARS {
            out.push('…');
            break;
        }
    }
    out
}

/// Log at [`Level::Error`]: an action the user asked for did not happen.
#[macro_export]
macro_rules! ks_error {
    ($area:expr, $($arg:tt)+) => {
        ::log::error!(target: $area.target(), $($arg)+)
    };
}

/// Log at [`log::Level::Warn`]: something degraded or was silently recovered from.
#[macro_export]
macro_rules! ks_warn {
    ($area:expr, $($arg:tt)+) => {
        ::log::warn!(target: $area.target(), $($arg)+)
    };
}

/// Log at [`log::Level::Info`]: a lifecycle or routing decision worth writing down.
#[macro_export]
macro_rules! ks_info {
    ($area:expr, $($arg:tt)+) => {
        ::log::info!(target: $area.target(), $($arg)+)
    };
}

/// Log at [`log::Level::Debug`]: per-step detail, off unless the user asks for it.
#[macro_export]
macro_rules! ks_debug {
    ($area:expr, $($arg:tt)+) => {
        ::log::debug!(target: $area.target(), $($arg)+)
    };
}

/// Whether a record at this area/level would be written. Guard loops with it:
/// building the message of a suppressed record still costs.
#[macro_export]
macro_rules! ks_enabled {
    ($area:expr, $level:expr) => {
        ::log::log_enabled!(target: $area.target(), $level)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_namespaced_and_unique() {
        let areas = [
            Area::Lifecycle,
            Area::Service,
            Area::Platform,
            Area::State,
            Area::Jobs,
            Area::Net,
            Area::Sub,
            Area::Asset,
            Area::Proc,
            Area::Ws,
            Area::Ui,
            Area::Helper,
            Area::Sys,
        ];
        for area in areas {
            assert_eq!(
                area.target(),
                format!("kasumi::{}", area_target_suffix(area))
            );
        }
        let mut targets: Vec<&str> = areas.iter().map(|a| a.target()).collect();
        targets.sort_unstable();
        targets.dedup();
        assert_eq!(targets.len(), areas.len());
    }

    fn area_target_suffix(area: Area) -> &'static str {
        area.target().trim_start_matches("kasumi::")
    }

    #[test]
    fn line_has_timestamp_elapsed_level_target_and_message() {
        let line = format_line(
            "2026-02-11T09:14:02.131+00:00",
            12.5,
            Level::Info,
            Area::Lifecycle.target(),
            "start requested",
        );
        assert_eq!(
            line,
            "2026-02-11T09:14:02.131+00:00 +12.500s INFO  kasumi::lifecycle start requested"
        );
        assert!(!line.contains('\n'));
    }

    #[test]
    fn newlines_in_a_message_are_escaped() {
        let line = format_line(
            "2026-02-11T09:14:02.131+00:00",
            0.0,
            Level::Warn,
            Area::Proc.target(),
            "core failed:\nfirst\nsecond\r\nthird",
        );
        assert_eq!(line.lines().count(), 1);
        assert!(line.contains("core failed:\\nfirst\\nsecond\\r\\nthird"));
    }

    #[test]
    fn long_messages_are_capped() {
        let message = "x".repeat(MAX_MESSAGE_CHARS + 500);
        let line = format_line(
            "2026-02-11T09:14:02.131+00:00",
            0.0,
            Level::Error,
            Area::Sub.target(),
            &message,
        );
        assert!(line.ends_with('…'));
        assert!(line.len() < MAX_MESSAGE_CHARS + 128);
    }

    #[test]
    fn directives_default_to_the_configured_level() {
        let config = LogConfig {
            level: LevelFilter::Warn,
            directives: None,
            ..LogConfig::default()
        };
        assert_eq!(directives_for(&config), "warn");
    }

    #[test]
    fn explicit_directives_beat_the_level() {
        let config = LogConfig {
            level: LevelFilter::Warn,
            directives: Some("info,kasumi::lifecycle=debug".into()),
            ..LogConfig::default()
        };
        assert_eq!(directives_for(&config), "info,kasumi::lifecycle=debug");
    }

    #[test]
    fn init_is_idempotent() {
        // The second install must not panic even though `log` accepts one logger.
        let config = LogConfig::default().with_buffer(0);
        init(&config);
        init(&config);
    }
}
