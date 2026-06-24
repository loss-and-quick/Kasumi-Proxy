//! Shared scaffolding for the daemon's headless background updaters. Subscriptions
//! ([`crate::sub_update`]) and geo assets ([`crate::asset_update`]) run on the same
//! cadence with the same due/backoff rule and the same lifecycle hook — they differ
//! only in what they do with the fetched content.

use std::time::Duration;

use chrono::Utc;

/// How often each updater re-evaluates which items are due.
pub const TICK: Duration = Duration::from_secs(60);
/// A failed fetch retries sooner than a long update interval.
pub const RETRY_MS: i64 = 10 * 60_000;

pub fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

/// Due when a full interval has elapsed since the last success **and** at least
/// `min(interval, RETRY_MS)` since the last attempt — so failures back off without
/// hammering, yet a long interval never delays a retry past `RETRY_MS`. All values
/// are epoch-ms; each caller maps its own `last_updated` representation.
pub fn is_due(updated_ms: i64, last_attempt: Option<i64>, now: i64, interval_ms: i64) -> bool {
    now - updated_ms >= interval_ms && now - last_attempt.unwrap_or(0) >= interval_ms.min(RETRY_MS)
}

/// The daemon's lifecycle commands, dispatched directly (the caller already holds the
/// serializer). Implemented by the `Service`; both updaters restart the active core
/// through it when a refresh warrants it.
#[async_trait::async_trait]
pub trait LifecycleControl: Send + Sync {
    async fn start(&self, profile_id: Option<String>) -> Result<(), String>;
    async fn stop(&self) -> Result<(), String>;
    async fn restart(&self, profile_id: Option<String>) -> Result<(), String>;
    async fn reload_app_filter(&self) -> Result<(), String>;
}
