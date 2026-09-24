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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_interval_still_retries_after_retry_ms() {
        let interval = 24 * 60 * 60_000; // 24h
        let now = 100 * 24 * 60 * 60_000;
        // Never succeeded, never attempted → due.
        assert!(is_due(0, None, now, interval));
        // Attempted 5 minutes ago → the retry window holds it.
        assert!(!is_due(0, Some(now - 5 * 60_000), now, interval));
        // Attempted 11 minutes ago → past RETRY_MS, due again without waiting 24h.
        assert!(is_due(0, Some(now - 11 * 60_000), now, interval));
    }

    #[test]
    fn a_short_interval_backs_off_by_the_interval_not_retry_ms() {
        let interval = 2 * 60_000; // 2 minutes, shorter than RETRY_MS
        let now = 100 * 60_000;
        // Succeeded 3 minutes ago, attempted 1 minute ago → the interval holds it.
        assert!(!is_due(now - 3 * 60_000, Some(now - 60_000), now, interval));
        // Same success, attempted 3 minutes ago → due.
        assert!(is_due(
            now - 3 * 60_000,
            Some(now - 3 * 60_000),
            now,
            interval
        ));
    }
}
