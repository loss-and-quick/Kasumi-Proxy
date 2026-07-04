//! Headless subscription auto-update. The daemon fetches every enabled
//! auto-update subscription on its own interval, applies the parsed profiles
//! through the shared core logic, and restarts the core only when the active
//! profile's rebuilt config actually changed. No UI is involved — an open one gets
//! a `subApplied` push and reloads.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use tokio::sync::Mutex;

use kasumi_core::contract::SubAppliedEvent;
use kasumi_core::core_config::{active_config_changed, build_core_config};
use kasumi_core::profile::Profile;
use kasumi_core::share::parse_share_links;
use kasumi_core::state::{AppState, Subscription};
use kasumi_core::sub_apply::{
    ProfileFilter, apply_subscription_profiles, deduplicate_profiles_scoped,
    map_fetched_subscription_profiles, profile_filter_regex,
};

use crate::net::{FetchUrlOptions, fetch_url};
use crate::platform::Platform;
use crate::state::read_app_state;

/// How often to re-evaluate which subscriptions are due.
pub const TICK: Duration = Duration::from_secs(60);
/// A failed fetch retries sooner than a long subscription interval.
const RETRY_MS: i64 = 10 * 60_000;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The daemon's lifecycle commands, dispatched directly (the caller already holds
/// the serializer). Implemented by the `Service`.
#[async_trait::async_trait]
pub trait LifecycleControl: Send + Sync {
    async fn start(&self, profile_id: Option<String>) -> Result<(), String>;
    async fn stop(&self) -> Result<(), String>;
    async fn restart(&self, profile_id: Option<String>) -> Result<(), String>;
    async fn reload_app_filter(&self) -> Result<(), String>;
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_iso_ms(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}

fn is_due(sub: &Subscription, last_attempt: Option<i64>, now: i64) -> bool {
    let updated = parse_iso_ms(&sub.last_updated);
    let attempted = last_attempt.unwrap_or(0);
    let interval_ms = sub.interval.saturating_mul(60_000);
    now - updated >= interval_ms && now - attempted >= interval_ms.min(RETRY_MS)
}

/// One pass: fetch and apply every due subscription. `last_attempt` is the caller's
/// persistent map so a failed fetch backs off; `serialize` is the lifecycle lock
/// shared with the command path so applies never interleave with a start/stop.
pub async fn tick(
    platform: &dyn Platform,
    lifecycle: &dyn LifecycleControl,
    serialize: &Mutex<()>,
    last_attempt: &mut HashMap<String, i64>,
    on_applied: &(dyn Fn(SubAppliedEvent) + Send + Sync),
) {
    let Some(state) = read_app_state(platform).await else {
        return;
    };
    let now = now_ms();
    let due: Vec<Subscription> = state
        .subscriptions
        .iter()
        .filter(|s| s.enabled && s.auto_update && !s.url.trim().is_empty())
        .filter(|s| is_due(s, last_attempt.get(&s.id).copied(), now))
        .cloned()
        .collect();

    for sub in due {
        last_attempt.insert(sub.id.clone(), now);
        let filter = profile_filter_regex(&sub.filter);
        // A non-empty filter that didn't compile would match everything; skip it
        // rather than import the whole subscription. The UI surfaces it on edit.
        if !sub.filter.trim().is_empty() && filter.is_unfiltered() {
            continue;
        }
        log::info!("sub-update {}: fetching", sub.remarks);
        match fetch_and_map(platform, &sub, &filter).await {
            Ok(mapped) => {
                let count = mapped.len() as u32;
                let _g = serialize.lock().await;
                // Headless: a user toggling the subscription off mid-fetch must
                // abort the apply, so re-check `enabled` against the live state.
                if apply(platform, lifecycle, &sub, mapped, true)
                    .await
                    .is_some()
                {
                    log::info!("sub-update {}: applied {count} profiles", sub.remarks);
                    on_applied(SubAppliedEvent {
                        sub_id: sub.id.clone(),
                        remarks: sub.remarks.clone(),
                        count,
                    });
                }
            }
            Err(message) => {
                log::warn!("sub-update {}: failed: {message}", sub.remarks);
                let _g = serialize.lock().await;
                record_error(platform, &sub.id, &message).await;
            }
        }
    }
}

/// Manually update one subscription (the UI's "update now"): fetch its URL and apply
/// the parsed profiles through the same path the headless updater uses, returning the
/// new merged state. Soft failures (empty URL, broken filter, fetch error) are
/// recorded as the subscription's `last_error` in the returned state rather than
/// thrown, so the UI surfaces them by reloading; a missing subscription is a hard
/// error. The fetch runs outside the serializer (it takes seconds); only the apply
/// holds the lock, exactly like the headless tick.
pub async fn update_subscription(
    platform: &dyn Platform,
    lifecycle: &dyn LifecycleControl,
    serialize: &Mutex<()>,
    sub_id: &str,
) -> Result<AppState, String> {
    let Some(state) = read_app_state(platform).await else {
        return Err("no app state".into());
    };
    let Some(sub) = state.subscriptions.iter().find(|s| s.id == sub_id).cloned() else {
        return Err(format!("subscription not found: {sub_id}"));
    };

    if sub.url.trim().is_empty() {
        return record_and_reload(platform, serialize, sub_id, "subscription URL is required")
            .await;
    }
    let filter = profile_filter_regex(&sub.filter);
    if !sub.filter.trim().is_empty() && filter.is_unfiltered() {
        return record_and_reload(platform, serialize, sub_id, "invalid profile filter").await;
    }

    match fetch_and_map(platform, &sub, &filter).await {
        Ok(mapped) => {
            let _g = serialize.lock().await;
            // The user explicitly triggered this, so apply even to a disabled sub.
            let applied = apply(platform, lifecycle, &sub, mapped, false).await;
            drop(_g);
            match applied {
                Some(next) => Ok(next),
                None => read_app_state(platform)
                    .await
                    .ok_or_else(|| "state unavailable after apply".into()),
            }
        }
        Err(message) => record_and_reload(platform, serialize, sub_id, &message).await,
    }
}

/// Record a soft failure on the subscription and return the reloaded state.
async fn record_and_reload(
    platform: &dyn Platform,
    serialize: &Mutex<()>,
    sub_id: &str,
    message: &str,
) -> Result<AppState, String> {
    {
        let _g = serialize.lock().await;
        record_error(platform, sub_id, message).await;
    }
    read_app_state(platform)
        .await
        .ok_or_else(|| message.to_string())
}

/// A fetch error trimmed for the UI. reqwest's outer wrapper repeats the URL
/// (`error sending request for url (https://…)`) the UI already shows next to the
/// field, so drop it and surface the underlying cause(s) — `operation timed out`,
/// `connection refused`. Errors we raise ourselves (`HTTP 403`, `proxy not running`)
/// have no inner cause and pass through unchanged. The full chain still hits the log.
fn display_fetch_error(e: &anyhow::Error) -> String {
    let causes: Vec<String> = e.chain().skip(1).map(|c| c.to_string()).collect();
    if causes.is_empty() {
        e.to_string()
    } else {
        causes.join(": ")
    }
}

async fn fetch_and_map(
    platform: &dyn Platform,
    sub: &Subscription,
    filter: &ProfileFilter,
) -> Result<Vec<Profile>, String> {
    let proxy = platform.proxy_status().await.map_err(|e| e.to_string())?;
    let body = match fetch_url(
        &sub.url,
        FetchUrlOptions {
            mode: sub.update_mode,
            proxy: Some(proxy),
            user_agent: (!sub.user_agent.is_empty()).then(|| sub.user_agent.clone()),
            allow_insecure: sub.allow_insecure,
            timeout: Some(FETCH_TIMEOUT),
        },
    )
    .await
    {
        Ok(body) => body,
        Err(e) => {
            // Full cause chain (with the URL) to the log — the manual "update now"
            // path logs nowhere else; the UI gets just the cause.
            log::warn!("subscription {}: fetch failed: {e:#}", sub.remarks);
            return Err(display_fetch_error(&e));
        }
    };
    let fresh = parse_share_links(&String::from_utf8_lossy(&body), None);
    // An error page / captive portal parses to zero profiles — never wipe a
    // subscription (possibly stopping the tunnel) over that.
    if fresh.is_empty() {
        return Err("no profiles in subscription body".into());
    }
    Ok(map_fetched_subscription_profiles(&fresh, sub, filter))
}

/// Apply a fetched-and-mapped body to the current state, persisting it and — when the
/// active profile is affected and its rebuilt config changed — restarting the
/// data-path. Returns the new persisted state (`None` if the subscription vanished, or
/// was disabled mid-fetch while `require_enabled`). Runs inside the serializer: the
/// fetch took seconds, so re-read the state the UI may have rewritten meanwhile.
async fn apply(
    platform: &dyn Platform,
    lifecycle: &dyn LifecycleControl,
    sub: &Subscription,
    mapped: Vec<Profile>,
    require_enabled: bool,
) -> Option<AppState> {
    let current = read_app_state(platform).await?;
    let cur_sub = current
        .subscriptions
        .iter()
        .find(|x| x.id == sub.id)
        .cloned()?;
    if require_enabled && !cur_sub.enabled {
        return None;
    }

    let old_active = current
        .profiles
        .iter()
        .find(|p| Some(p.meta().id.as_str()) == current.active_id.as_deref())
        .cloned();
    let res = apply_subscription_profiles(
        &current.profiles,
        &current.subscriptions,
        current.active_id.as_deref(),
        &cur_sub,
        &mapped,
        &now_iso(),
    );
    let mut next = current.clone();
    next.profiles = res.profiles;
    next.subscriptions = res.subscriptions;
    next.active_id = res.active_id.clone();
    if current.settings.dedup_on_update {
        let (kept, _) = deduplicate_profiles_scoped(
            &next.profiles,
            next.active_id.as_deref(),
            cur_sub.group_id.as_deref(),
        );
        next.profiles = kept;
    }
    // Same write tail as the intent path: run the write-side chain (invariants) then
    // persist. Keeps the chain the single enforcement point across save and fetch.
    let _ = crate::commands::persist_with_chain(platform, &current, &mut next).await;

    if res.active_affected {
        let running = platform
            .service_state()
            .await
            .map(|s| s.engine.is_some())
            .unwrap_or(false);
        if running {
            let needs_restart =
                res.active_id.is_none() || config_changed(&current, old_active.as_ref(), &next);
            if needs_restart {
                let _ = match &res.active_id {
                    Some(id) => lifecycle.restart(Some(id.clone())).await,
                    None => lifecycle.stop().await,
                };
            }
        }
    }
    Some(next)
}

/// Rebuild the active profile's config before/after the update and report whether
/// it differs — an unchanged re-fetch must not churn the connection.
fn config_changed(prev: &AppState, old_active: Option<&Profile>, next: &AppState) -> bool {
    let new_active = next
        .profiles
        .iter()
        .find(|p| Some(p.meta().id.as_str()) == next.active_id.as_deref());
    let (Some(old), Some(new)) = (old_active, new_active) else {
        return true; // can't compare → restart to be safe
    };
    let prev_cfg = build_core_config(old, &prev.settings, &prev.routing_rules, &prev.profiles, "");
    let next_cfg = build_core_config(new, &next.settings, &next.routing_rules, &next.profiles, "");
    match (prev_cfg, next_cfg) {
        (Ok(a), Ok(b)) => active_config_changed(&a, &b),
        _ => true, // a build failed → don't risk leaving a stale config
    }
}

async fn record_error(platform: &dyn Platform, sub_id: &str, message: &str) {
    let Some(prev) = read_app_state(platform).await else {
        return;
    };
    if !prev.subscriptions.iter().any(|x| x.id == sub_id) {
        return;
    }
    let mut next = prev.clone();
    for x in next.subscriptions.iter_mut() {
        if x.id == sub_id {
            x.last_error = Some(message.to_owned());
        }
    }
    let _ = crate::commands::persist_with_chain(platform, &prev, &mut next).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::write_app_state;
    use crate::testutil::{TestPlatform, sample_vless};
    use kasumi_core::state::default_app_state;
    use std::sync::Mutex as StdMutex;

    fn sub(id: &str, url: &str) -> Subscription {
        Subscription {
            id: id.into(),
            remarks: format!("sub-{id}"),
            url: url.into(),
            enabled: true,
            group_id: Some("g-main".into()),
            auto_update: true,
            interval: 60,
            allow_insecure: false,
            user_agent: String::new(),
            filter: String::new(),
            update_mode: Default::default(),
            last_updated: String::new(),
            count: 0,
            last_error: None,
            prev_profile: None,
            next_profile: None,
        }
    }

    struct RecordingLifecycle {
        calls: StdMutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl LifecycleControl for RecordingLifecycle {
        async fn start(&self, id: Option<String>) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("start:{id:?}"));
            Ok(())
        }
        async fn stop(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("stop".into());
            Ok(())
        }
        async fn restart(&self, id: Option<String>) -> Result<(), String> {
            self.calls.lock().unwrap().push(format!("restart:{id:?}"));
            Ok(())
        }
        async fn reload_app_filter(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("reload".into());
            Ok(())
        }
    }

    #[test]
    fn due_only_after_interval_and_backoff() {
        let mut s = sub("s", "u");
        s.interval = 1; // 1 minute
        let now = 10 * 60_000;
        // Never updated, never attempted → due.
        assert!(is_due(&s, None, now));
        // Just updated → not due.
        s.last_updated = now_iso_at(now);
        assert!(!is_due(&s, None, now));
        // Old update but attempted just now → backoff holds it.
        s.last_updated = now_iso_at(0);
        assert!(!is_due(&s, Some(now), now));
    }

    fn now_iso_at(ms: i64) -> String {
        chrono::DateTime::from_timestamp_millis(ms)
            .unwrap()
            .to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    #[tokio::test]
    async fn fetch_failure_records_error() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        // Port 1 refuses instantly → fetch fails → error recorded.
        state.subscriptions = vec![sub("s1", "http://127.0.0.1:1/")];
        write_app_state(&p, &state).await.unwrap();

        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let mut last = HashMap::new();
        tick(&p, &lc, &serialize, &mut last, &|_| {}).await;

        let after = read_app_state(&p).await.unwrap();
        assert!(after.subscriptions[0].last_error.is_some());
        assert!(lc.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_replaces_profiles_and_restarts_active() {
        let (p, _d) = TestPlatform::new();
        let mut old = sample_vless();
        old.meta_mut().id = "old".into();
        old.meta_mut().sub_id = Some("s1".into());
        old.meta_mut().group_id = "g-main".into();

        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", "u")];
        state.profiles = vec![old];
        state.active_id = Some("old".into());
        write_app_state(&p, &state).await.unwrap();

        // Same remarks (so the active selection follows it) but a different
        // endpoint (so the rebuilt config differs → a restart is warranted).
        let mut fresh = crate::testutil::vless_at(8443);
        fresh.meta_mut().id = "fresh".into();
        fresh.meta_mut().remarks = "Home".into();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let next = apply(&p, &lc, &state.subscriptions[0], vec![fresh], true)
            .await
            .expect("apply returns the new state");
        assert_eq!(next.subscriptions[0].count, 1);

        let after = read_app_state(&p).await.unwrap();
        assert!(after.profiles.iter().any(|x| x.meta().id == "fresh"));
        assert!(!after.profiles.iter().any(|x| x.meta().id == "old"));
        // Active belonged to s1, follows the renamed endpoint, config differs, and
        // TestPlatform reports Running → a restart of the new active id fired.
        let calls = lc.calls.lock().unwrap();
        assert!(calls.iter().any(|c| c.starts_with("restart")));
    }

    #[tokio::test]
    async fn update_subscription_unknown_id_errors() {
        let (p, _d) = TestPlatform::new();
        write_app_state(&p, &default_app_state()).await.unwrap();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let err = update_subscription(&p, &lc, &serialize, "nope")
            .await
            .unwrap_err();
        assert!(err.contains("subscription not found"));
    }

    #[tokio::test]
    async fn update_subscription_fetch_failure_records_error_in_state() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        // Port 1 refuses instantly → fetch fails → error recorded, state returned.
        state.subscriptions = vec![sub("s1", "http://127.0.0.1:1/")];
        write_app_state(&p, &state).await.unwrap();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let returned = update_subscription(&p, &lc, &serialize, "s1")
            .await
            .unwrap();
        assert!(returned.subscriptions[0].last_error.is_some());
        assert!(lc.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_subscription_empty_url_is_soft_error() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", "   ")];
        write_app_state(&p, &state).await.unwrap();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let returned = update_subscription(&p, &lc, &serialize, "s1")
            .await
            .unwrap();
        assert_eq!(
            returned.subscriptions[0].last_error.as_deref(),
            Some("subscription URL is required")
        );
    }

    #[test]
    fn display_fetch_error_drops_the_url_wrapper_but_keeps_the_cause() {
        // A wrapped error (reqwest-style): the outer layer repeats the URL, the
        // inner is the real cause — only the cause should survive.
        let wrapped = anyhow::anyhow!("operation timed out")
            .context("error sending request for url (https://example.com/sub)");
        assert_eq!(display_fetch_error(&wrapped), "operation timed out");

        // An error we raise ourselves has no inner cause — it passes through whole.
        let bare = anyhow::anyhow!("HTTP 403");
        assert_eq!(display_fetch_error(&bare), "HTTP 403");
    }
}
