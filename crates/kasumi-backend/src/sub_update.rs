//! Headless subscription auto-update. The daemon fetches every enabled
//! auto-update subscription on its own interval, applies the parsed profiles
//! through the shared core logic, and restarts the core only when the active
//! profile's rebuilt config actually changed. No UI is involved — an open one gets
//! a `subApplied` push and reloads.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use happ_sub::happ_request::{RequestProfile, RetryCause};
use happ_sub::{MergeMode, MetaMap, RoutingAction};
use tokio::sync::Mutex;

use kasumi_core::contract::SubAppliedEvent;
use kasumi_core::core_config::{active_config_changed, build_core_config};
use kasumi_core::data_path_plan::HostTraits;
use kasumi_core::import_input::{is_encrypted_url, subscription_fetch_url};
use kasumi_core::mutate::rename_owned_group;
use kasumi_core::profile::Profile;
use kasumi_core::request_identity::{IdentityInput, RequestIdentityDefaults};
use kasumi_core::route::{repoint_profile_ids, resolve_route};
use kasumi_core::state::{
    AppState, AuditEntry, AuditOutcome, SubErrorKind, SubWarning, Subscription,
};
use kasumi_core::sub_apply::{
    ProfileFilter, apply_subscription_profiles, deduplicate_profiles_scoped,
    map_fetched_subscription_profiles, profile_filter_regex, refreshed_id,
};
use kasumi_core::sub_changes::{
    consented_keys, host_of, offer_changes, offer_provider_configs, push_audit, routing_off,
};
use kasumi_core::sub_ingest::{
    IngestError, IngestInput, StoredSubMeta, ingest, limits, record_after, stored_for_url,
    withhold_unavailable_profiles,
};
use kasumi_core::sub_policy::{apply_auto, effective_interval_minutes};

use crate::identity::resolve_request;
use crate::net::{BodyTooLarge, FetchResponse, FetchUrlOptions, HttpStatusError, fetch};
use crate::platform::Platform;
use crate::state::read_app_state;
use crate::sub_cookies::SubCookies;
use crate::sub_meta;
use crate::updater::{self, LifecycleControl, now_ms};

/// Used unless the provider sends `subscription-request-timeout`. Longer than
/// Happ's 7 s: a fetch through the proxy can be slow.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_iso_ms(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}

fn is_due(sub: &Subscription, last_attempt: Option<i64>, now: i64) -> bool {
    updater::is_due(
        parse_iso_ms(&sub.last_updated),
        last_attempt,
        now,
        effective_interval_minutes(sub).saturating_mul(60_000),
    )
}

fn fetch_timeout(sub: &Subscription) -> Duration {
    sub.request_timeout_secs
        .map(|s| Duration::from_secs(s.into()))
        .unwrap_or(FETCH_TIMEOUT)
}

/// One pass: fetch and apply every due subscription. `last_attempt` is the caller's
/// persistent map so a failed fetch backs off; `serialize` is the lifecycle lock
/// shared with the command path so applies never interleave with a start/stop.
/// `cookies` is the jar every subscription fetch shares.
pub async fn tick(
    platform: &dyn Platform,
    lifecycle: &dyn LifecycleControl,
    serialize: &Mutex<()>,
    cookies: &Arc<SubCookies>,
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
        // Happ's background update keeps meta keys a response omits.
        let identity = &state.settings.request_identity;
        match fetch_and_map(
            platform,
            identity,
            cookies,
            &sub,
            &filter,
            MergeMode::Partial,
        )
        .await
        {
            Ok(fetched) => {
                let count = fetched.mapped.len() as u32;
                let _g = serialize.lock().await;
                // Headless: a user toggling the subscription off mid-fetch must
                // abort the apply, so re-check `enabled` against the live state.
                if let Some(next) = apply(
                    platform,
                    lifecycle,
                    &sub,
                    fetched.mapped,
                    Some(fetched.outcome),
                    true,
                )
                .await
                {
                    log::info!("sub-update {}: applied {count} profiles", sub.remarks);
                    // The provider may have renamed it.
                    let remarks = next
                        .subscriptions
                        .iter()
                        .find(|x| x.id == sub.id)
                        .map_or_else(|| sub.remarks.clone(), |x| x.remarks.clone());
                    on_applied(SubAppliedEvent {
                        sub_id: sub.id.clone(),
                        remarks,
                        count,
                    });
                }
            }
            Err(e) => {
                log::warn!("sub-update {}: failed: {}", sub.remarks, e.message);
                let _g = serialize.lock().await;
                record_error(platform, &sub.id, &e).await;
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
    cookies: &Arc<SubCookies>,
    sub_id: &str,
) -> Result<AppState, String> {
    let Some(state) = read_app_state(platform).await else {
        return Err("no app state".into());
    };
    let Some(sub) = state.subscriptions.iter().find(|s| s.id == sub_id).cloned() else {
        return Err(format!("subscription not found: {sub_id}"));
    };

    if sub.url.trim().is_empty() {
        let e = SubFetchError::plain("subscription URL is required");
        return record_and_reload(platform, serialize, sub_id, e).await;
    }
    let filter = profile_filter_regex(&sub.filter);
    if !sub.filter.trim().is_empty() && filter.is_unfiltered() {
        let e = SubFetchError::plain("invalid profile filter");
        return record_and_reload(platform, serialize, sub_id, e).await;
    }

    let identity = &state.settings.request_identity;
    match fetch_and_map(platform, identity, cookies, &sub, &filter, MergeMode::Full).await {
        Ok(fetched) => {
            let _g = serialize.lock().await;
            // The user explicitly triggered this, so apply even to a disabled sub.
            let applied = apply(
                platform,
                lifecycle,
                &sub,
                fetched.mapped,
                Some(fetched.outcome),
                false,
            )
            .await;
            drop(_g);
            match applied {
                Some(next) => Ok(next),
                None => read_app_state(platform)
                    .await
                    .ok_or_else(|| "state unavailable after apply".into()),
            }
        }
        Err(e) => record_and_reload(platform, serialize, sub_id, e).await,
    }
}

/// Record a soft failure on the subscription and return the reloaded state.
async fn record_and_reload(
    platform: &dyn Platform,
    serialize: &Mutex<()>,
    sub_id: &str,
    e: SubFetchError,
) -> Result<AppState, String> {
    {
        let _g = serialize.lock().await;
        record_error(platform, sub_id, &e).await;
    }
    read_app_state(platform).await.ok_or(e.message)
}

/// A failed update: the message for the log, the kind for the UI to translate.
struct SubFetchError {
    message: String,
    kind: Option<SubErrorKind>,
    /// The body was full Xray configs the user has not allowed yet.
    needs_consent: bool,
}

impl SubFetchError {
    fn plain(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            kind: None,
            needs_consent: false,
        }
    }
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

fn fetch_error_kind(e: &anyhow::Error) -> SubErrorKind {
    if let Some(HttpStatusError(status)) = e.downcast_ref() {
        SubErrorKind::Http { status: *status }
    } else if e.downcast_ref::<BodyTooLarge>().is_some() {
        SubErrorKind::Limit
    } else {
        SubErrorKind::Network
    }
}

struct Fetched {
    mapped: Vec<Profile>,
    outcome: Outcome,
}

/// What a successful fetch carries besides its profiles.
struct Outcome {
    record: StoredSubMeta,
    /// The stored meta this fetch merged into, to tell what the provider changed.
    previous: Option<MetaMap>,
    routing: Vec<RoutingAction>,
    warnings: Vec<SubWarning>,
    /// No stored meta matched: this fetch read the URL fragment.
    imported: bool,
}

/// Fetch and ingest a subscription. Any error leaves its profiles and sub-meta as
/// they were: an error page, a failed decryption or an empty list must never wipe
/// a subscription (possibly stopping the tunnel).
async fn fetch_and_map(
    platform: &dyn Platform,
    identity: &RequestIdentityDefaults,
    cookies: &Arc<SubCookies>,
    sub: &Subscription,
    filter: &ProfileFilter,
    merge: MergeMode,
) -> Result<Fetched, SubFetchError> {
    let url = subscription_fetch_url(&sub.url).map_err(|e| {
        log::warn!("subscription {}: {e}", sub.remarks);
        SubFetchError {
            message: format!("the encrypted link could not be decrypted: {e}"),
            kind: Some(SubErrorKind::UrlDecrypt),
            needs_consent: false,
        }
    })?;
    let encrypted = is_encrypted_url(&sub.url);
    let proxy = platform
        .proxy_status()
        .await
        .map_err(|e| SubFetchError::plain(&e.to_string()))?;
    let stored = sub_meta::read_all(platform).await;
    let stored = stored_for_url(stored.get(&sub.id), &sub.url);
    let consented = consented_keys(sub, stored.map(|s| &s.meta));
    let request = resolve_request(
        platform,
        &IdentityInput::stored(identity, Some(sub)),
        stored.map(|s| &s.meta),
        &consented,
    )
    .await
    .profile;
    let opts = FetchUrlOptions {
        mode: sub.update_mode,
        proxy: Some(proxy),
        allow_insecure: sub.allow_insecure,
        timeout: Some(fetch_timeout(sub)),
        headers: request.headers.clone(),
        max_body_bytes: Some(limits().max_body_bytes),
        cookie_jar: (identity.cookie_jar && request.use_cookie_jar).then(|| cookies.clone()),
        gzip_only: true,
        // Offer HTTP/2 as Happ's OkHttp does; downloads and probes keep HTTP/1.1.
        http2: true,
        // As close to Happ's request as reqwest allows; it still adds `Accept: */*`,
        // which no client or request option removes. Incy spells its `x-` headers in
        // lower case; one case has to win, and theirs is the one a server can tell.
        title_case_headers: sub.client.is_happ(),
        ..Default::default()
    };
    // The fragment carries provider directives for the import and never goes on
    // the wire.
    let primary = fetch_like_happ(happ_sub::meta::fetch_url(&url), opts.clone(), &request);
    let mut merge = merge;
    let mut used_fallback = None;
    let res = match primary.await {
        Ok(res) => res,
        Err(e) => {
            // Full cause chain (with the URL) to the log — the manual "update now"
            // path logs nowhere else; the UI gets just the cause. A decrypted URL
            // stays out of the log too.
            if encrypted {
                let cause = display_fetch_error(&e);
                log::warn!("subscription {}: fetch failed: {cause}", sub.remarks);
            } else {
                log::warn!("subscription {}: fetch failed: {e:#}", sub.remarks);
            }
            let failed = SubFetchError {
                message: display_fetch_error(&e),
                kind: Some(fetch_error_kind(&e)),
                needs_consent: false,
            };
            // Only a fallback URL the user accepted is ever contacted, and a redirect
            // from it may not lead to a private address.
            let Some(fallback) = sub.fallback_url.as_deref() else {
                return Err(failed);
            };
            let opts = FetchUrlOptions {
                redirect_guard: true,
                ..opts
            };
            match fetch_like_happ(happ_sub::meta::fetch_url(fallback), opts, &request).await {
                Ok(res) => {
                    log::info!("subscription {}: used the fallback URL", sub.remarks);
                    used_fallback = Some(host_of(fallback));
                    // Happ merges a fallback response like a background update.
                    merge = MergeMode::Partial;
                    res
                }
                Err(e) => {
                    log::warn!("subscription {}: fallback failed: {e:#}", sub.remarks);
                    return Err(failed);
                }
            }
        }
    };
    // The stored meta stays keyed by the link as saved; the fragment and `?key=`
    // are read from the URL it leads to.
    let mut ingested = ingest(&IngestInput {
        url: &url,
        headers: &res.headers,
        body: &res.body,
        stored,
        merge,
        allow_provider_configs: sub.allow_provider_configs,
        title: &sub.remarks,
    })
    .map_err(|e| {
        log::warn!("subscription {}: {e}", sub.remarks);
        SubFetchError {
            message: e.to_string(),
            kind: Some(e.kind()),
            needs_consent: matches!(e, IngestError::UnsupportedPayload(_)),
        }
    })?;
    withhold_unavailable_profiles(&mut ingested, platform.unavailable_protocols());
    let mut warnings = ingested.warnings.clone();
    if let Some(host) = used_fallback {
        warnings.insert(0, SubWarning::UsedFallback { host });
    }
    log_warnings(sub, &warnings);
    Ok(Fetched {
        mapped: map_fetched_subscription_profiles(&ingested.profiles, sub, filter),
        outcome: Outcome {
            record: record_after(&sub.url, &ingested),
            previous: stored.map(|s| s.meta.clone()),
            routing: ingested.routing,
            warnings,
            imported: stored.is_none(),
        },
    })
}

/// Fetch with Happ's retries. A reply with any status is final; a failed attempt is
/// retried as [`RequestProfile::retry`] says.
async fn fetch_like_happ(
    url: &str,
    opts: FetchUrlOptions,
    request: &RequestProfile,
) -> anyhow::Result<FetchResponse> {
    let mut result = fetch(url, opts.clone()).await;
    for _ in 0..request.retries {
        let Some(cause) = result.as_ref().err().and_then(retry_cause) else {
            break;
        };
        log::info!("subscription fetch failed ({cause:?}), retrying");
        let retry = request.retry(cause);
        let opts = FetchUrlOptions {
            headers: retry.headers,
            ipv4_only: retry.ipv4_only,
            ..opts.clone()
        };
        result = fetch(url, opts).await;
    }
    result
}

/// How a transport failure maps onto Happ's retry rule. Errors raised after a reply
/// (a status, the body limit) or before any attempt (no proxy) are not retried.
fn retry_cause(e: &anyhow::Error) -> Option<RetryCause> {
    if !e.chain().any(|c| c.is::<reqwest::Error>()) {
        return None;
    }
    let reset = e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionReset)
            || c.to_string().to_ascii_lowercase().contains("reset")
    });
    Some(if reset {
        RetryCause::ConnectionReset
    } else {
        RetryCause::TimeoutOrIo
    })
}

fn log_warnings(sub: &Subscription, warnings: &[SubWarning]) {
    for w in warnings {
        log::info!("subscription {}: {w:?}", sub.remarks);
    }
}

/// Apply a fetched-and-mapped body to the current state, persisting it and — when the
/// active profile is affected and its rebuilt config changed — restarting the
/// data-path. Returns the new persisted state (`None` if the subscription vanished, or
/// was disabled mid-fetch while `require_enabled`). Runs inside the serializer: the
/// fetch took seconds, so re-read the state the UI may have rewritten meanwhile.
/// `outcome` carries the provider meta to apply and the sub-meta entry to store.
async fn apply(
    platform: &dyn Platform,
    lifecycle: &dyn LifecycleControl,
    sub: &Subscription,
    mapped: Vec<Profile>,
    outcome: Option<Outcome>,
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
    // Routes and rules that name one of this subscription's profiles follow it
    // to its new id, as the active id does.
    repoint_profile_ids(&mut next, &|id| {
        refreshed_id(&current.profiles, id, &cur_sub.id, &mapped)
    });
    next.profiles = res.profiles;
    next.subscriptions = res.subscriptions;
    next.active_id = res.active_id.clone();
    if let Some(o) = &outcome
        && let Some(i) = next.subscriptions.iter().position(|x| x.id == sub.id)
    {
        let mut updated = next.subscriptions[i].clone();
        // Only a subscription's very first fetch may switch auto-update on, not
        // the first one after an upgrade or a lost sub-meta.json.
        let first_import = o.imported && cur_sub.last_updated.is_empty();
        let disposition = o.record.content_disposition.as_deref();
        apply_auto(&mut updated, &o.record.meta, disposition, first_import);
        updated.warnings.clone_from(&o.warnings);
        updated.body_encrypted = o.record.encrypted;
        let now = now_iso();
        let offers = offer_changes(
            &next,
            &updated,
            o.previous.as_ref(),
            &o.record.meta,
            &o.routing,
            &now,
        );
        updated.pending_changes = offers.pending;
        push_audit(&mut updated, offers.audit);
        rename_owned_group(&mut next, &updated);
        next.subscriptions[i] = updated;
        // `happ://routing/off` needs no consent: it only switches off what this
        // subscription's own routing turned on.
        if o.routing.contains(&RoutingAction::Off) && routing_off(&mut next, &sub.id) {
            let entry = AuditEntry {
                at: now,
                key: "routing".into(),
                outcome: AuditOutcome::AutoApplied,
                summary: "happ://routing/off".into(),
            };
            push_audit(&mut next.subscriptions[i], vec![entry]);
        }
    }
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
    if let Some(Outcome { record, .. }) = outcome {
        let live: Vec<&str> = next.subscriptions.iter().map(|s| s.id.as_str()).collect();
        if let Err(e) = sub_meta::write_entry(platform, &sub.id, Some(record), &live).await {
            log::warn!("subscription {}: writing sub-meta failed: {e}", sub.remarks);
        }
    }

    if res.active_affected {
        let running = platform
            .service_state()
            .await
            .map(|s| s.engine.is_some())
            .unwrap_or(false);
        if running {
            let needs_restart = res.active_id.is_none()
                || config_changed(&current, old_active.as_ref(), &next, platform.host_traits());
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
fn config_changed(
    prev: &AppState,
    old_active: Option<&Profile>,
    next: &AppState,
    host: HostTraits,
) -> bool {
    let new_active = next
        .profiles
        .iter()
        .find(|p| Some(p.meta().id.as_str()) == next.active_id.as_deref());
    let (Some(old), Some(new)) = (old_active, new_active) else {
        return true; // can't compare → restart to be safe
    };
    let prev_rules = resolve_route(prev, old);
    let next_rules = resolve_route(next, new);
    let prev_cfg = build_core_config(old, &prev.settings, &prev_rules, &prev.profiles, "", host);
    let next_cfg = build_core_config(new, &next.settings, &next_rules, &next.profiles, "", host);
    match (prev_cfg, next_cfg) {
        (Ok(a), Ok(b)) => active_config_changed(&a, &b),
        _ => true, // a build failed → don't risk leaving a stale config
    }
}

async fn record_error(platform: &dyn Platform, sub_id: &str, e: &SubFetchError) {
    let Some(prev) = read_app_state(platform).await else {
        return;
    };
    if !prev.subscriptions.iter().any(|x| x.id == sub_id) {
        return;
    }
    let mut next = prev.clone();
    for x in next.subscriptions.iter_mut() {
        if x.id == sub_id {
            x.last_error = Some(e.message.clone());
            x.last_error_kind.clone_from(&e.kind);
            if e.needs_consent && offer_provider_configs(x, &now_iso()) {
                log::info!(
                    "subscription {}: asked to allow its Xray configs",
                    x.remarks
                );
            }
        }
    }
    let _ = crate::commands::persist_with_chain(platform, &prev, &mut next).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::write_app_state;
    use crate::testutil::{TestPlatform, http_response, sample_vless, serve, serve_tls};
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
            ..Default::default()
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
        tick(&p, &lc, &serialize, &jar(), &mut last, &|_| {}).await;

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
        let next = apply(&p, &lc, &state.subscriptions[0], vec![fresh], None, true)
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
    async fn refresh_that_replaces_profiles_drops_their_test_logs() {
        let (p, _d) = TestPlatform::new();
        let mut old = sample_vless();
        old.meta_mut().id = "old".into();
        old.meta_mut().sub_id = Some("s1".into());
        old.meta_mut().group_id = "g-main".into();
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", "u")];
        state.profiles = vec![old];
        write_app_state(&p, &state).await.unwrap();
        let dir = p.paths().data_dir.clone();
        let stale = dir.join("test-last-realping-old.log");
        std::fs::write(&stale, "boom").unwrap();

        let mut fresh = crate::testutil::vless_at(8443);
        fresh.meta_mut().id = "fresh".into();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        apply(&p, &lc, &state.subscriptions[0], vec![fresh], None, true)
            .await
            .expect("apply returns the new state");
        assert!(!stale.exists());
    }

    #[tokio::test]
    async fn a_route_keeps_its_profile_through_a_refresh() {
        let (p, _d) = TestPlatform::new();
        let mut old = sample_vless();
        old.meta_mut().id = "old".into();
        old.meta_mut().sub_id = Some("s1".into());
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", "u")];
        state.profiles = vec![old.clone()];
        state.routes.push(kasumi_core::route::Route {
            id: "work".into(),
            name: "Work".into(),
            profiles: vec!["old".into()],
            ..kasumi_core::route::default_route()
        });
        write_app_state(&p, &state).await.unwrap();

        let mut fresh = old;
        fresh.meta_mut().id = "fresh".into();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        apply(&p, &lc, &state.subscriptions[0], vec![fresh], None, true)
            .await
            .expect("apply returns the new state");

        let after = read_app_state(&p).await.unwrap();
        assert_eq!(after.routes[1].profiles, ["fresh"]);
    }

    #[tokio::test]
    async fn update_subscription_unknown_id_errors() {
        let (p, _d) = TestPlatform::new();
        write_app_state(&p, &default_app_state()).await.unwrap();
        let lc = RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        };
        let serialize = Mutex::new(());
        let err = update_subscription(&p, &lc, &serialize, &jar(), "nope")
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
        let returned = update_subscription(&p, &lc, &serialize, &jar(), "s1")
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
        let returned = update_subscription(&p, &lc, &serialize, &jar(), "s1")
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

    fn lifecycle() -> RecordingLifecycle {
        RecordingLifecycle {
            calls: StdMutex::new(vec![]),
        }
    }

    fn jar() -> Arc<SubCookies> {
        Arc::default()
    }

    /// Lower-cased header lines of request `i`.
    fn sent(requests: &crate::testutil::Requests, i: usize) -> Vec<(String, String)> {
        requests.lock().unwrap()[i]
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(": "))
            .map(|(n, v)| (n.to_ascii_lowercase(), v.to_owned()))
            .collect()
    }

    fn sent_header(requests: &crate::testutil::Requests, i: usize, name: &str) -> Option<String> {
        sent(requests, i)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
    }

    fn phone(p: &TestPlatform) {
        p.identity(|i| {
            i.facts = kasumi_core::request_identity::DeviceFacts {
                os: "Android".into(),
                os_version: "16".into(),
                model: "Pixel 9".into(),
                locale: "ru-RU".into(),
                ..Default::default()
            };
            i.user_key =
                Some("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F".into());
        });
    }

    #[tokio::test]
    async fn default_fetch_sends_happ_identity() {
        let (p, _d) = TestPlatform::new();
        phone(&p);
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;

        let names: Vec<String> = sent(&requests, 0).into_iter().map(|(n, _)| n).collect();
        let at = |n: &str| names.iter().position(|x| x == n).unwrap();
        let order = [
            "connection",
            "user-agent",
            "x-device-locale",
            "x-hwid",
            "x-device-os",
            "x-ver-os",
            "x-device-model",
        ];
        assert!(order.windows(2).all(|w| at(w[0]) < at(w[1])), "{names:?}");
        let ua = sent_header(&requests, 0, "user-agent").unwrap();
        assert!(ua.starts_with("Happ/4."), "{ua}");
        // The SSAID happ-sub computes for the synthetic key 00..1f.
        assert_eq!(
            sent_header(&requests, 0, "x-hwid").as_deref(),
            Some("013b86e99e8dce53")
        );
        assert_eq!(
            sent_header(&requests, 0, "x-device-locale").as_deref(),
            Some("ru")
        );
        assert_eq!(
            sent_header(&requests, 0, "accept-encoding").as_deref(),
            Some("gzip")
        );
    }

    #[tokio::test]
    async fn subscription_fetch_agrees_http2_over_tls() {
        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve_tls(LINK).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let mut state = read_app_state(&p).await.unwrap();
        // The test server's certificate is self-signed.
        state.subscriptions[0].allow_insecure = true;
        write_app_state(&p, &state).await.unwrap();
        let state = update(&p).await;

        let seen = requests.lock().unwrap()[0].clone();
        assert_eq!(seen.alpn.as_deref(), Some("h2"));
        assert_eq!(seen.version, "HTTP/2");
        assert!(
            seen.headers.contains(&"x-device-locale".to_string()),
            "{seen:?}"
        );
        assert_eq!(state.subscriptions[0].last_error, None);
    }

    #[tokio::test]
    async fn subscription_request_head_on_the_wire() {
        let (p, _d) = TestPlatform::new();
        phone(&p);
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;

        let head = requests.lock().unwrap()[0].clone();
        let mut lines = head.split("\r\n");
        assert_eq!(lines.next(), Some("GET /s HTTP/1.1"));
        let sent: Vec<(&str, &str)> = lines.filter_map(|l| l.split_once(": ")).collect();
        let names: Vec<&str> = sent.iter().map(|(n, _)| *n).collect();
        // Happ writes `User-agent`, `X-HWID`, `X-Device-OS`, `X-Ver-OS` and
        // `X-Device-model`, then `Host` and `Accept-Encoding`, and no `Accept`.
        assert_eq!(
            names,
            [
                "Connection",
                "User-Agent",
                "X-Device-Locale",
                "X-Hwid",
                "X-Device-Os",
                "X-Ver-Os",
                "X-Device-Model",
                "Accept",
                "Accept-Encoding",
                "Host",
            ]
        );
        let value = |name: &str| sent.iter().find(|(n, _)| *n == name).unwrap().1;
        assert_eq!(value("Connection"), "close");
        assert_eq!(value("X-Device-Model"), "Pixel 9");
        assert_eq!(value("Accept"), "*/*");
        assert_eq!(value("Accept-Encoding"), "gzip");
        assert_eq!(value("Host"), base.trim_start_matches("http://"));
    }

    #[tokio::test]
    async fn incy_subscription_request_head_on_the_wire() {
        let (p, _d) = TestPlatform::new();
        phone(&p);
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let mut state = read_app_state(&p).await.unwrap();
        state.subscriptions[0].client = kasumi_core::request_identity::RequestClient::Incy;
        write_app_state(&p, &state).await.unwrap();
        let after = update(&p).await;
        assert_eq!(after.subscriptions[0].last_error, None);

        let head = requests.lock().unwrap()[0].clone();
        let sent: Vec<(&str, &str)> = head
            .split("\r\n")
            .skip(1)
            .filter_map(|l| l.split_once(": "))
            .collect();
        let names: Vec<&str> = sent.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            [
                "user-agent",
                "accept",
                "accept-language",
                "x-hwid",
                "x-device-os",
                "x-ver-os",
                "x-device-model",
                "x-app-version",
                "x-device-locale",
                "x-client",
                "accept-encoding",
                "host",
            ]
        );
        let value = |name: &str| sent.iter().find(|(n, _)| *n == name).unwrap().1;
        assert_eq!(value("user-agent"), "INCY/3.7.0/android Dalvik/2.1.0");
        assert_eq!(value("x-client"), "INCY");
        assert_eq!(value("x-device-locale"), "ru_RU");
        assert_eq!(value("x-hwid").len(), 36);
    }

    #[tokio::test]
    async fn custom_user_agent_is_kept() {
        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let mut state = read_app_state(&p).await.unwrap();
        state.subscriptions[0].user_agent = "v2rayNG/1.10.16".into();
        state.subscriptions[0].request.send_hwid = Some(false);
        write_app_state(&p, &state).await.unwrap();
        update(&p).await;
        assert_eq!(
            sent_header(&requests, 0, "user-agent").as_deref(),
            Some("v2rayNG/1.10.16")
        );
        assert_eq!(sent_header(&requests, 0, "x-hwid"), None);
        assert_eq!(sent_header(&requests, 0, "x-device-os"), None);
    }

    #[tokio::test]
    async fn reset_is_retried_without_connection_close() {
        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve(vec![
            crate::testutil::RESET.to_vec(),
            http_response(200, &[], LINK),
        ])
        .await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let next = update(&p).await;
        assert_eq!(next.subscriptions[0].last_error, None);
        assert_eq!(requests.lock().unwrap().len(), 2);
        assert_eq!(
            sent_header(&requests, 0, "connection").as_deref(),
            Some("close")
        );
        assert_eq!(sent_header(&requests, 1, "connection"), None);
    }

    #[tokio::test]
    async fn other_failures_are_retried_once_with_the_same_headers() {
        let (p, _d) = TestPlatform::new();
        // Closing without a reply is an I/O error, not a reset.
        let (base, requests) = serve(vec![Vec::new(), Vec::new(), Vec::new()]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let next = update(&p).await;
        assert!(next.subscriptions[0].last_error.is_some());
        assert_eq!(requests.lock().unwrap().len(), 2, "one retry");
        assert_eq!(sent(&requests, 0), sent(&requests, 1));

        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve(vec![http_response(503, &[], b"busy")]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        assert_eq!(requests.lock().unwrap().len(), 1, "a reply is final");
    }

    #[tokio::test]
    async fn subscriptions_share_one_cookie_jar() {
        for enabled in [true, false] {
            let (p, _d) = TestPlatform::new();
            let set = [("set-cookie", "cf=1; Path=/")];
            let (base, requests) = serve(vec![
                http_response(200, &set, LINK),
                http_response(200, &[], LINK),
            ])
            .await;
            let mut state = default_app_state();
            state.settings.request_identity.cookie_jar = enabled;
            state.subscriptions = vec![
                sub("s1", &format!("{base}/a")),
                sub("s2", &format!("{base}/b")),
            ];
            write_app_state(&p, &state).await.unwrap();
            let cookies = jar();
            for id in ["s1", "s2"] {
                update_subscription(&p, &lifecycle(), &Mutex::new(()), &cookies, id)
                    .await
                    .unwrap();
            }
            let expect = enabled.then(|| "cf=1".to_owned());
            assert_eq!(sent_header(&requests, 1, "cookie"), expect);
        }
    }

    #[tokio::test]
    async fn cookies_are_never_written_to_disk() {
        const VALUE: &str = "kasumi-cookie-sentinel";
        let (p, dir) = TestPlatform::new();
        let cookie = format!("id={VALUE}; Path=/; Max-Age=86400");
        let (base, requests) = serve(vec![
            http_response(200, &[("set-cookie", &cookie)], LINK),
            http_response(200, &[], LINK),
        ])
        .await;
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", &format!("{base}/a"))];
        write_app_state(&p, &state).await.unwrap();
        let cookies = jar();
        for _ in 0..2 {
            update_subscription(&p, &lifecycle(), &Mutex::new(()), &cookies, "s1")
                .await
                .unwrap();
        }
        assert_eq!(
            sent_header(&requests, 1, "cookie"),
            Some(format!("id={VALUE}"))
        );
        let mut dirs = vec![dir.path().to_path_buf()];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
                    assert!(!text.contains(VALUE), "{} holds a cookie", path.display());
                }
            }
        }
    }

    /// State with subscription `s1` at `url` that already owns profile `old`.
    async fn with_old_profile(p: &TestPlatform, url: &str) {
        let mut old = sample_vless();
        old.meta_mut().id = "old".into();
        old.meta_mut().sub_id = Some("s1".into());
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", url)];
        state.profiles = vec![old];
        write_app_state(p, &state).await.unwrap();
    }

    async fn update(p: &TestPlatform) -> AppState {
        update_subscription(p, &lifecycle(), &Mutex::new(()), &jar(), "s1")
            .await
            .unwrap()
    }

    async fn assert_kept(p: &TestPlatform, error: &str) {
        let after = read_app_state(p).await.unwrap();
        let ids: Vec<&str> = after
            .profiles
            .iter()
            .map(|x| x.meta().id.as_str())
            .collect();
        assert_eq!(ids, ["old"]);
        let last_error = after.subscriptions[0].last_error.as_deref().unwrap_or("");
        assert!(last_error.contains(error), "{last_error}");
        assert!(sub_meta::read_all(p).await.is_empty());
    }

    const LINK: &[u8] =
        b"vless://11111111-1111-1111-1111-111111111111@e.example:443?type=tcp#Fresh\n";

    #[tokio::test]
    async fn decrypt_failure_keeps_profiles_and_records_error() {
        let (p, _d) = TestPlatform::new();
        // A tag with `?key=` makes the body ciphertext; plain links fail to decrypt.
        let tag = [("Encrypt-Tag", "AAAAAAAAAAAAAAAAAAAAAA==")];
        let (base, _) = serve(vec![http_response(200, &tag, LINK)]).await;
        with_old_profile(&p, &format!("{base}/s?key=key02")).await;
        update(&p).await;
        assert_kept(&p, "could not be decrypted").await;
    }

    #[tokio::test]
    async fn stored_crypt_link_is_decrypted_at_fetch() {
        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        let link = crate::testutil::crypt1_link(&format!("{base}/s?t=1#N?profile-title=Hidden"));
        with_old_profile(&p, &link).await;
        let after = update(&p).await;

        assert!(requests.lock().unwrap()[0].starts_with("GET /s?t=1 HTTP/1.1"));
        let s = &after.subscriptions[0];
        assert_eq!(s.url, link, "the link stays encrypted");
        assert_eq!(s.last_error, None);
        assert_eq!(after.profiles[0].meta().remarks, "Fresh");
        // The fragment of the decrypted URL is read; the meta is keyed by the link.
        assert_eq!(s.remarks, "Hidden");
        let stored = sub_meta::read_all(&p).await.remove("s1").unwrap();
        assert_eq!(stored.source_url, link);
    }

    #[tokio::test]
    async fn stored_incy_link_is_decrypted_at_fetch() {
        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        let link = crate::testutil::incy_link(&format!("{base}/s?t=1"), Some("Example VPN"));
        with_old_profile(&p, &link).await;
        let after = update(&p).await;

        assert!(requests.lock().unwrap()[0].starts_with("GET /s?t=1 HTTP/1.1"));
        let s = &after.subscriptions[0];
        assert_eq!(s.url, link, "the link stays encrypted");
        assert_eq!(s.last_error, None);
        assert_eq!(after.profiles[0].meta().remarks, "Fresh");
    }

    #[tokio::test]
    async fn undecryptable_link_keeps_profiles() {
        let (p, _d) = TestPlatform::new();
        with_old_profile(&p, "happ://crypt5/zzzzAAAAAAAAAAAAAAAAAAAAAAAA").await;
        update(&p).await;
        assert_kept(&p, "could not be decrypted").await;
        assert_eq!(
            sub_after(&p).await.last_error_kind,
            Some(SubErrorKind::UrlDecrypt)
        );
    }

    #[tokio::test]
    async fn zero_profile_body_keeps_profiles() {
        let (p, _d) = TestPlatform::new();
        let body = b"#profile-title: Empty\nunknown://not-a-proxy\n";
        let (base, _) = serve(vec![http_response(200, &[], body)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        assert_kept(&p, "no profiles in subscription body").await;
    }

    #[tokio::test]
    async fn error_page_html_keeps_profiles() {
        let (p, _d) = TestPlatform::new();
        let page = b"<html><body><h1>502 Bad Gateway</h1></body></html>";
        let html = [("content-type", "text/html; charset=utf-8")];
        let (base, _) = serve(vec![http_response(200, &html, page)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        assert_kept(&p, "web page").await;
    }

    #[tokio::test]
    async fn fragment_never_sent() {
        let (p, _d) = TestPlatform::new();
        let (base, requests) = serve(vec![http_response(200, &[], LINK)]).await;
        let url = format!("{base}/s?token=1#Name?profile-title=FromFragment");
        with_old_profile(&p, &url).await;
        let next = update(&p).await;

        let request_line = requests.lock().unwrap()[0]
            .lines()
            .next()
            .unwrap()
            .to_owned();
        assert_eq!(request_line, "GET /s?token=1 HTTP/1.1");
        assert_eq!(next.subscriptions[0].url, url, "the URL is kept as typed");
        assert_eq!(next.subscriptions[0].last_error, None);
        let stored = sub_meta::read_all(&p).await.remove("s1").unwrap();
        assert_eq!(stored.source_url, url);
        assert_eq!(stored.meta.profile_title(), Some("FromFragment"));
    }

    async fn stored_announce(p: &TestPlatform) -> Option<String> {
        let stored = sub_meta::read_all(p).await.remove("s1").unwrap();
        stored.meta.announce().map(str::to_owned)
    }

    #[tokio::test]
    async fn manual_update_drops_absent_keys_tick_keeps_them() {
        let a = http_response(200, &[("profile-title", "T"), ("announce", "Hi")], LINK);
        let b = http_response(200, &[("profile-title", "T")], LINK);

        // Manual refresh: a key the provider stopped sending is dropped.
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![a.clone(), b.clone()]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        assert_eq!(stored_announce(&p).await.as_deref(), Some("Hi"));
        update(&p).await;
        assert_eq!(stored_announce(&p).await, None);

        // Background update: the same response keeps it.
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![a, b]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        let mut state = read_app_state(&p).await.unwrap();
        state.subscriptions[0].last_updated.clear(); // due again
        write_app_state(&p, &state).await.unwrap();
        tick(
            &p,
            &lifecycle(),
            &Mutex::new(()),
            &jar(),
            &mut HashMap::new(),
            &|_| {},
        )
        .await;
        let after = read_app_state(&p).await.unwrap();
        assert!(
            !after.subscriptions[0].last_updated.is_empty(),
            "tick applied"
        );
        assert_eq!(stored_announce(&p).await.as_deref(), Some("Hi"));
    }

    #[tokio::test]
    async fn sub_meta_entry_removed_when_subscription_gone() {
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![http_response(200, &[("profile-title", "T")], LINK)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        sub_meta::write_entry(&p, "gone", Some(StoredSubMeta::default()), &["gone"])
            .await
            .unwrap();
        update(&p).await;
        let all = sub_meta::read_all(&p).await;
        assert_eq!(all.keys().collect::<Vec<_>>(), ["s1"]);
    }

    async fn sub_after(p: &TestPlatform) -> Subscription {
        read_app_state(p).await.unwrap().subscriptions.remove(0)
    }

    #[tokio::test]
    async fn live_fixture_fills_provider_info() {
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![crate::testutil::fixture_response("01-happ-full")]).await;
        let mut state = default_app_state();
        let mut s = sub("s1", &format!("{base}/s"));
        s.auto_update = false;
        state.subscriptions = vec![s];
        write_app_state(&p, &state).await.unwrap();
        update(&p).await;

        let s = sub_after(&p).await;
        assert_eq!(s.remarks, "Example VPN 🗽");
        assert_eq!(s.provider_interval_hours, Some(1));
        assert!(s.auto_update, "first import with a provider interval");
        let info = s.provider.unwrap();
        assert_eq!(info.traffic.unwrap().expire, Some(1_796_256_000));
        assert!(info.announce.is_some() && info.support_url.is_some());
    }

    #[tokio::test]
    async fn apply_renames_owned_group_on_provider_title() {
        let titled = || http_response(200, &[("profile-title", "Provider")], LINK);
        for manual in [false, true] {
            let (p, _d) = TestPlatform::new();
            let (base, _) = serve(vec![titled()]).await;
            let mut state = default_app_state();
            let mut s = sub("s1", &format!("{base}/s"));
            s.group_id = Some("g-s1".into());
            s.manual_title = manual;
            state.subscriptions = vec![s];
            state.groups.push(kasumi_core::state::Group {
                id: "g-s1".into(),
                name: "sub-s1".into(),
                sub_id: Some("s1".into()),
            });
            write_app_state(&p, &state).await.unwrap();
            let next = update(&p).await;

            let expect = if manual { "sub-s1" } else { "Provider" };
            assert_eq!(next.subscriptions[0].remarks, expect);
            let group = next.groups.iter().find(|g| g.id == "g-s1").unwrap();
            assert_eq!(group.name, expect);
        }
    }

    #[tokio::test]
    async fn refresh_does_not_switch_auto_update_back_on() {
        let headers = [("profile-update-interval", "6")];
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![
            http_response(200, &headers, LINK),
            http_response(200, &headers, LINK),
        ])
        .await;
        let mut state = default_app_state();
        let mut s = sub("s1", &format!("{base}/s"));
        // Fetched before sub-meta.json existed, as after an upgrade.
        s.last_updated = "2026-01-01T00:00:00.000Z".into();
        s.auto_update = false;
        state.subscriptions = vec![s];
        write_app_state(&p, &state).await.unwrap();
        update(&p).await;
        assert!(!sub_after(&p).await.auto_update);
        update(&p).await;
        let s = sub_after(&p).await;
        assert!(!s.auto_update);
        assert_eq!(s.provider_interval_hours, Some(6));
    }

    #[test]
    fn tick_uses_provider_interval() {
        let mut s = sub("s", "u");
        s.interval = 60;
        s.provider_interval_hours = Some(24);
        let now = 3 * 3_600_000;
        s.last_updated = now_iso_at(0);
        assert!(!is_due(&s, None, now), "the provider asks for a day");
        s.interval_override = true;
        assert!(is_due(&s, None, now), "the user's hour wins");
    }

    #[tokio::test]
    async fn request_timeout_from_provider() {
        let mut s = sub("s", "u");
        assert_eq!(fetch_timeout(&s), FETCH_TIMEOUT);
        s.request_timeout_secs = Some(7);
        assert_eq!(fetch_timeout(&s), Duration::from_secs(7));

        let (p, _d) = TestPlatform::new();
        let headers = [("subscription-request-timeout", "60")];
        let (base, _) = serve(vec![http_response(200, &headers, LINK)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        assert_eq!(sub_after(&p).await.request_timeout_secs, Some(15));
    }

    #[tokio::test]
    async fn error_kind_recorded_for_http_and_decrypt() {
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![http_response(403, &[], b"no")]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        let s = sub_after(&p).await;
        assert_eq!(s.last_error_kind, Some(SubErrorKind::Http { status: 403 }));
        assert_eq!(s.last_error.as_deref(), Some("HTTP 403"));

        let (p, _d) = TestPlatform::new();
        let tag = [("Encrypt-Tag", "AAAAAAAAAAAAAAAAAAAAAA==")];
        let (base, _) = serve(vec![
            http_response(200, &tag, LINK),
            http_response(200, &[], LINK),
        ])
        .await;
        with_old_profile(&p, &format!("{base}/s?key=key02")).await;
        update(&p).await;
        assert_eq!(
            sub_after(&p).await.last_error_kind,
            Some(SubErrorKind::Decrypt {
                key_id: Some("key02".into())
            })
        );
        // A later success clears both.
        update(&p).await;
        let s = sub_after(&p).await;
        assert_eq!((s.last_error, s.last_error_kind), (None, None));
    }

    #[tokio::test]
    async fn plain_errors_have_no_kind() {
        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", "   ")];
        write_app_state(&p, &state).await.unwrap();
        let returned = update(&p).await;
        assert_eq!(returned.subscriptions[0].last_error_kind, None);
    }

    fn reality(sni: &str, sid: &str, port: u16) -> Vec<u8> {
        let link = format!(
            "vless://11111111-1111-1111-1111-111111111111@r.example.org:{port}?type=tcp\
             &security=reality&pbk=PK&fp=firefox&sni={sni}&sid={sid}#Node\n"
        );
        http_response(200, &[], link.as_bytes())
    }

    fn reality_config(sni: &str, sid: &str, port: u16) -> Vec<u8> {
        let config = serde_json::json!({ "remarks": "Node", "outbounds": [
            { "tag": "proxy", "protocol": "vless",
              "settings": { "vnext": [{ "address": "r.example.org", "port": port,
                  "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
              "streamSettings": { "network": "tcp", "security": "reality",
                  "realitySettings": { "serverName": sni, "shortId": sid, "publicKey": "PK",
                      "fingerprint": "firefox" } } },
        ]});
        http_response(200, &[], config.to_string().as_bytes())
    }

    /// Fetch `first`, make its profile active, then fetch `second` and report the
    /// lifecycle calls the second apply made.
    async fn refresh_calls(first: Vec<u8>, second: Vec<u8>) -> Vec<String> {
        refresh_calls_with(false, first, second).await
    }

    async fn refresh_calls_with(
        allow_provider_configs: bool,
        first: Vec<u8>,
        second: Vec<u8>,
    ) -> Vec<String> {
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![first, second]).await;
        let mut state = default_app_state();
        state.subscriptions = vec![Subscription {
            allow_provider_configs,
            ..sub("s1", &format!("{base}/s"))
        }];
        write_app_state(&p, &state).await.unwrap();
        let mut state = update(&p).await;
        state.active_id = Some(state.profiles[0].meta().id.clone());
        write_app_state(&p, &state).await.unwrap();

        let lc = lifecycle();
        update_subscription(&p, &lc, &Mutex::new(()), &jar(), "s1")
            .await
            .unwrap();
        lc.calls.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn reality_sni_and_sid_rotation_does_not_restart() {
        let calls = refresh_calls(
            reality("a1.sni.example.com", "aaaa", 443),
            reality("b2.sni.example.com", "bbbb", 443),
        )
        .await;
        assert_eq!(calls, Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_port_change_still_restarts() {
        let calls = refresh_calls(
            reality("a1.sni.example.com", "aaaa", 443),
            reality("b2.sni.example.com", "bbbb", 8443),
        )
        .await;
        assert!(calls.iter().any(|c| c.starts_with("restart")), "{calls:?}");
    }

    #[tokio::test]
    async fn provider_config_reality_rotation_does_not_restart() {
        let calls = refresh_calls_with(
            true,
            reality_config("a1.sni.example.com", "aaaa", 443),
            reality_config("b2.sni.example.com", "bbbb", 443),
        )
        .await;
        assert_eq!(calls, Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_provider_config_port_change_still_restarts() {
        let calls = refresh_calls_with(
            true,
            reality_config("a1.sni.example.com", "aaaa", 443),
            reality_config("b2.sni.example.com", "bbbb", 8443),
        )
        .await;
        assert!(calls.iter().any(|c| c.starts_with("restart")), "{calls:?}");
    }

    fn request_paths(requests: &crate::testutil::Requests) -> Vec<String> {
        requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.split(' ').nth(1).unwrap_or_default().to_owned())
            .collect()
    }

    #[tokio::test]
    async fn fallback_used_only_after_consent() {
        let (p, _d) = TestPlatform::new();
        let offered = [("fallback-url", "https://backup.example.net/s")];
        let (base, requests) = serve(vec![
            http_response(200, &offered, LINK),
            http_response(500, &[], b"down"),
        ])
        .await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        let s = sub_after(&p).await;
        assert_eq!(s.fallback_url, None, "offered, not applied");
        assert_eq!(s.pending_changes[0].key, "fallback-url");

        let s = update(&p).await.subscriptions.remove(0);
        assert!(s.last_error.is_some());
        assert_eq!(request_paths(&requests), ["/s", "/s"], "no fallback fetch");

        // Accepted: the next failure falls back to it.
        let (fb, fb_requests) = serve(vec![http_response(200, &[], LINK)]).await;
        let mut state = read_app_state(&p).await.unwrap();
        state.subscriptions[0].fallback_url = Some(format!("{fb}/backup"));
        write_app_state(&p, &state).await.unwrap();
        let s = update(&p).await.subscriptions.remove(0);
        assert_eq!(s.last_error, None);
        assert_eq!(request_paths(&fb_requests), ["/backup"]);
        assert_eq!(
            s.warnings[0],
            SubWarning::UsedFallback {
                host: "127.0.0.1".into()
            }
        );
    }

    #[tokio::test]
    async fn fallback_redirect_to_private_refused() {
        let (p, _d) = TestPlatform::new();
        let (target, target_requests) = serve(vec![http_response(200, &[], LINK)]).await;
        let location = format!("{target}/internal");
        let (fb, _) = serve(vec![http_response(
            302,
            &[("location", location.as_str())],
            b"",
        )])
        .await;
        let (base, _) = serve(vec![http_response(503, &[], b"down")]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let mut state = read_app_state(&p).await.unwrap();
        state.subscriptions[0].fallback_url = Some(format!("{fb}/backup"));
        write_app_state(&p, &state).await.unwrap();

        update(&p).await;
        assert_kept(&p, "HTTP 503").await;
        assert!(target_requests.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn live_fixture_with_an_empty_routing_offers_none() {
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![crate::testutil::fixture_response("01-happ-full")]).await;
        let mut state = default_app_state();
        state.subscriptions = vec![sub("s1", &format!("{base}/s"))];
        write_app_state(&p, &state).await.unwrap();
        let next = update(&p).await;

        let s = &next.subscriptions[0];
        assert!(s.pending_changes.is_empty());
        assert_eq!(next.routes, state.routes, "no routing applied");
        assert_eq!(next.rule_blocks, state.rule_blocks);
        assert!(s.audit.is_empty());
    }

    #[tokio::test]
    async fn routing_off_switches_the_provider_route_off() {
        let (p, _d) = TestPlatform::new();
        let body = [LINK, b"happ://routing/off\n"].concat();
        let (base, _) = serve(vec![http_response(200, &[], &body)]).await;
        with_old_profile(&p, &format!("{base}/s")).await;
        let mut state = read_app_state(&p).await.unwrap();
        state.routes.push(kasumi_core::route::Route {
            id: "sub-route-s1".into(),
            name: "Provider".into(),
            source_sub_id: Some("s1".into()),
            ..kasumi_core::route::default_route()
        });
        write_app_state(&p, &state).await.unwrap();
        let next = update(&p).await;
        let route = next.routes.iter().find(|r| r.id == "sub-route-s1").unwrap();
        assert!(!route.enabled);
        assert_eq!(
            next.subscriptions[0].audit[0].outcome,
            AuditOutcome::AutoApplied
        );
    }

    fn xray_array(tag: &str, names: [&str; 2]) -> Vec<u8> {
        let config = |name: &str, host: &str| {
            serde_json::json!({
                "remarks": name,
                "log": { "access": "/data/adb/kasumi-proxy/a.log" },
                "outbounds": [{ "tag": tag, "protocol": "trojan",
                    "settings": { "servers": [{ "address": host, "port": 443, "password": "pw" }] } }],
            })
        };
        serde_json::json!([config(names[0], "a.example"), config(names[1], "b.example")])
            .to_string()
            .into_bytes()
    }

    #[tokio::test]
    async fn json_configs_wait_for_consent_then_import() {
        let (p, _d) = TestPlatform::new();
        let (base, _) = serve(vec![
            http_response(200, &[], &xray_array("proxy", ["A", "B"])),
            http_response(200, &[], &xray_array("proxy", ["A", "B"])),
            http_response(200, &[], &xray_array("proxy", ["A", "B"])),
            http_response(200, &[], &xray_array("renamed", ["A1", "B1"])),
        ])
        .await;
        with_old_profile(&p, &format!("{base}/s")).await;
        update(&p).await;
        update(&p).await;
        assert_kept(&p, "not allowed").await;
        let s = sub_after(&p).await;
        assert_eq!(
            s.last_error_kind,
            Some(SubErrorKind::UnsupportedPayload {
                payload: kasumi_core::state::PayloadKind::JsonArray
            })
        );
        // Asked once, however many refused fetches.
        assert_eq!(s.pending_changes.len(), 1);
        assert_eq!(
            s.pending_changes[0].action,
            kasumi_core::state::ChangeAction::AllowProviderConfigs
        );
        assert_eq!(s.audit.len(), 1);

        let mut state = read_app_state(&p).await.unwrap();
        let digest = s.pending_changes[0].digest.clone();
        kasumi_core::sub_changes::resolve_changes(&mut state, "s1", &[digest], true, None, "t");
        write_app_state(&p, &state).await.unwrap();
        let next = update(&p).await;
        let s = &next.subscriptions[0];
        assert!(s.allow_provider_configs && s.last_error.is_none());
        assert!(s.pending_changes.is_empty());
        let names: Vec<&str> = next
            .profiles
            .iter()
            .map(|x| x.meta().remarks.as_str())
            .collect();
        assert_eq!(names, ["A", "B"]);
        assert!(
            next.profiles
                .iter()
                .all(|x| matches!(x, Profile::Custom(c) if !c.raw.contains("/data/adb")))
        );

        // A refresh that renames the configs and their tags keeps the selection.
        let mut state = next.clone();
        let picked = state.profiles[1].meta().id.clone();
        state.active_id = Some(picked);
        write_app_state(&p, &state).await.unwrap();
        let next = update(&p).await;
        let active = next
            .profiles
            .iter()
            .find(|x| Some(&x.meta().id) == next.active_id.as_ref())
            .unwrap();
        assert_eq!(active.meta().remarks, "B1");
    }
}
