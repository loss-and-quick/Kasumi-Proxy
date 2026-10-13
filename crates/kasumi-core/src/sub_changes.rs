//! Provider keys that need the user's consent. A fetch turns the `TrustBoundary` and
//! `TunnelBehaviour` keys (and routing deeplinks) into [`PendingChange`]s; the
//! `ResolveSubChange` intent answers them, and only an accepted one changes state.
//! Happ applies `new-url`, `new-domain` and `fallback-url` only to subscriptions its
//! vendor service marks as special; Kasumi offers them to every subscription instead,
//! behind this review.

use happ_sub::meta::{changes, classify_key, single_line, validate_url_safety};
use happ_sub::{MetaMap, RiskClass, RoutingAction, RoutingProfile};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::import_input::is_encrypted_url;
use crate::profile::{CustomOrigin, Profile};
use crate::route::{Route, RouteBlockRef, RuleBlock, upsert_route};
use crate::state::{
    AdvancedSettings, AppState, AuditEntry, AuditOutcome, BASE_GROUP_ID, ChangeAction,
    ChangeDecision, PendingChange, RoutingImport, RoutingRule, Subscription, TunnelSetting,
};
use crate::sub_apply::{next_active_id_after_subscription_update, owned_by_sub};

/// Audit entries kept per subscription.
pub const AUDIT_MAX: usize = 50;
/// Answers kept per subscription; an older answered value may be asked about again.
pub const DECISIONS_MAX: usize = 100;
/// Keys whose consent happ-sub reads while building the request.
pub const CONSENT_KEYS: [&str; 2] = ["change-user-agent", "manual-block-user-agent"];
/// The key of the [`ChangeAction::AllowProviderConfigs`] request.
pub const PROVIDER_CONFIGS_KEY: &str = "provider-configs";
const PROVIDER_CONFIGS_VALUE: &str = "Xray JSON";

const SUMMARY_MAX: usize = 200;
const ROUTING_NAME_MAX: usize = 64;
const RULE_ENTRY_MAX: usize = 512;

/// SHA-256 over `key\0content`, lower-case hex.
pub fn digest(key: &str, content: &str) -> String {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    h.update([0]);
    h.update(content.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn clean(value: &str) -> String {
    // MetaMap already dropped control and bidi characters on insert.
    single_line(value)
}

fn parse_bool(value: &str) -> bool {
    let v = value.trim();
    v.eq_ignore_ascii_case("true") || v == "1"
}

/// The provider keys among [`CONSENT_KEYS`] whose current value the user accepted.
pub fn consented_keys(sub: &Subscription, meta: Option<&MetaMap>) -> Vec<String> {
    let Some(meta) = meta else {
        return Vec::new();
    };
    CONSENT_KEYS
        .iter()
        .filter(|key| {
            meta.get(key).is_some_and(|v| {
                let d = digest(key, &clean(v));
                sub.decisions.iter().any(|x| x.accepted && x.digest == d)
            })
        })
        .map(|k| (*k).to_owned())
        .collect()
}

/// What one fetch proposes: the subscription's new pending list and what to audit.
#[derive(Debug, Default)]
pub struct Offers {
    pub pending: Vec<PendingChange>,
    pub audit: Vec<AuditEntry>,
}

enum Mapped {
    Offer {
        action: Box<ChangeAction>,
        previous: Option<String>,
    },
    /// Nothing would change.
    NoOp,
    Ignore(String),
}

/// The pending changes `sub` gets from a fetch whose merged meta went from `old` to
/// `new`. An answered value is not offered again; a changed one is.
pub fn offer_changes(
    state: &AppState,
    sub: &Subscription,
    old: Option<&MetaMap>,
    new: &MetaMap,
    routing: &[RoutingAction],
    now: &str,
) -> Offers {
    let deltas = changes(old, new);
    let changed = |key: &str| deltas.iter().any(|d| d.key == key);
    let mut out = Offers::default();
    for (key, raw) in new.iter() {
        let risk = classify_key(key);
        if !matches!(risk, RiskClass::TrustBoundary | RiskClass::TunnelBehaviour)
            || key == "routing"
        {
            continue;
        }
        let value = clean(raw);
        match map_key(state, sub, key, &value) {
            Mapped::NoOp => {}
            Mapped::Ignore(reason) => {
                if changed(key) {
                    out.audit
                        .push(audit(now, key, AuditOutcome::Ignored, &reason));
                }
            }
            Mapped::Offer { action, previous } => {
                let d = digest(key, &value);
                offer(&mut out, sub, now, key, value, previous, risk, *action, d);
            }
        }
    }

    match routing_offer(routing, new) {
        Some(import) => {
            let content = serde_json::to_string(&import).unwrap_or_default();
            let d = digest("routing", &content);
            let action = ChangeAction::ImportRouting {
                routing: import.clone(),
                activate: true,
            };
            offer(
                &mut out,
                sub,
                now,
                "routing",
                import.name,
                None,
                RiskClass::TrustBoundary,
                action,
                d,
            );
        }
        // A routing profile stays on offer until answered, even when a later
        // response no longer carries it.
        None => out.pending.extend(
            sub.pending_changes
                .iter()
                .filter(|p| matches!(p.action, ChangeAction::ImportRouting { .. }))
                .cloned(),
        ),
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn offer(
    out: &mut Offers,
    sub: &Subscription,
    now: &str,
    key: &str,
    value: String,
    previous: Option<String>,
    risk: RiskClass,
    action: ChangeAction,
    digest: String,
) {
    if sub.decisions.iter().any(|d| d.digest == digest) {
        return;
    }
    let seen_at = match sub.pending_changes.iter().find(|p| p.digest == digest) {
        Some(p) => p.seen_at.clone(),
        None => {
            out.audit
                .push(audit(now, key, AuditOutcome::Offered, &value));
            now.to_owned()
        }
    };
    out.pending.push(PendingChange {
        key: key.to_owned(),
        value,
        previous,
        risk: risk.into(),
        action,
        digest,
        seen_at,
    });
}

fn audit(at: &str, key: &str, outcome: AuditOutcome, summary: &str) -> AuditEntry {
    AuditEntry {
        at: at.to_owned(),
        key: key.to_owned(),
        outcome,
        summary: summary.chars().take(SUMMARY_MAX).collect(),
    }
}

fn map_key(state: &AppState, sub: &Subscription, key: &str, value: &str) -> Mapped {
    let s = &state.settings;
    match key {
        "new-url" => match safe_url(value) {
            Err(e) => Mapped::Ignore(e),
            Ok(url) if same_url(&url, &sub.url) => Mapped::NoOp,
            Ok(url) => {
                let (from_host, to_host) = (host_of(&sub.url), host_of(&url));
                Mapped::Offer {
                    action: Box::new(ChangeAction::ReplaceUrl {
                        other_domain: other_domain(&from_host, &to_host),
                        url,
                        from_host,
                        to_host,
                    }),
                    previous: Some(sub.url.clone()),
                }
            }
        },
        // The domain of an encrypted link is the provider's secret.
        "new-domain" if is_encrypted_url(&sub.url) => {
            Mapped::Ignore("the subscription link is encrypted".into())
        }
        "new-domain" => match replace_authority(&sub.url, value) {
            Err(e) => Mapped::Ignore(e),
            Ok(url) if url == sub.url => Mapped::NoOp,
            Ok(url) => match safe_url(&url) {
                Err(e) => Mapped::Ignore(e),
                Ok(url) => {
                    let (from_host, to_host) = (host_of(&sub.url), host_of(&url));
                    Mapped::Offer {
                        action: Box::new(ChangeAction::ReplaceDomain {
                            other_domain: other_domain(&from_host, &to_host),
                            url,
                            from_host,
                            to_host,
                        }),
                        previous: Some(sub.url.clone()),
                    }
                }
            },
        },
        "fallback-url" => match safe_url(value) {
            Err(e) => Mapped::Ignore(e),
            Ok(url) if sub.fallback_url.as_deref() == Some(url.as_str()) => Mapped::NoOp,
            Ok(url) => Mapped::Offer {
                action: Box::new(ChangeAction::SetFallbackUrl {
                    host: host_of(&url),
                    url,
                }),
                previous: sub.fallback_url.clone(),
            },
        },
        "change-user-agent" => {
            let ua = value.trim();
            if ua.is_empty() || !ua.chars().all(|c| (' '..='~').contains(&c)) {
                return Mapped::Ignore("not a printable ASCII User-Agent".into());
            }
            Mapped::Offer {
                action: Box::new(ChangeAction::SetUserAgent {
                    user_agent: ua.to_owned(),
                }),
                previous: Some(sub.user_agent.trim().to_owned()).filter(|u| !u.is_empty()),
            }
        }
        "manual-block-user-agent" => {
            if !parse_bool(value) {
                return Mapped::NoOp;
            }
            Mapped::Offer {
                action: Box::new(ChangeAction::LockUserAgent { on: true }),
                previous: Some(sub.user_agent.trim().to_owned()).filter(|u| !u.is_empty()),
            }
        }
        "insecure" => {
            let on = parse_bool(value);
            // Off only undoes what an accepted `insecure` turned on.
            if on == sub.allow_insecure || (!on && !sub.insecure_by_provider) {
                return Mapped::NoOp;
            }
            Mapped::Offer {
                action: Box::new(ChangeAction::SetInsecure { on }),
                previous: Some(sub.allow_insecure.to_string()),
            }
        }
        "routing-enable" => {
            let on = parse_bool(value);
            match provider_route(state, &sub.id) {
                Some(r) if r.enabled != on => Mapped::Offer {
                    action: Box::new(ChangeAction::SetRoutingEnabled { on }),
                    previous: Some(r.enabled.to_string()),
                },
                _ => Mapped::NoOp,
            }
        }
        _ => match tunnel_setting(key, value) {
            Some(Ok(setting)) => match current_setting(s, &setting) {
                Some(now) if now == setting_value(&setting) => Mapped::NoOp,
                previous => Mapped::Offer {
                    action: Box::new(ChangeAction::TunnelSetting { setting }),
                    previous,
                },
            },
            Some(Err(e)) => Mapped::Ignore(e),
            None => Mapped::Offer {
                action: Box::new(ChangeAction::Unsupported),
                previous: None,
            },
        },
    }
}

/// An http(s) URL to a public host, as the provider wrote it.
fn safe_url(value: &str) -> Result<String, String> {
    let url = value.trim();
    url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    validate_url_safety(url, true).map_err(str::to_owned)?;
    Ok(url.to_owned())
}

fn same_url(a: &str, b: &str) -> bool {
    let wire = happ_sub::meta::fetch_url;
    wire(a.trim()) == wire(b.trim())
}

/// The host of an http(s) `url`, or empty.
pub fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
        .and_then(|u| {
            u.host_str()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        })
        .unwrap_or_default()
}

/// Whether two hosts differ in their last two labels. Enough to word a warning; a
/// public-suffix list would be needed to tell `a.co.uk` from `b.co.uk`.
fn other_domain(from: &str, to: &str) -> bool {
    let tail = |h: &str| {
        let labels: Vec<&str> = h.rsplit('.').take(2).collect();
        labels.join(".")
    };
    tail(from) != tail(to)
}

/// `url` with its authority replaced by `domain` (`host`, `host:port` or a URL
/// whose authority is taken); path, query and fragment are kept.
fn replace_authority(url: &str, domain: &str) -> Result<String, String> {
    let domain = domain.trim();
    let domain = domain.split_once("://").map_or(domain, |(_, rest)| rest);
    let authority = domain.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty()
        || authority.contains(['@', '\\'])
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("invalid domain".into());
    }
    let (scheme, rest) = url
        .trim()
        .split_once("://")
        .ok_or("subscription URL has no scheme")?;
    let tail = rest.find(['/', '?', '#']).map_or("", |i| &rest[i..]);
    Ok(format!("{scheme}://{authority}{tail}"))
}

fn tunnel_setting(key: &str, value: &str) -> Option<Result<TunnelSetting, String>> {
    let on = parse_bool(value);
    let range = |v: &str| {
        let v = v.trim();
        let num = |s: &str| !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit());
        let ok = match v.split_once('-') {
            Some((a, b)) => num(a) && num(b),
            None => num(v),
        };
        if ok {
            Ok(v.to_owned())
        } else {
            Err(format!("not a number or range: {v}"))
        }
    };
    Some(match key {
        "mux-enable" => Ok(TunnelSetting::Mux { on }),
        "fragmentation-enable" => Ok(TunnelSetting::Fragment { on }),
        "sniffing-enable" => Ok(TunnelSetting::Sniffing { on }),
        "fragmentation-packets" => {
            let v = value.trim();
            if v.eq_ignore_ascii_case("tlshello") {
                Ok(TunnelSetting::FragmentPackets {
                    value: "tlshello".into(),
                })
            } else {
                range(v).map(|value| TunnelSetting::FragmentPackets { value })
            }
        }
        "fragmentation-length" => range(value).map(|value| TunnelSetting::FragmentLength { value }),
        "fragmentation-interval" => {
            range(value).map(|value| TunnelSetting::FragmentInterval { value })
        }
        _ => return None,
    })
}

fn setting_value(setting: &TunnelSetting) -> String {
    match setting {
        TunnelSetting::Mux { on }
        | TunnelSetting::Fragment { on }
        | TunnelSetting::Sniffing { on } => on.to_string(),
        TunnelSetting::FragmentPackets { value }
        | TunnelSetting::FragmentLength { value }
        | TunnelSetting::FragmentInterval { value } => value.clone(),
    }
}

fn current_setting(s: &AdvancedSettings, setting: &TunnelSetting) -> Option<String> {
    match setting {
        TunnelSetting::Mux { .. } => Some(s.mux.to_string()),
        TunnelSetting::Fragment { .. } => Some(s.fragment.to_string()),
        TunnelSetting::Sniffing { .. } => Some(s.domain_sniffing.to_string()),
        TunnelSetting::FragmentPackets { .. } => Some(s.fragment_packets.clone()),
        TunnelSetting::FragmentLength { .. } => s.fragment_length.clone(),
        TunnelSetting::FragmentInterval { .. } => s.fragment_delay.clone(),
    }
    .filter(|v| !v.is_empty())
}

/// The last routing profile the fetch delivered, from the body or the stored header.
fn routing_offer(routing: &[RoutingAction], meta: &MetaMap) -> Option<RoutingImport> {
    let from_meta = meta
        .routing()
        .and_then(|link| happ_sub::routing::parse_routing_url(link).ok());
    routing
        .iter()
        .chain(from_meta.as_ref())
        .rev()
        .find_map(RoutingAction::profile)
        .map(routing_import)
}

/// Map a Happ routing profile onto Kasumi's rule lists. DNS, geo-file URLs, the
/// domain strategy and fake DNS are global settings in Kasumi, not part of a route,
/// so they are listed as ignored rather than applied.
pub fn routing_import(p: &RoutingProfile) -> RoutingImport {
    let name: String = clean(&happ_sub::meta::normalize_untrusted_text(&p.name))
        .chars()
        .take(ROUTING_NAME_MAX)
        .collect();
    let set = |s: &Option<String>| s.as_deref().is_some_and(|v| !v.trim().is_empty());
    let ignored = [
        ("DomainStrategy", set(&p.domain_strategy)),
        ("RemoteDnsType", set(&p.remote_dns_type)),
        ("RemoteDnsDomain", set(&p.remote_dns_domain)),
        ("RemoteDnsIp", set(&p.remote_dns_ip)),
        ("DomesticDnsType", set(&p.domestic_dns_type)),
        ("DomesticDnsDomain", set(&p.domestic_dns_domain)),
        ("DomesticDnsIp", set(&p.domestic_dns_ip)),
        (
            "DnsHosts",
            p.dns_hosts.as_ref().is_some_and(|h| !h.is_empty()),
        ),
        ("FakeDns", p.fake_dns.is_some()),
        ("Geoipurl", set(&p.geoipurl)),
        ("Geositeurl", set(&p.geositeurl)),
    ];
    RoutingImport {
        name: if name.is_empty() {
            "Routing".into()
        } else {
            name
        },
        direct_sites: rule_entries(&p.direct_sites),
        direct_ip: rule_entries(&p.direct_ip),
        proxy_sites: rule_entries(&p.proxy_sites),
        proxy_ip: rule_entries(&p.proxy_ip),
        block_sites: rule_entries(&p.block_sites),
        block_ip: rule_entries(&p.block_ip),
        global_proxy: p.global_proxy,
        ignored_fields: ignored
            .iter()
            .filter(|(_, on)| *on)
            .map(|(name, _)| (*name).to_owned())
            .collect(),
    }
}

/// Entries the cores can take as a domain or IP matcher: one token, no controls.
fn rule_entries(list: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in list {
        let e = raw.trim();
        let ok = !e.is_empty()
            && e.len() <= RULE_ENTRY_MAX
            && !e.chars().any(|c| c.is_whitespace() || c.is_control())
            && !e.contains(['"', '\\']);
        if ok && !out.iter().any(|x| x == e) {
            out.push(e.to_owned());
        }
    }
    out
}

fn provider_route<'a>(state: &'a AppState, sub_id: &str) -> Option<&'a Route> {
    state
        .routes
        .iter()
        .find(|r| r.source_sub_id.as_deref() == Some(sub_id))
}

/// The ids of the block and route imported for `sub_id`: one of each per subscription.
pub fn provider_ids(sub_id: &str) -> (String, String) {
    (format!("sub-block-{sub_id}"), format!("sub-route-{sub_id}"))
}

/// `happ://routing/off`: switch off the routes imported from `sub_id`, and only those.
pub fn routing_off(state: &mut AppState, sub_id: &str) -> bool {
    let mut changed = false;
    for r in state
        .routes
        .iter_mut()
        .filter(|r| r.source_sub_id.as_deref() == Some(sub_id) && r.enabled)
    {
        r.enabled = false;
        changed = true;
    }
    changed
}

/// Ask, once, to import the full Xray configs `sub`'s provider sends; `false` when
/// nothing changed. Not a provider key: Kasumi raises it when such a body arrives.
pub fn offer_provider_configs(sub: &mut Subscription, now: &str) -> bool {
    let d = digest(PROVIDER_CONFIGS_KEY, PROVIDER_CONFIGS_VALUE);
    let asked = sub.decisions.iter().any(|x| x.digest == d)
        || sub.pending_changes.iter().any(|p| p.digest == d);
    if sub.allow_provider_configs || asked {
        return false;
    }
    sub.pending_changes.push(PendingChange {
        key: PROVIDER_CONFIGS_KEY.to_owned(),
        value: PROVIDER_CONFIGS_VALUE.to_owned(),
        previous: None,
        risk: RiskClass::TrustBoundary.into(),
        action: ChangeAction::AllowProviderConfigs,
        digest: d,
        seen_at: now.to_owned(),
    });
    let entry = audit(
        now,
        PROVIDER_CONFIGS_KEY,
        AuditOutcome::Offered,
        PROVIDER_CONFIGS_VALUE,
    );
    push_audit(sub, vec![entry]);
    true
}

/// The full Xray configs `sub` imported that withdrawing the permission removes.
fn provider_configs_of<'a>(
    profiles: &'a [Profile],
    sub: &'a Subscription,
) -> impl Iterator<Item = &'a Profile> {
    profiles.iter().filter(|p| {
        matches!(p, Profile::Custom(c) if c.origin == CustomOrigin::Provider)
            && owned_by_sub(p, &sub.id, sub.group_id.as_deref())
    })
}

/// Take back the permission to import `sub_id`'s full Xray configs and remove the
/// ones it imported. The active selection moves on as after a refresh that no
/// longer carries them.
pub fn withdraw_provider_configs(state: &mut AppState, sub_id: &str) {
    let Some(sub) = state.subscriptions.iter_mut().find(|s| s.id == sub_id) else {
        return;
    };
    sub.allow_provider_configs = false;
    let sub = sub.clone();
    let gone: HashSet<String> = provider_configs_of(&state.profiles, &sub)
        .map(|p| p.meta().id.clone())
        .collect();
    if let Some(active) = state.active_id.as_deref().filter(|id| gone.contains(*id)) {
        let left: Vec<Profile> = state
            .profiles
            .iter()
            .filter(|p| p.meta().sub_id.as_deref() == Some(sub_id) && !gone.contains(&p.meta().id))
            .cloned()
            .collect();
        state.active_id =
            next_active_id_after_subscription_update(&state.profiles, Some(active), sub_id, &left);
    }
    state.profiles.retain(|p| !gone.contains(&p.meta().id));
}

/// Prepend `entries` to `sub`'s audit, keeping [`AUDIT_MAX`].
pub fn push_audit(sub: &mut Subscription, entries: Vec<AuditEntry>) {
    let mut next = entries;
    next.reverse();
    next.append(&mut sub.audit);
    next.truncate(AUDIT_MAX);
    sub.audit = next;
}

/// Answer the pending changes `digests` of `sub_id`. Accepting applies each one;
/// either answer is recorded and audited. `activate` overrides a routing import's
/// default. Unknown digests are skipped.
pub fn resolve_changes(
    state: &mut AppState,
    sub_id: &str,
    digests: &[String],
    accept: bool,
    activate: Option<bool>,
    at: &str,
) {
    for d in digests {
        let Some(i) = state.subscriptions.iter().position(|s| s.id == sub_id) else {
            return;
        };
        let sub = &mut state.subscriptions[i];
        let Some(pos) = sub.pending_changes.iter().position(|p| p.digest == *d) else {
            continue;
        };
        let change = sub.pending_changes.remove(pos);
        // Only a dismissal is possible for a key Kasumi cannot apply.
        let accepted = accept && change.action != ChangeAction::Unsupported;
        sub.decisions.insert(
            0,
            ChangeDecision {
                key: change.key.clone(),
                digest: change.digest.clone(),
                accepted,
                at: at.to_owned(),
            },
        );
        sub.decisions.truncate(DECISIONS_MAX);
        let outcome = if accepted {
            AuditOutcome::Accepted
        } else {
            AuditOutcome::Rejected
        };
        push_audit(sub, vec![audit(at, &change.key, outcome, &change.value)]);
        if accepted {
            apply_action(state, i, &change.action, activate);
        }
    }
}

fn apply_action(state: &mut AppState, i: usize, action: &ChangeAction, activate: Option<bool>) {
    let sub = &mut state.subscriptions[i];
    match action {
        // A new URL is a re-import: the backend no longer matches the stored meta.
        ChangeAction::ReplaceUrl { url, .. } | ChangeAction::ReplaceDomain { url, .. } => {
            sub.url = url.clone();
        }
        ChangeAction::SetFallbackUrl { url, .. } => sub.fallback_url = Some(url.clone()),
        // happ-sub applies the consented value; the decision is the consent.
        ChangeAction::SetUserAgent { .. } => {}
        ChangeAction::LockUserAgent { on } => {
            // Happ clears the user's own User-Agent when the provider locks it.
            if *on {
                sub.user_agent.clear();
            }
        }
        ChangeAction::SetInsecure { on } => {
            sub.allow_insecure = *on;
            sub.insecure_by_provider = *on;
        }
        ChangeAction::SetRoutingEnabled { on } => {
            let id = sub.id.clone();
            for r in state
                .routes
                .iter_mut()
                .filter(|r| r.source_sub_id.as_deref() == Some(id.as_str()))
            {
                r.enabled = *on;
            }
        }
        ChangeAction::ImportRouting {
            routing,
            activate: offered,
        } => {
            let target = RoutingTarget {
                ids: provider_ids(&sub.id),
                group: Some(
                    sub.group_id
                        .clone()
                        .unwrap_or_else(|| BASE_GROUP_ID.to_owned()),
                ),
                source_sub_id: Some(sub.id.clone()),
            };
            import_routing(state, target, routing, activate.unwrap_or(*offered));
        }
        ChangeAction::TunnelSetting { setting } => {
            let s = &mut state.settings;
            match setting {
                TunnelSetting::Mux { on } => s.mux = *on,
                TunnelSetting::Fragment { on } => s.fragment = *on,
                TunnelSetting::Sniffing { on } => s.domain_sniffing = *on,
                TunnelSetting::FragmentPackets { value } => s.fragment_packets = value.clone(),
                TunnelSetting::FragmentLength { value } => s.fragment_length = Some(value.clone()),
                TunnelSetting::FragmentInterval { value } => {
                    s.fragment_delay = Some(value.clone());
                }
            }
        }
        ChangeAction::AllowProviderConfigs => sub.allow_provider_configs = true,
        ChangeAction::Unsupported => {}
    }
}

/// Block and route ids, the routed group (none for a route of its own) and the
/// subscription that sent the profile.
struct RoutingTarget {
    ids: (String, String),
    group: Option<String>,
    source_sub_id: Option<String>,
}

/// A pasted `happ://routing` profile as `group_id`'s route; a re-import replaces it.
pub fn import_routing_link(
    state: &mut AppState,
    group_id: &str,
    routing: &RoutingImport,
    enabled: bool,
) {
    let target = RoutingTarget {
        ids: (
            format!("link-block-{group_id}"),
            format!("link-route-{group_id}"),
        ),
        group: Some(group_id.to_owned()),
        source_sub_id: None,
    };
    import_routing(state, target, routing, enabled);
}

/// A `happ://routing` profile as a new route `route_id` that applies to nothing
/// yet, the way a shared route comes in: the user picks its profiles and groups
/// afterwards.
pub fn import_routing_route(state: &mut AppState, route_id: &str, routing: &RoutingImport) {
    let target = RoutingTarget {
        ids: (format!("{route_id}-block"), route_id.to_owned()),
        group: None,
        source_sub_id: None,
    };
    import_routing(state, target, routing, true);
}

/// One block and one route for the target, replacing an earlier import.
/// Rules run block, direct, proxy: Happ's default `BLOCK_DIRECT_PROXY` order.
fn import_routing(state: &mut AppState, target: RoutingTarget, r: &RoutingImport, enabled: bool) {
    let RoutingTarget {
        ids: (block_id, route_id),
        group,
        source_sub_id,
    } = target;
    let lists: [(&str, &str, &[String], bool); 6] = [
        ("BlockSites", "block", &r.block_sites, true),
        ("BlockIp", "block", &r.block_ip, false),
        ("DirectSites", "direct", &r.direct_sites, true),
        ("DirectIp", "direct", &r.direct_ip, false),
        ("ProxySites", "proxy", &r.proxy_sites, true),
        ("ProxyIp", "proxy", &r.proxy_ip, false),
    ];
    let rules = lists
        .into_iter()
        .filter(|(_, _, entries, _)| !entries.is_empty())
        .map(|(name, outbound, entries, sites)| RoutingRule {
            id: format!("{block_id}-{}", name.to_ascii_lowercase()),
            remarks: name.to_owned(),
            enabled: true,
            outbound_tag: outbound.to_owned(),
            domain: sites.then(|| entries.to_vec()),
            ip: (!sites).then(|| entries.to_vec()),
            port: None,
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        })
        .collect();
    let block = RuleBlock {
        id: block_id.clone(),
        name: r.name.clone(),
        rules,
        source_sub_id: source_sub_id.clone(),
    };
    match state.rule_blocks.iter_mut().find(|b| b.id == block_id) {
        Some(slot) => *slot = block,
        None => state.rule_blocks.push(block),
    }
    // Another route listing the group loses it: a group runs with one route.
    upsert_route(
        state,
        Route {
            id: route_id,
            name: r.name.clone(),
            enabled,
            profiles: Vec::new(),
            groups: group.into_iter().collect(),
            blocks: vec![RouteBlockRef {
                block_id,
                enabled: true,
            }],
            final_outbound: if r.global_proxy == Some(false) {
                "direct".into()
            } else {
                "proxy".into()
            },
            source_sub_id,
        },
    );
}

/// Drop the routes and blocks imported from `sub_id`.
pub fn remove_provider_routing(state: &mut AppState, sub_id: &str) {
    let mine = |s: &Option<String>| s.as_deref() == Some(sub_id);
    state.routes.retain(|r| !mine(&r.source_sub_id));
    let gone: Vec<String> = state
        .rule_blocks
        .iter()
        .filter(|b| mine(&b.source_sub_id))
        .map(|b| b.id.clone())
        .collect();
    state.rule_blocks.retain(|b| !mine(&b.source_sub_id));
    for r in &mut state.routes {
        r.blocks.retain(|b| !gone.contains(&b.block_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::DEFAULT_ROUTE_ID;
    use crate::state::{MetaRisk, default_app_state};

    const NOW: &str = "2026-10-13T10:00:00.000Z";
    const LATER: &str = "2026-10-13T11:00:00.000Z";

    fn meta(pairs: &[(&str, &str)]) -> MetaMap {
        let mut m = MetaMap::new();
        for (k, v) in pairs {
            m.insert(k, v);
        }
        m
    }

    fn sub() -> Subscription {
        Subscription {
            id: "s1".into(),
            remarks: "Sub".into(),
            url: "https://sub.example.org/api/s?token=1".into(),
            enabled: true,
            group_id: Some("g-s1".into()),
            ..Default::default()
        }
    }

    fn state() -> AppState {
        let mut s = default_app_state();
        s.groups.push(crate::state::Group {
            id: "g-s1".into(),
            name: "Sub".into(),
            sub_id: Some("s1".into()),
        });
        s.subscriptions = vec![sub()];
        s
    }

    fn offers(st: &AppState, m: &MetaMap, routing: &[RoutingAction]) -> Offers {
        offer_changes(st, &st.subscriptions[0], None, m, routing, NOW)
    }

    /// Offer `m` to the state's subscription and store the result on it.
    fn offer_into(st: &mut AppState, old: Option<&MetaMap>, m: &MetaMap, at: &str) -> Offers {
        let o = offer_changes(st, &st.subscriptions[0], old, m, &[], at);
        st.subscriptions[0].pending_changes = o.pending.clone();
        o
    }

    fn pending<'a>(st: &'a AppState, key: &str) -> &'a PendingChange {
        st.subscriptions[0]
            .pending_changes
            .iter()
            .find(|p| p.key == key)
            .unwrap_or_else(|| panic!("{key} not pending"))
    }

    fn answer(st: &mut AppState, key: &str, accept: bool) {
        let d = pending(st, key).digest.clone();
        resolve_changes(st, "s1", &[d], accept, None, LATER);
    }

    #[test]
    fn trust_boundary_keys_become_pending_not_applied() {
        let mut st = state();
        let m = meta(&[
            ("new-url", "https://new.example.org/s"),
            ("fallback-url", "https://backup.example.net/s"),
            ("insecure", "true"),
            ("per-app-proxy-list", "com.example"),
            ("profile-title", "T"),
        ]);
        let o = offer_into(&mut st, None, &m, NOW);
        let keys: Vec<&str> = o.pending.iter().map(|p| p.key.as_str()).collect();
        assert_eq!(
            keys,
            ["fallback-url", "insecure", "new-url", "per-app-proxy-list"]
        );
        assert!(o.pending.iter().all(|p| p.risk == MetaRisk::TrustBoundary));
        assert_eq!(
            pending(&st, "per-app-proxy-list").action,
            ChangeAction::Unsupported
        );
        assert_eq!(o.audit.len(), 4);
        assert!(o.audit.iter().all(|a| a.outcome == AuditOutcome::Offered));
        let s = &st.subscriptions[0];
        assert_eq!(s.url, sub().url);
        assert_eq!(s.fallback_url, None);
        assert!(!s.allow_insecure);
    }

    #[test]
    fn rejected_value_not_reoffered_changed_value_is() {
        let mut st = state();
        let m = meta(&[("fallback-url", "https://backup.example.net/a")]);
        offer_into(&mut st, None, &m, NOW);
        answer(&mut st, "fallback-url", false);
        assert!(st.subscriptions[0].pending_changes.is_empty());

        let again = offer_into(&mut st, Some(&m), &m, LATER);
        assert!(again.pending.is_empty() && again.audit.is_empty());

        let changed = meta(&[("fallback-url", "https://backup.example.net/b")]);
        let o = offer_into(&mut st, Some(&m), &changed, LATER);
        assert_eq!(o.pending.len(), 1);
        assert_eq!(o.pending[0].value, "https://backup.example.net/b");
    }

    #[test]
    fn a_pending_change_is_audited_once_and_keeps_its_first_sighting() {
        let mut st = state();
        let m = meta(&[("mux-enable", "1")]);
        let first = offer_into(&mut st, None, &m, NOW);
        assert_eq!(first.audit.len(), 1);
        let second = offer_into(&mut st, Some(&m), &m, LATER);
        assert!(second.audit.is_empty());
        assert_eq!(second.pending[0].seen_at, NOW);
    }

    #[test]
    fn new_url_rejects_private_and_http() {
        for bad in [
            "http://new.example.org/s",
            "https://192.168.1.10/s",
            "https://localhost/s",
            "https://[::1]/s",
            "javascript:alert(1)",
        ] {
            let o = offers(&state(), &meta(&[("new-url", bad)]), &[]);
            assert!(o.pending.is_empty(), "{bad}");
            assert_eq!(o.audit.len(), 1, "{bad}");
            assert_eq!(o.audit[0].outcome, AuditOutcome::Ignored);
        }
        // Unchanged since the last fetch: not audited again.
        let m = meta(&[("new-url", "https://10.0.0.1/s")]);
        let o = offer_changes(&state(), &sub(), Some(&m), &m, &[], NOW);
        assert!(o.audit.is_empty());
    }

    #[test]
    fn new_domain_rewrites_authority_keeps_path_query() {
        let o = offers(
            &state(),
            &meta(&[("new-domain", "mirror.example.com:8443")]),
            &[],
        );
        let ChangeAction::ReplaceDomain {
            url,
            from_host,
            to_host,
            other_domain,
        } = &o.pending[0].action
        else {
            panic!("{:?}", o.pending[0].action);
        };
        assert_eq!(url, "https://mirror.example.com:8443/api/s?token=1");
        assert_eq!(
            (from_host.as_str(), to_host.as_str()),
            ("sub.example.org", "mirror.example.com")
        );
        assert!(*other_domain);

        let o = offers(
            &state(),
            &meta(&[("new-domain", "https://cdn.example.org/ignored")]),
            &[],
        );
        let ChangeAction::ReplaceDomain {
            url, other_domain, ..
        } = &o.pending[0].action
        else {
            panic!();
        };
        assert_eq!(url, "https://cdn.example.org/api/s?token=1");
        assert!(!*other_domain, "same registrable tail");

        for bad in ["user@evil.example", "a b", "10.0.0.1"] {
            let o = offers(&state(), &meta(&[("new-domain", bad)]), &[]);
            assert!(o.pending.is_empty(), "{bad}");
        }
        assert!(
            offers(&state(), &meta(&[("new-domain", "sub.example.org")]), &[])
                .pending
                .is_empty()
        );
    }

    #[test]
    fn accept_new_url_changes_url_only() {
        let mut st = state();
        let before = st.clone();
        offer_into(
            &mut st,
            None,
            &meta(&[("new-url", "https://new.example.net/s")]),
            NOW,
        );
        answer(&mut st, "new-url", true);
        let s = &st.subscriptions[0];
        assert_eq!(s.url, "https://new.example.net/s");
        assert!(s.pending_changes.is_empty());
        assert!(s.decisions[0].accepted);
        assert_eq!(s.audit[0].outcome, AuditOutcome::Accepted);
        let mut rest = st.clone();
        rest.subscriptions = before.subscriptions.clone();
        assert_eq!(rest, before, "nothing else changed");
        // The new URL is the subscription's own: nothing to offer any more.
        let o = offer_changes(
            &st,
            &st.subscriptions[0],
            None,
            &meta(&[("new-url", "https://new.example.net/s")]),
            &[],
            LATER,
        );
        assert!(o.pending.is_empty());
    }

    #[test]
    fn accept_fallback_and_insecure() {
        let mut st = state();
        offer_into(
            &mut st,
            None,
            &meta(&[
                ("fallback-url", "https://b.example.net/s"),
                ("insecure", "1"),
            ]),
            NOW,
        );
        answer(&mut st, "fallback-url", true);
        answer(&mut st, "insecure", true);
        let s = &st.subscriptions[0];
        assert_eq!(s.fallback_url.as_deref(), Some("https://b.example.net/s"));
        assert!(s.allow_insecure && s.insecure_by_provider);
    }

    fn routing_profile() -> RoutingProfile {
        RoutingProfile {
            name: "EXAMPLE-ROUTING".into(),
            direct_sites: vec![
                "geosite:ru".into(),
                "domain:example.ru".into(),
                "bad entry".into(),
            ],
            direct_ip: vec!["geoip:ru".into(), "geoip:ru".into()],
            block_sites: vec!["geosite:category-ads-all".into()],
            proxy_ip: vec!["1.2.3.0/24".into()],
            global_proxy: Some(false),
            remote_dns_type: Some("DoH".into()),
            geoipurl: Some("https://example.org/geoip.dat".into()),
            domain_strategy: Some("IPIfNonMatch".into()),
            ..Default::default()
        }
    }

    #[test]
    fn routing_import_maps_lists_and_lists_ignored_fields() {
        let r = routing_import(&routing_profile());
        assert_eq!(r.direct_sites, ["geosite:ru", "domain:example.ru"]);
        assert_eq!(r.direct_ip, ["geoip:ru"]);
        assert_eq!(
            r.ignored_fields,
            ["DomainStrategy", "RemoteDnsType", "Geoipurl"]
        );
    }

    #[test]
    fn routing_import_creates_block_and_route_for_group() {
        let mut st = state();
        let o = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::OnAdd(routing_profile())],
        );
        assert_eq!(o.pending.len(), 1);
        assert_eq!(o.pending[0].value, "EXAMPLE-ROUTING");
        assert!(st.routes.len() == 1, "nothing imported before the answer");
        st.subscriptions[0].pending_changes = o.pending;
        answer(&mut st, "routing", true);

        let block = st
            .rule_blocks
            .iter()
            .find(|b| b.source_sub_id.is_some())
            .unwrap();
        let order: Vec<&str> = block
            .rules
            .iter()
            .map(|r| r.outbound_tag.as_str())
            .collect();
        assert_eq!(order, ["block", "direct", "direct", "proxy"]);
        assert_eq!(
            block.rules[0].domain.as_deref(),
            Some(&["geosite:category-ads-all".to_owned()][..])
        );
        assert_eq!(
            block.rules[2].ip.as_deref(),
            Some(&["geoip:ru".to_owned()][..])
        );
        let route = st
            .routes
            .iter()
            .find(|r| r.source_sub_id.is_some())
            .unwrap();
        assert_eq!(route.groups, ["g-s1"]);
        assert_eq!(route.final_outbound, "direct", "GlobalProxy false");
        assert!(route.enabled);
        assert_eq!(route.blocks[0].block_id, block.id);
    }

    #[test]
    fn routing_import_respects_the_turn_on_choice() {
        let mut st = state();
        let o = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::Add(routing_profile())],
        );
        st.subscriptions[0].pending_changes = o.pending;
        let d = pending(&st, "routing").digest.clone();
        resolve_changes(&mut st, "s1", &[d], true, Some(false), LATER);
        assert!(
            !st.routes
                .iter()
                .find(|r| r.source_sub_id.is_some())
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn routing_link_becomes_the_group_route_and_a_reimport_replaces_it() {
        let mut st = state();
        let mut routing = routing_import(&routing_profile());
        import_routing_link(&mut st, "g-main", &routing, false);
        routing.name = "Second".into();
        import_routing_link(&mut st, "g-main", &routing, true);

        let route = st
            .routes
            .iter()
            .find(|r| r.id == "link-route-g-main")
            .unwrap();
        assert_eq!(route.groups, ["g-main"]);
        assert_eq!(route.name, "Second");
        assert!(route.enabled);
        assert_eq!(route.source_sub_id, None);
        assert_eq!(st.routes.len(), 2, "the default route and one import");
        let block = st
            .rule_blocks
            .iter()
            .find(|b| b.id == "link-block-g-main")
            .unwrap();
        assert_eq!(block.source_sub_id, None);
        assert_eq!(block.rules.len(), 4);
    }

    #[test]
    fn routing_route_stands_alone_and_leaves_group_routes_alone() {
        let mut st = state();
        let routing = routing_import(&routing_profile());
        import_routing_link(&mut st, "g-main", &routing, true);
        import_routing_route(&mut st, "r1", &routing);
        import_routing_route(&mut st, "r2", &routing);

        let route = st.routes.iter().find(|r| r.id == "r1").unwrap();
        assert!(route.groups.is_empty() && route.profiles.is_empty());
        assert!(route.enabled);
        assert_eq!(route.source_sub_id, None);
        assert_eq!(route.blocks[0].block_id, "r1-block");
        let block = st.rule_blocks.iter().find(|b| b.id == "r1-block").unwrap();
        assert_eq!(block.rules.len(), 4);
        assert_eq!(
            st.routes.len(),
            4,
            "the default, the group route and two imports"
        );
        let group_route = st
            .routes
            .iter()
            .find(|r| r.id == "link-route-g-main")
            .unwrap();
        assert_eq!(group_route.groups, ["g-main"]);
    }

    #[test]
    fn encrypted_link_hides_its_host_from_url_changes() {
        let mut st = state();
        st.subscriptions[0].url = "happ://crypt5/abcdef".into();
        let o = offers(&st, &meta(&[("new-domain", "mirror.example.com")]), &[]);
        assert!(o.pending.is_empty());
        assert_eq!(o.audit[0].outcome, AuditOutcome::Ignored);

        let o = offers(&st, &meta(&[("new-url", "https://new.example.com/s")]), &[]);
        let ChangeAction::ReplaceUrl { from_host, .. } = &o.pending[0].action else {
            panic!("{:?}", o.pending[0].action);
        };
        assert_eq!(from_host, "");
    }

    #[test]
    fn routing_import_moves_group_from_other_route() {
        let mut st = state();
        st.routes.push(Route {
            id: "mine".into(),
            name: "Mine".into(),
            groups: vec!["g-s1".into(), "g-main".into()],
            ..crate::route::default_route()
        });
        st.subscriptions[0].pending_changes = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::OnAdd(routing_profile())],
        )
        .pending;
        answer(&mut st, "routing", true);
        let mine = st.routes.iter().find(|r| r.id == "mine").unwrap();
        assert_eq!(mine.groups, ["g-main"]);
    }

    #[test]
    fn routing_offer_stays_until_answered_and_reimport_replaces() {
        let mut st = state();
        st.subscriptions[0].pending_changes = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::OnAdd(routing_profile())],
        )
        .pending;
        let kept = offers(&st, &MetaMap::new(), &[]);
        assert_eq!(kept.pending.len(), 1);
        assert!(kept.audit.is_empty());
        answer(&mut st, "routing", true);

        let mut other = routing_profile();
        other.name = "V2".into();
        st.subscriptions[0].pending_changes =
            offers(&st, &MetaMap::new(), &[RoutingAction::OnAdd(other)]).pending;
        answer(&mut st, "routing", true);
        let provider: Vec<&Route> = st
            .routes
            .iter()
            .filter(|r| r.source_sub_id.is_some())
            .collect();
        assert_eq!(provider.len(), 1);
        assert_eq!(provider[0].name, "V2");
        assert_eq!(
            st.rule_blocks
                .iter()
                .filter(|b| b.source_sub_id.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn routing_off_disables_only_provider_route() {
        let mut st = state();
        st.subscriptions[0].pending_changes = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::OnAdd(routing_profile())],
        )
        .pending;
        answer(&mut st, "routing", true);
        st.routes.push(Route {
            id: "user".into(),
            name: "User".into(),
            groups: vec!["g-main".into()],
            ..crate::route::default_route()
        });
        let mut foreign = provider_route(&st, "s1").unwrap().clone();
        foreign.id = "sub-route-s2".into();
        foreign.groups = vec![];
        foreign.source_sub_id = Some("s2".into());
        st.routes.push(foreign);

        assert!(routing_off(&mut st, "s1"));
        let enabled = |id: &str| st.routes.iter().find(|r| r.id == id).unwrap().enabled;
        assert!(!enabled("sub-route-s1"));
        assert!(enabled("user") && enabled("sub-route-s2") && enabled(DEFAULT_ROUTE_ID));
        assert!(!routing_off(&mut st, "s1"), "already off");
    }

    #[test]
    fn routing_enable_toggles_only_an_existing_provider_route() {
        let mut st = state();
        assert!(
            offers(&st, &meta(&[("routing-enable", "0")]), &[])
                .pending
                .is_empty()
        );
        st.subscriptions[0].pending_changes = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::OnAdd(routing_profile())],
        )
        .pending;
        answer(&mut st, "routing", true);
        offer_into(&mut st, None, &meta(&[("routing-enable", "false")]), NOW);
        answer(&mut st, "routing-enable", true);
        assert!(!provider_route(&st, "s1").unwrap().enabled);
    }

    #[test]
    fn remove_sub_removes_provider_routes() {
        let mut st = state();
        st.subscriptions[0].pending_changes = offers(
            &st,
            &MetaMap::new(),
            &[RoutingAction::OnAdd(routing_profile())],
        )
        .pending;
        answer(&mut st, "routing", true);
        crate::mutate::apply_mutation(
            &mut st,
            &crate::mutate::MutationIntent::RemoveSub {
                id: "s1".into(),
                delete_group: false,
            },
        );
        assert!(st.routes.iter().all(|r| r.source_sub_id.is_none()));
        assert!(st.rule_blocks.iter().all(|b| b.source_sub_id.is_none()));
        assert_eq!(st.routes.len(), 1);
    }

    #[test]
    fn tunnel_accept_writes_global_setting() {
        let mut st = state();
        let m = meta(&[
            ("mux-enable", "true"),
            ("fragmentation-enable", "1"),
            ("fragmentation-packets", "1-3"),
            ("fragmentation-length", "100-200"),
            ("fragmentation-interval", "10-20"),
            ("sniffing-enable", "true"),
            ("noises-enable", "true"),
            ("fragmentation-maxsplit", "4"),
        ]);
        let o = offer_into(&mut st, None, &m, NOW);
        // Sniffing is on by default: nothing to change.
        assert!(!o.pending.iter().any(|p| p.key == "sniffing-enable"));
        assert!(
            o.pending
                .iter()
                .all(|p| p.risk == MetaRisk::TunnelBehaviour)
        );
        assert_eq!(
            pending(&st, "noises-enable").action,
            ChangeAction::Unsupported
        );
        assert_eq!(
            pending(&st, "mux-enable").previous.as_deref(),
            Some("false")
        );
        let digests: Vec<String> = st.subscriptions[0]
            .pending_changes
            .iter()
            .map(|p| p.digest.clone())
            .collect();
        resolve_changes(&mut st, "s1", &digests, true, None, LATER);
        let s = &st.settings;
        assert!(s.mux && s.fragment);
        assert_eq!(s.fragment_packets, "1-3");
        assert_eq!(s.fragment_length.as_deref(), Some("100-200"));
        assert_eq!(s.fragment_delay.as_deref(), Some("10-20"));
        let sub = &st.subscriptions[0];
        assert!(sub.pending_changes.is_empty());
        // The unsupported keys were dismissed, not accepted.
        let unsupported: Vec<bool> = sub
            .decisions
            .iter()
            .filter(|d| d.key == "noises-enable" || d.key == "fragmentation-maxsplit")
            .map(|d| d.accepted)
            .collect();
        assert_eq!(unsupported, [false, false]);
    }

    #[test]
    fn invalid_tunnel_value_is_ignored() {
        let o = offers(
            &state(),
            &meta(&[("fragmentation-length", "10;rm -rf")]),
            &[],
        );
        assert!(o.pending.is_empty());
        assert_eq!(o.audit[0].outcome, AuditOutcome::Ignored);
    }

    #[test]
    fn audit_capped_at_50() {
        let mut s = sub();
        for i in 0..60 {
            push_audit(
                &mut s,
                vec![audit(&format!("t{i}"), "k", AuditOutcome::Offered, "v")],
            );
        }
        assert_eq!(s.audit.len(), AUDIT_MAX);
        assert_eq!(s.audit[0].at, "t59", "newest first");
        push_audit(
            &mut s,
            vec![
                audit("a", "k", AuditOutcome::Offered, "v"),
                audit("b", "k", AuditOutcome::Offered, "v"),
            ],
        );
        assert_eq!((s.audit[0].at.as_str(), s.audit[1].at.as_str()), ("b", "a"));
    }

    #[test]
    fn user_agent_consent_follows_the_accepted_value() {
        let mut st = state();
        st.subscriptions[0].user_agent = "Mine/1".into();
        let m = meta(&[
            ("change-user-agent", "Provider/1"),
            ("manual-block-user-agent", "true"),
        ]);
        offer_into(&mut st, None, &m, NOW);
        assert!(consented_keys(&st.subscriptions[0], Some(&m)).is_empty());
        answer(&mut st, "change-user-agent", true);
        answer(&mut st, "manual-block-user-agent", true);
        let s = &st.subscriptions[0];
        assert_eq!(consented_keys(s, Some(&m)), CONSENT_KEYS);
        assert_eq!(s.user_agent, "", "the lock clears the user's own");
        let changed = meta(&[("change-user-agent", "Provider/2")]);
        assert!(consented_keys(s, Some(&changed)).is_empty());
    }

    #[test]
    fn consent_then_import() {
        let body = serde_json::json!({ "outbounds": [
            { "protocol": "trojan",
              "settings": { "servers": [{ "address": "a.example", "port": 443, "password": "pw" }] } },
        ]})
        .to_string();
        let fetch = |st: &AppState| {
            let sub = &st.subscriptions[0];
            crate::sub_ingest::ingest(&crate::sub_ingest::IngestInput {
                url: &sub.url,
                headers: &[],
                body: body.as_bytes(),
                stored: None,
                merge: happ_sub::MergeMode::Full,
                allow_provider_configs: sub.allow_provider_configs,
                title: &sub.remarks,
            })
        };
        let mut st = state();
        assert!(fetch(&st).is_err());
        assert!(offer_provider_configs(&mut st.subscriptions[0], NOW));
        // Asked once: a second JSON response adds nothing.
        assert!(!offer_provider_configs(&mut st.subscriptions[0], LATER));
        let p = pending(&st, PROVIDER_CONFIGS_KEY);
        assert_eq!(p.risk, MetaRisk::TrustBoundary);
        assert_eq!(p.action, ChangeAction::AllowProviderConfigs);
        assert_eq!(st.subscriptions[0].audit[0].outcome, AuditOutcome::Offered);

        answer(&mut st, PROVIDER_CONFIGS_KEY, true);
        assert!(st.subscriptions[0].allow_provider_configs);
        assert_eq!(fetch(&st).unwrap().profiles.len(), 1);
    }

    #[test]
    fn rejected_provider_configs_are_not_asked_again() {
        let mut st = state();
        offer_provider_configs(&mut st.subscriptions[0], NOW);
        answer(&mut st, PROVIDER_CONFIGS_KEY, false);
        let s = &mut st.subscriptions[0];
        assert!(!s.allow_provider_configs);
        assert!(!offer_provider_configs(s, LATER));
        assert!(s.pending_changes.is_empty());
    }

    fn provider_config(id: &str, host: &str, group: &str) -> Profile {
        let raw = serde_json::json!({ "outbounds": [{ "protocol": "trojan",
            "settings": { "servers": [{ "address": host, "port": 443, "password": "pw" }] } }] });
        serde_json::from_value(serde_json::json!({
            "protocol": "custom",
            "meta": { "id": id, "remarks": id, "groupId": group, "subId": "s1" },
            "raw": raw.to_string(),
            "origin": "provider",
        }))
        .unwrap()
    }

    fn withdrawn(profiles: Vec<Profile>, active: &str) -> AppState {
        let mut st = state();
        st.subscriptions[0].allow_provider_configs = true;
        st.profiles = profiles;
        st.active_id = Some(active.into());
        withdraw_provider_configs(&mut st, "s1");
        assert!(!st.subscriptions[0].allow_provider_configs);
        st
    }

    fn ids(st: &AppState) -> Vec<&str> {
        st.profiles.iter().map(|p| p.meta().id.as_str()).collect()
    }

    #[test]
    fn withdrawing_provider_configs_removes_only_the_imported_ones() {
        let mut typed =
            crate::share::parse_share_link("trojan://pw@t.example:443#T", None).unwrap();
        typed.meta_mut().id = "typed".into();
        typed.meta_mut().sub_id = Some("s1".into());
        typed.meta_mut().group_id = "g-s1".into();
        let mut own = provider_config("own", "o.example", "g-s1");
        if let Profile::Custom(c) = &mut own {
            c.origin = CustomOrigin::User;
            c.meta.sub_id = None;
        }
        let mut other_sub = provider_config("other", "x.example", "g-s1");
        other_sub.meta_mut().sub_id = Some("s2".into());
        let st = withdrawn(
            vec![
                provider_config("a", "a.example", "g-s1"),
                provider_config("moved", "m.example", BASE_GROUP_ID),
                typed,
                own,
                other_sub,
            ],
            "typed",
        );
        assert_eq!(ids(&st), ["moved", "typed", "own", "other"]);
        assert_eq!(st.active_id.as_deref(), Some("typed"));
    }

    #[test]
    fn withdrawing_the_active_config_moves_the_selection_as_a_refresh_would() {
        let gone = withdrawn(vec![provider_config("a", "a.example", "g-s1")], "a");
        assert!(gone.profiles.is_empty());
        assert_eq!(gone.active_id, None);

        // The copy the user moved out of the group is the same server.
        let st = withdrawn(
            vec![
                provider_config("a", "a.example", "g-s1"),
                provider_config("moved", "a.example", BASE_GROUP_ID),
            ],
            "a",
        );
        assert_eq!(ids(&st), ["moved"]);
        assert_eq!(st.active_id.as_deref(), Some("moved"));
    }

    #[test]
    fn risk_mirror_is_exhaustive() {
        for (_, class) in happ_sub::meta::KNOWN_KEYS {
            let _: MetaRisk = (*class).into();
        }
        assert_eq!(
            MetaRisk::from(RiskClass::TrustBoundary),
            MetaRisk::TrustBoundary
        );
        assert_eq!(MetaRisk::from(RiskClass::Ignored), MetaRisk::Ignored);
    }

    #[test]
    fn live_fixture_offers_one_routing_import() {
        let (headers, body) = crate::sub_ingest::tests::http_fixture("01-happ-full");
        let ing = crate::sub_ingest::ingest(&crate::sub_ingest::IngestInput {
            url: "https://sub.example.org/s",
            headers: &headers,
            body: &body,
            stored: None,
            merge: happ_sub::MergeMode::Full,
            allow_provider_configs: false,
            title: "",
        })
        .unwrap();
        let st = state();
        let o = offer_changes(
            &st,
            &st.subscriptions[0],
            None,
            &ing.meta,
            &ing.routing,
            NOW,
        );
        assert_eq!(o.pending.len(), 1);
        let ChangeAction::ImportRouting { routing, activate } = &o.pending[0].action else {
            panic!("{:?}", o.pending[0].action);
        };
        assert_eq!(routing.name, "EXAMPLE-ROUTING");
        assert!(*activate);
    }
}
