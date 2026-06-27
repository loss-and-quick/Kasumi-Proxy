//! Pure subscription-apply logic, shared by the UI (manual update) and the
//! daemon (headless auto-update). No I/O — a function of its inputs, so both
//! consumers apply identically.

use std::collections::{HashMap, HashSet};

use fancy_regex::Regex;

use crate::profile::Profile;
use crate::state::Subscription;

/// A compiled profile filter (a leading `(?i)` selects case-insensitive).
pub struct ProfileFilter(Option<Regex>);

impl ProfileFilter {
    /// True when no regex is in force — either the filter was empty or it failed to
    /// compile. Paired with a non-empty source string, this flags a broken filter.
    pub fn is_unfiltered(&self) -> bool {
        self.0.is_none()
    }
}

/// Parse a subscription's profile filter (`None`/invalid → match-all).
///
/// Uses `fancy_regex` (backtracking) rather than the `regex` crate so that
/// lookahead/backreference filters compile and match as written. Real
/// subscriptions commonly use a negative lookahead to drop expiry/notice
/// pseudo-nodes (e.g. `(?i)^(?!.*(expire|官网)).*`); under the linear `regex`
/// engine that pattern fails to compile and silently matches everything.
pub fn profile_filter_regex(filter: &str) -> ProfileFilter {
    let trimmed = filter.trim();
    if trimmed.is_empty() {
        return ProfileFilter(None);
    }
    // A leading `(?i)` selects case-insensitive for the whole pattern; strip and
    // re-prepend it as an inline flag so it applies even after the prefix split.
    let (source, ci) = match trimmed.strip_prefix("(?i)") {
        Some(rest) => (rest, true),
        None => (trimmed, false),
    };
    let pattern = if ci {
        format!("(?i){source}")
    } else {
        source.to_string()
    };
    ProfileFilter(Regex::new(&pattern).ok())
}

/// Lower-cased searchable haystack used by name/host filters.
fn profile_search_text(p: &Profile) -> String {
    let mut parts: Vec<String> = vec![p.meta().remarks.clone(), wire(&p.protocol())];
    if p.endpoint().is_some() {
        parts.push(p.address().to_string());
        parts.push(p.port().map(|x| x.to_string()).unwrap_or_default());
    }
    if let Some(t) = p.transport() {
        parts.push(wire(&t.network()));
        parts.push(t.host().to_string());
        parts.push(t.path().to_string());
    }
    if let Some(tls) = p.tls() {
        parts.push(wire(&tls.security));
        parts.push(tls.sni.clone());
    }
    parts
        .into_iter()
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub fn profile_matches_filter(profile: &Profile, filter: &ProfileFilter) -> bool {
    let Some(re) = &filter.0 else {
        return true;
    };
    let haystack = format!(
        "{} {} {}",
        profile_search_text(profile),
        profile.uuid().unwrap_or(""),
        profile.password().unwrap_or(""),
    );
    re.is_match(&haystack).unwrap_or(false)
}

/// Same endpoint identity: protocol + address + port + name. Lets the active
/// selection survive a refresh that re-creates ids.
pub fn same_profile_identity(a: &Profile, b: &Profile) -> bool {
    a.protocol() == b.protocol()
        && a.address() == b.address()
        && a.port() == b.port()
        && a.meta().remarks == b.meta().remarks
}

fn profile_dedup_key(p: &Profile) -> String {
    let secret = p.uuid().or_else(|| p.password()).unwrap_or("");
    let port = p
        .port()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "null".into());
    format!(
        "{}|{}|{}|{}",
        wire(&p.protocol()),
        p.address(),
        port,
        secret
    )
}

/// Drop duplicate endpoints, keeping the first (or the active one).
pub fn deduplicate_profiles(
    profiles: &[Profile],
    active_id: Option<&str>,
) -> (Vec<Profile>, usize) {
    let mut seen: HashMap<String, String> = HashMap::new(); // key -> kept profile id
    for p in profiles {
        let key = profile_dedup_key(p);
        let is_active = active_id == Some(p.meta().id.as_str());
        if !seen.contains_key(&key) || is_active {
            seen.insert(key, p.meta().id.clone());
        }
    }
    let kept: Vec<Profile> = profiles
        .iter()
        .filter(|p| {
            seen.get(&profile_dedup_key(p)).map(String::as_str) == Some(p.meta().id.as_str())
        })
        .cloned()
        .collect();
    let removed = profiles.len() - kept.len();
    (kept, removed)
}

/// Dedup only within `group_id` (or everything when it's `None`/`"all"`), keeping
/// profiles outside the scope untouched. Returns the surviving profiles and the ids
/// that were dropped.
pub fn deduplicate_profiles_scoped(
    profiles: &[Profile],
    active_id: Option<&str>,
    group_id: Option<&str>,
) -> (Vec<Profile>, HashSet<String>) {
    let affected: Vec<Profile> = match group_id {
        None | Some("all") => profiles.to_vec(),
        Some(g) => profiles
            .iter()
            .filter(|p| p.meta().group_id == g)
            .cloned()
            .collect(),
    };
    let (kept_affected, _) = deduplicate_profiles(&affected, active_id);
    let kept_ids: HashSet<&str> = kept_affected.iter().map(|p| p.meta().id.as_str()).collect();
    let removed_ids: HashSet<String> = affected
        .iter()
        .filter(|p| !kept_ids.contains(p.meta().id.as_str()))
        .map(|p| p.meta().id.clone())
        .collect();
    let kept = profiles
        .iter()
        .filter(|p| !removed_ids.contains(&p.meta().id))
        .cloned()
        .collect();
    (kept, removed_ids)
}

/// Remove a subscription's profiles, preserving any manually moved to another group.
pub fn remove_profiles_by_sub_id(
    profiles: &[Profile],
    sub_id: &str,
    sub_group_id: Option<&str>,
) -> Vec<Profile> {
    profiles
        .iter()
        .filter(|p| {
            let m = p.meta();
            if m.sub_id.as_deref() != Some(sub_id) {
                return true;
            }
            if let Some(g) = sub_group_id {
                if m.group_id != g {
                    return true;
                }
            }
            false
        })
        .cloned()
        .collect()
}

/// Move a subscription's profiles from `old_group` to `new_group` in place,
/// returning how many moved. Profiles manually dragged to a *third* group are
/// left untouched — only the ones still in the subscription's previous target
/// group follow it to the new one. Pure: no I/O.
pub fn migrate_profiles_to_new_group(
    profiles: &mut [Profile],
    sub_id: &str,
    old_group: &str,
    new_group: &str,
) -> usize {
    let mut moved = 0;
    for p in profiles.iter_mut() {
        if p.meta().sub_id.as_deref() == Some(sub_id) && p.meta().group_id == old_group {
            p.meta_mut().group_id = new_group.to_string();
            moved += 1;
        }
    }
    moved
}

/// Filter a freshly fetched batch and stamp each with the subscription's id/group.
pub fn map_fetched_subscription_profiles(
    fresh_raw: &[Profile],
    sub: &Subscription,
    filter: &ProfileFilter,
) -> Vec<Profile> {
    fresh_raw
        .iter()
        .filter(|p| profile_matches_filter(p, filter))
        .cloned()
        .map(|mut p| {
            let m = p.meta_mut();
            m.sub_id = Some(sub.id.clone());
            if let Some(g) = &sub.group_id {
                m.group_id = g.clone();
            }
            p
        })
        .collect()
}

/// Re-resolve the active id after a subscription refresh (exact identity, else
/// same-name fallback so the selection follows an endpoint change).
pub fn next_active_id_after_subscription_update(
    profiles: &[Profile],
    active_id: Option<&str>,
    sub_id: &str,
    fresh_mapped: &[Profile],
) -> Option<String> {
    let active = profiles
        .iter()
        .find(|p| Some(p.meta().id.as_str()) == active_id);
    let Some(active) = active else {
        return active_id.map(str::to_string);
    };
    if active.meta().sub_id.as_deref() != Some(sub_id) {
        return active_id.map(str::to_string);
    }
    if let Some(exact) = fresh_mapped
        .iter()
        .find(|p| same_profile_identity(p, active))
    {
        return Some(exact.meta().id.clone());
    }
    fresh_mapped
        .iter()
        .find(|p| p.protocol() == active.protocol() && p.meta().remarks == active.meta().remarks)
        .map(|p| p.meta().id.clone())
}

pub struct SubApplyResult {
    pub profiles: Vec<Profile>,
    pub subscriptions: Vec<Subscription>,
    pub active_id: Option<String>,
    /// The pre-update active profile belonged to this subscription.
    pub active_affected: bool,
}

/// Apply one fetched-and-mapped subscription body to the current state.
///
/// This is the *fetch* path's profile reconciliation (read-modify-write under the
/// lifecycle lock). The *save* path has its own counterpart — the `UpsertSub` arm of
/// [`crate::mutate::apply_mutation`], which keeps a sub's profiles with its group when
/// a plain edit (no fetch) changes `group_id` (via [`migrate_profiles_to_new_group`]).
/// Two mechanisms by design: a save never goes through here, and a fetch never goes
/// through `apply_mutation`.
pub fn apply_subscription_profiles(
    profiles: &[Profile],
    subscriptions: &[Subscription],
    active_id: Option<&str>,
    sub: &Subscription,
    fresh_mapped: &[Profile],
    fetched_at: &str,
) -> SubApplyResult {
    let active_affected = profiles
        .iter()
        .find(|p| Some(p.meta().id.as_str()) == active_id)
        .map(|p| p.meta().sub_id.as_deref() == Some(sub.id.as_str()))
        .unwrap_or(false);

    let mut new_profiles = remove_profiles_by_sub_id(profiles, &sub.id, sub.group_id.as_deref());
    new_profiles.extend(fresh_mapped.iter().cloned());

    let new_subs = subscriptions
        .iter()
        .map(|x| {
            if x.id == sub.id {
                let mut x = x.clone();
                x.last_updated = fetched_at.to_string();
                x.count = fresh_mapped.len() as i64;
                x.last_error = None;
                x
            } else {
                x.clone()
            }
        })
        .collect();

    SubApplyResult {
        profiles: new_profiles,
        subscriptions: new_subs,
        active_id: next_active_id_after_subscription_update(
            profiles,
            active_id,
            &sub.id,
            fresh_mapped,
        ),
        active_affected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::parse_share_link;

    fn p(uri: &str) -> Profile {
        parse_share_link(uri, None).unwrap()
    }

    #[test]
    fn filter_case_insensitive_and_haystack() {
        let prof = p("vless://11111111-1111-1111-1111-111111111111@de.ex:443?type=tcp#DE Node");
        assert!(profile_matches_filter(
            &prof,
            &profile_filter_regex("(?i)de node")
        ));
        assert!(profile_matches_filter(
            &prof,
            &profile_filter_regex("de\\.ex")
        ));
        assert!(!profile_matches_filter(
            &prof,
            &profile_filter_regex("^NL$")
        ));
        // empty / invalid → match all
        assert!(profile_matches_filter(&prof, &profile_filter_regex("")));
        assert!(profile_matches_filter(&prof, &profile_filter_regex("(")));
    }

    #[test]
    fn filter_supports_js_lookahead() {
        // A negative-lookahead exclude filter (valid JS RegExp) must compile and
        // actually filter — the linear `regex` engine would reject it and degrade
        // to match-all, importing the very nodes the user meant to drop.
        let keep = p("vless://11111111-1111-1111-1111-111111111111@de.ex:443?type=tcp#DE Premium");
        let drop =
            p("vless://11111111-1111-1111-1111-111111111111@x.ex:443?type=tcp#Expire 2026-01-01");
        let filter = profile_filter_regex("(?i)^(?!.*expire).*");
        assert!(!filter.is_unfiltered(), "lookahead filter must compile");
        assert!(profile_matches_filter(&keep, &filter));
        assert!(!profile_matches_filter(&drop, &filter));
    }

    #[test]
    fn dedup_keeps_first_or_active() {
        let mut a = p("trojan://pw@ex.com:443#A");
        let mut b = p("trojan://pw@ex.com:443#B"); // same endpoint+secret → dup of a
        let c = p("trojan://pw@other.com:443#C");
        a.meta_mut().id = "a".into();
        b.meta_mut().id = "b".into();
        let (kept, removed) = deduplicate_profiles(&[a.clone(), b.clone(), c.clone()], None);
        assert_eq!(removed, 1);
        let kept_ids: Vec<String> = kept.iter().map(|x| x.meta().id.clone()).collect();
        assert_eq!(kept_ids, vec!["a".to_string(), c.meta().id.clone()]);
        // active dup wins
        let (kept2, _) = deduplicate_profiles(&[a, b], Some("b"));
        assert_eq!(kept2[0].meta().id, "b");
    }

    #[test]
    fn dedup_scoped_leaves_other_groups_untouched() {
        let mut a = p("trojan://pw@ex.com:443#A");
        let mut b = p("trojan://pw@ex.com:443#B"); // dup of a in group g1
        let mut c = p("trojan://pw@ex.com:443#C"); // same endpoint but other group
        a.meta_mut().id = "a".into();
        a.meta_mut().group_id = "g1".into();
        b.meta_mut().id = "b".into();
        b.meta_mut().group_id = "g1".into();
        c.meta_mut().id = "c".into();
        c.meta_mut().group_id = "g2".into();

        // Scope g1: b dropped, c (other group) kept even though it's a dup endpoint.
        let (kept, removed) =
            deduplicate_profiles_scoped(&[a.clone(), b.clone(), c.clone()], None, Some("g1"));
        let ids: Vec<String> = kept.iter().map(|x| x.meta().id.clone()).collect();
        assert_eq!(ids, vec!["a".to_string(), "c".to_string()]);
        assert_eq!(removed, HashSet::from(["b".to_string()]));

        // No scope → dedup across everything (only first endpoint survives).
        let (kept_all, _) = deduplicate_profiles_scoped(&[a, b, c], None, None);
        assert_eq!(kept_all.len(), 1);
    }

    #[test]
    fn apply_replaces_sub_profiles_and_follows_active() {
        let mut old = p("vless://u@ex.com:443?type=tcp#Server");
        old.meta_mut().id = "old".into();
        old.meta_mut().sub_id = Some("s1".into());
        let sub = Subscription {
            id: "s1".into(),
            remarks: "Sub".into(),
            url: "u".into(),
            enabled: true,
            group_id: Some("g-main".into()),
            auto_update: false,
            interval: 60,
            allow_insecure: false,
            user_agent: String::new(),
            filter: String::new(),
            update_mode: crate::contract::FetchMode::Auto,
            last_updated: String::new(),
            count: 1,
            last_error: None,
            prev_profile: None,
            next_profile: None,
        };
        // fresh batch: same name, different port (endpoint changed)
        let fresh = vec![p("vless://u@ex.com:8443?type=tcp#Server")];
        let mapped = map_fetched_subscription_profiles(&fresh, &sub, &profile_filter_regex(""));
        assert_eq!(mapped[0].meta().sub_id.as_deref(), Some("s1"));

        let r = apply_subscription_profiles(
            &[old],
            std::slice::from_ref(&sub),
            Some("old"),
            &sub,
            &mapped,
            "2026-06-14",
        );
        assert!(r.active_affected);
        assert_eq!(r.profiles.len(), 1); // old removed, fresh added
        assert_eq!(r.active_id.as_deref(), Some(mapped[0].meta().id.as_str())); // followed by name
        assert_eq!(r.subscriptions[0].count, 1);
        assert_eq!(r.subscriptions[0].last_updated, "2026-06-14");
    }

    fn sub(id: &str, group: Option<&str>) -> Subscription {
        Subscription {
            id: id.into(),
            remarks: "Sub".into(),
            url: "u".into(),
            enabled: true,
            group_id: group.map(str::to_string),
            auto_update: false,
            interval: 60,
            allow_insecure: false,
            user_agent: String::new(),
            filter: String::new(),
            update_mode: crate::contract::FetchMode::Auto,
            last_updated: String::new(),
            count: 0,
            last_error: None,
            prev_profile: None,
            next_profile: None,
        }
    }

    #[test]
    fn same_profile_identity_keys_on_endpoint_and_name() {
        let a = p("vless://u1@e.x:443?type=tcp#Name");
        // Different credential but identical endpoint + name → same identity.
        let b = p("vless://u2@e.x:443?type=tcp#Name");
        assert!(same_profile_identity(&a, &b));
        // A different port or a different name breaks identity.
        assert!(!same_profile_identity(
            &a,
            &p("vless://u1@e.x:8443?type=tcp#Name")
        ));
        assert!(!same_profile_identity(
            &a,
            &p("vless://u1@e.x:443?type=tcp#Other")
        ));
    }

    #[test]
    fn remove_by_sub_id_preserves_moved_and_other_subs() {
        let mut in_group = p("trojan://pw@a.com:443#A");
        in_group.meta_mut().id = "in".into();
        in_group.meta_mut().sub_id = Some("s1".into());
        in_group.meta_mut().group_id = "g1".into();

        // User dragged this one out of the subscription's group; it must survive.
        let mut moved = p("trojan://pw@b.com:443#B");
        moved.meta_mut().id = "moved".into();
        moved.meta_mut().sub_id = Some("s1".into());
        moved.meta_mut().group_id = "g2".into();

        let mut other_sub = p("trojan://pw@c.com:443#C");
        other_sub.meta_mut().id = "other".into();
        other_sub.meta_mut().sub_id = Some("s2".into());
        other_sub.meta_mut().group_id = "g1".into();

        let kept = remove_profiles_by_sub_id(&[in_group, moved, other_sub], "s1", Some("g1"));
        let ids: Vec<&str> = kept.iter().map(|x| x.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["moved", "other"]);
    }

    #[test]
    fn map_fetched_filters_and_stamps_sub_and_group() {
        let fresh = vec![
            p("vless://u@e.x:443?type=tcp#Keep"),
            p("vless://u@e.x:443?type=tcp#Drop"),
        ];
        let s = sub("s1", Some("g-main"));
        // The haystack is lower-cased, so the filter source must be too.
        let mapped = map_fetched_subscription_profiles(&fresh, &s, &profile_filter_regex("keep"));
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].meta().remarks, "Keep");
        assert_eq!(mapped[0].meta().sub_id.as_deref(), Some("s1"));
        assert_eq!(mapped[0].meta().group_id, "g-main");
    }

    #[test]
    fn next_active_id_name_fallback_and_other_sub_passthrough() {
        // Active belongs to s1; the refresh moved the endpoint but kept the name,
        // so the selection follows by name.
        let mut active = p("vless://u@e.x:443?type=tcp#Server");
        active.meta_mut().id = "active".into();
        active.meta_mut().sub_id = Some("s1".into());
        let fresh = vec![p("vless://u@e.x:9443?type=tcp#Server")];
        let profiles = vec![active.clone()];
        let next =
            next_active_id_after_subscription_update(&profiles, Some("active"), "s1", &fresh);
        assert_eq!(next.as_deref(), Some(fresh[0].meta().id.as_str()));

        // When the active profile belongs to another subscription, it's untouched.
        let mut other = active.clone();
        other.meta_mut().sub_id = Some("s2".into());
        let keep = next_active_id_after_subscription_update(&[other], Some("active"), "s1", &fresh);
        assert_eq!(keep.as_deref(), Some("active"));
    }
}
