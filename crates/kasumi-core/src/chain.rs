//! Proxy chains: a profile can dial its server through another profile
//! ([`crate::mixins::Meta::via`]), which can itself dial through a third, and so
//! on. The config builders turn each link into the core's own mechanism —
//! sing-box `detour`, xray `sockopt.dialerProxy` — so the first hop in the list is
//! the only server the device connects to directly.

use crate::profile::Profile;
use crate::state::AppState;

/// The profiles `p` dials through, nearest first: `p.via`, then that profile's
/// `via`, and so on. Empty when `p` connects directly.
///
/// A missing hop, a loop, or a custom (raw JSON) hop is an error rather than a
/// silently shorter chain: dropping a link would connect straight to a server the
/// user chose to reach only through another one.
pub fn chain_hops<'a>(p: &Profile, profiles: &'a [Profile]) -> Result<Vec<&'a Profile>, String> {
    let mut hops: Vec<&Profile> = Vec::new();
    let mut seen = vec![p.meta().id.as_str()];
    let mut next = p.meta().via.as_deref();
    while let Some(id) = next {
        if seen.contains(&id) {
            return Err(format!(
                "proxy chain of \"{}\" loops back to {id}",
                p.meta().remarks
            ));
        }
        let hop = profiles.iter().find(|x| x.meta().id == id).ok_or_else(|| {
            format!(
                "proxy chain of \"{}\": profile {id} not found",
                p.meta().remarks
            )
        })?;
        if matches!(hop, Profile::Custom(_)) {
            return Err(format!(
                "proxy chain of \"{}\": custom profile \"{}\" can't be a hop",
                p.meta().remarks,
                hop.meta().remarks
            ));
        }
        seen.push(id);
        hops.push(hop);
        next = hop.meta().via.as_deref();
    }
    Ok(hops)
}

/// Ids of the profiles `p` could dial through: every profile that, set as
/// `p.via`, gives a chain [`chain_hops`] accepts — so the picker offers exactly
/// what the config builders will take. `p` may be an unsaved draft; it stands in
/// for its stored copy (same id) while the chains are walked.
pub fn chain_candidates(p: &Profile, profiles: &[Profile]) -> Vec<String> {
    let mut state: Vec<Profile> = profiles
        .iter()
        .filter(|x| x.meta().id != p.meta().id)
        .cloned()
        .collect();
    let mut draft = p.clone();
    state.push(draft.clone());
    let draft_idx = state.len() - 1;
    profiles
        .iter()
        .map(|c| c.meta().id.clone())
        .filter(|id| {
            draft.meta_mut().via = Some(id.clone());
            state[draft_idx] = draft.clone();
            chain_hops(&draft, &state).is_ok()
        })
        .collect()
}

/// Null every `via` that no longer points at another existing profile (the hop was
/// deleted, dropped by a subscription update, or is the profile itself), so a
/// removed hop turns the chain back into a direct connection instead of leaving a
/// profile that can't start. Pure; idempotent.
pub fn fixup_dangling_via(state: &mut AppState) {
    let ids: Vec<String> = state.profiles.iter().map(|p| p.meta().id.clone()).collect();
    for p in &mut state.profiles {
        let meta = p.meta_mut();
        if let Some(via) = &meta.via
            && (*via == meta.id || !ids.contains(via))
        {
            meta.via = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn profile(id: &str, via: Option<&str>) -> Profile {
        serde_json::from_value(json!({
            "protocol": "trojan",
            "meta": { "id": id, "remarks": id, "groupId": "g-main", "via": via },
            "endpoint": { "address": format!("{id}.example"), "port": 443 },
            "password": "pw",
        }))
        .unwrap()
    }

    fn ids(hops: &[&Profile]) -> Vec<String> {
        hops.iter().map(|p| p.meta().id.clone()).collect()
    }

    #[test]
    fn hops_follow_via_nearest_first() {
        let all = vec![
            profile("exit", Some("mid")),
            profile("mid", Some("entry")),
            profile("entry", None),
        ];
        assert_eq!(ids(&chain_hops(&all[0], &all).unwrap()), ["mid", "entry"]);
        assert_eq!(ids(&chain_hops(&all[1], &all).unwrap()), ["entry"]);
        assert!(chain_hops(&all[2], &all).unwrap().is_empty());
    }

    #[test]
    fn broken_chains_are_errors() {
        let looped = vec![profile("a", Some("b")), profile("b", Some("a"))];
        assert!(
            chain_hops(&looped[0], &looped)
                .unwrap_err()
                .contains("loops")
        );
        let own = vec![profile("a", Some("a"))];
        assert!(chain_hops(&own[0], &own).unwrap_err().contains("loops"));
        let missing = vec![profile("a", Some("gone"))];
        assert!(
            chain_hops(&missing[0], &missing)
                .unwrap_err()
                .contains("not found")
        );

        let custom: Profile = serde_json::from_value(json!({
            "protocol": "custom",
            "meta": { "id": "c", "remarks": "c", "groupId": "g-main" },
            "raw": "{}",
        }))
        .unwrap();
        let all = vec![profile("a", Some("c")), custom];
        assert!(chain_hops(&all[0], &all).unwrap_err().contains("custom"));
    }

    #[test]
    fn candidates_are_the_hops_the_builders_accept() {
        let custom: Profile = serde_json::from_value(json!({
            "protocol": "custom",
            "meta": { "id": "raw", "remarks": "raw", "groupId": "g-main" },
            "raw": "{}",
        }))
        .unwrap();
        // c -> b -> a, plus an unrelated d and a custom profile.
        let all = vec![
            profile("a", None),
            profile("b", Some("a")),
            profile("c", Some("b")),
            profile("d", None),
            custom,
        ];
        // a can't dial through b or c (they already go through a), itself, or raw.
        assert_eq!(chain_candidates(&all[0], &all), ["d"]);
        assert_eq!(chain_candidates(&all[2], &all), ["a", "b", "d"]);
        // An unsaved draft (id not stored yet) may use anything but the custom one.
        let draft = profile("new", None);
        assert_eq!(chain_candidates(&draft, &all), ["a", "b", "c", "d"]);
        // The draft's edits count, not its stored copy: once a dials through d,
        // d can no longer dial through a.
        let mut a_via_d = all[0].clone();
        a_via_d.meta_mut().via = Some("d".into());
        let mut edited = all.clone();
        edited[0] = a_via_d;
        assert!(!chain_candidates(&edited[3], &edited).contains(&"a".to_string()));
    }

    #[test]
    fn dangling_and_self_via_are_cleared() {
        let mut state = crate::state::default_app_state();
        state.profiles = vec![
            profile("a", Some("b")),
            profile("b", Some("gone")),
            profile("c", Some("c")),
        ];
        fixup_dangling_via(&mut state);
        let via: Vec<Option<String>> = state
            .profiles
            .iter()
            .map(|p| p.meta().via.clone())
            .collect();
        assert_eq!(via, [Some("b".to_string()), None, None]);
    }
}
