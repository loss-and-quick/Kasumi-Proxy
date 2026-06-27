//! Write-side middleware for [`AppState`].
//!
//! `WriteState` is the "replace the whole persisted state" escape hatch the UI
//! uses for every edit. That makes it a natural sink for cross-cutting domain
//! rules that must hold whenever state is saved — "a subscription whose group
//! changed drags its profiles along", "a dangling active_id is nulled", and so
//! on. Left inline, those rules rot the command router; collected here as small,
//! pure, individually testable rules they stay next to the domain they express.
//!
//! Each rule sees both the state currently on disk (`prev`) and the state about
//! to replace it (`next`), so it can react to a *transition* — something a
//! read-side normalizer can't do, since on read there is no "before". Rules that
//! only need a single state are of course free to ignore `prev`.
//!
//! Registration order is load-bearing: a rule that assumes another already ran
//! must be pushed after it (see [`WriteChain::run`]). Keep that order in one
//! place — the [`default_chain`] constructor — so it is visible at a glance and
//! not scattered across init sites.

use kasumi_core::state::AppState;
use kasumi_core::sub_apply::migrate_profiles_to_new_group;

/// A single write-side rule. Pure: no I/O, deterministic, trivially unit-testable.
///
/// Implementors mutate `next` in place based on the `prev` → `next` transition.
/// Returning early when the rule doesn't apply keeps the chain cheap.
pub trait WriteMiddleware: Send + Sync {
    /// Stable identifier for logs/diagnostics; not load-bearing for behaviour.
    fn name(&self) -> &'static str;
    /// Apply the rule, mutating `next` as needed.
    fn apply(&self, prev: &AppState, next: &mut AppState);
}

/// An ordered collection of write-side rules, run before persistence.
pub struct WriteChain {
    rules: Vec<Box<dyn WriteMiddleware>>,
}

impl WriteChain {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Append a rule. Rules run in push order.
    pub fn push<R: WriteMiddleware + 'static>(&mut self, rule: R) -> &mut Self {
        self.rules.push(Box::new(rule));
        self
    }

    /// Run every rule in registration order. A panicking rule aborts the write;
    /// rules are expected to be infallible (they only rearrange in-memory data).
    pub fn run(&self, prev: &AppState, next: &mut AppState) {
        for rule in &self.rules {
            rule.apply(prev, next);
        }
    }

    /// Number of registered rules (diagnostics / tests).
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Default for WriteChain {
    fn default() -> Self {
        default_chain()
    }
}

/// Move a subscription's profiles to its new group whenever `group_id` changed
/// between `prev` and `next`. Profiles the user dragged to a *third* group are
/// left where they are — only the ones still in the subscription's previous
/// target group follow it.
pub struct MigrateSubGroups;

impl WriteMiddleware for MigrateSubGroups {
    fn name(&self) -> &'static str {
        "migrate-sub-groups"
    }

    fn apply(&self, prev: &AppState, next: &mut AppState) {
        for new_sub in &next.subscriptions {
            let Some(prev_sub) = prev.subscriptions.iter().find(|s| s.id == new_sub.id) else {
                continue;
            };
            if let (Some(old_g), Some(new_g)) = (&prev_sub.group_id, &new_sub.group_id) {
                if old_g != new_g {
                    migrate_profiles_to_new_group(&mut next.profiles, &new_sub.id, old_g, new_g);
                }
            }
        }
    }
}

/// Build the canonical chain of write-side rules, in dependency order.
///
/// Centralizing construction here keeps rule ordering auditable in one spot;
/// individual modules own their rule's *implementation* but not where it sits in
/// the sequence. Add new rules here as the dependency graph grows.
pub fn default_chain() -> WriteChain {
    let mut chain = WriteChain::new();
    chain.push(MigrateSubGroups);
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_core::profile::Profile;
    use kasumi_core::share::parse_share_link;
    use kasumi_core::state::{default_app_state, Group, Subscription};

    fn p(uri: &str) -> Profile {
        parse_share_link(uri, None).unwrap()
    }

    fn sub(id: &str, group: Option<&str>) -> Subscription {
        Subscription {
            id: id.into(),
            remarks: "Sub".into(),
            url: String::new(),
            enabled: true,
            group_id: group.map(str::to_string),
            auto_update: false,
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

    fn state_with(subs: Vec<Subscription>, mut profiles: Vec<Profile>) -> AppState {
        let mut s = default_app_state();
        // Give every profile a stable id for the assertions.
        for (i, p) in profiles.iter_mut().enumerate() {
            p.meta_mut().id = format!("p{i}");
        }
        s.subscriptions = subs;
        s.groups = vec![
            Group {
                id: "g-old".into(),
                name: "Old".into(),
                sub_id: None,
            },
            Group {
                id: "g-new".into(),
                name: "New".into(),
                sub_id: None,
            },
            Group {
                id: "g-manual".into(),
                name: "Manual".into(),
                sub_id: None,
            },
        ];
        s.profiles = profiles;
        s
    }

    #[test]
    fn migrate_follows_group_change_and_preserves_manual_moves() {
        // s1 owned two profiles in g-old, one dragged to g-manual by hand.
        let mut a = p("vless://u1@e.x:443?type=tcp#A");
        a.meta_mut().sub_id = Some("s1".into());
        a.meta_mut().group_id = "g-old".into();
        let mut b = p("vless://u2@e.x:443?type=tcp#B");
        b.meta_mut().sub_id = Some("s1".into());
        b.meta_mut().group_id = "g-old".into();
        let mut manual = p("vless://u3@e.x:443?type=tcp#M");
        manual.meta_mut().sub_id = Some("s1".into());
        manual.meta_mut().group_id = "g-manual".into();
        // s2 has a profile in g-old too — must not be touched by s1's move.
        let mut other = p("vless://u4@e.x:443?type=tcp#O");
        other.meta_mut().sub_id = Some("s2".into());
        other.meta_mut().group_id = "g-old".into();

        let prev = state_with(
            vec![sub("s1", Some("g-old")), sub("s2", Some("g-old"))],
            vec![],
        );
        let mut next = state_with(
            vec![sub("s1", Some("g-new")), sub("s2", Some("g-old"))],
            vec![a, b, manual, other],
        );

        default_chain().run(&prev, &mut next);

        let group_of = |id: &str| {
            next.profiles
                .iter()
                .find(|p| p.meta().id == id)
                .unwrap()
                .meta()
                .group_id
                .as_str()
        };
        // s1's g-old profiles followed the subscription to g-new.
        assert_eq!(group_of("p0"), "g-new");
        assert_eq!(group_of("p1"), "g-new");
        // The manual move and the other subscription are untouched.
        assert_eq!(group_of("p2"), "g-manual");
        assert_eq!(group_of("p3"), "g-old");
    }

    #[test]
    fn no_change_when_group_id_unchanged() {
        let mut a = p("vless://u1@e.x:443?type=tcp#A");
        a.meta_mut().sub_id = Some("s1".into());
        a.meta_mut().group_id = "g-old".into();
        let prev = state_with(vec![sub("s1", Some("g-old"))], vec![]);
        let mut next = state_with(vec![sub("s1", Some("g-old"))], vec![a]);
        default_chain().run(&prev, &mut next);
        assert_eq!(next.profiles[0].meta().group_id.as_str(), "g-old");
    }

    #[test]
    fn new_subscription_leaves_existing_profiles_alone() {
        // s1 newly added (no prev entry) — nothing to migrate from.
        let mut a = p("vless://u1@e.x:443?type=tcp#A");
        a.meta_mut().sub_id = Some("s1".into());
        a.meta_mut().group_id = "g-old".into();
        let prev = state_with(vec![], vec![]);
        let mut next = state_with(vec![sub("s1", Some("g-new"))], vec![a]);
        default_chain().run(&prev, &mut next);
        assert_eq!(next.profiles[0].meta().group_id.as_str(), "g-old");
    }

    #[test]
    fn chain_runs_rules_in_registration_order() {
        // A sentinel rule that flips a marker; verify it ran by side effect.
        struct Flip;
        impl WriteMiddleware for Flip {
            fn name(&self) -> &'static str {
                "flip"
            }
            fn apply(&self, _prev: &AppState, next: &mut AppState) {
                next.settings.mtu = 9999;
            }
        }
        let mut chain = WriteChain::new();
        chain.push(Flip);
        chain.push(MigrateSubGroups);
        assert_eq!(chain.len(), 2);
        let prev = default_app_state();
        let mut next = default_app_state();
        chain.run(&prev, &mut next);
        assert_eq!(next.settings.mtu, 9999);
    }
}
