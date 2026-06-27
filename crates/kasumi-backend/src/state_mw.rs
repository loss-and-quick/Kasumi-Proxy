//! Write-side middleware for [`AppState`].
//!
//! Every persisted edit flows through one path: the `Mutate` command applies a
//! domain intent (`kasumi_core::mutate`) and then runs this chain before the write.
//! That makes the chain the natural sink for cross-cutting *invariants* that must
//! hold whenever state is saved — "a dangling active_id is nulled", "a deleted
//! group's profiles are pruned" — regardless of which intent triggered the save. An
//! intent's *own* consequences (e.g. a subscription dragging its profiles when its
//! group changes) belong in `apply_mutation`, next to that intent; the chain is only
//! for rules that span every edit. Collected here as small, pure, individually
//! testable rules, they stay next to the domain they express.
//!
//! Each rule sees both the state currently on disk (`prev`) and the state about
//! to replace it (`next`), so it can react to a *transition* — something a
//! read-side normalizer can't do, since on read there is no "before". Rules that
//! only need a single state are of course free to ignore `prev`.
//!
//! Rules are *pure*: they only rearrange in-memory data and return `()`. A rule that
//! needs a side-effect — e.g. "the active profile was removed, so stop the
//! data-path" — does not belong here; that lives in the `Service`, which owns the
//! lifecycle. Keep this layer about state invariants only.
//!
//! Registration order is load-bearing: a rule that assumes another already ran
//! must be pushed after it (see [`WriteChain::run`]). Keep that order in one
//! place — the [`default_chain`] constructor — so it is visible at a glance and
//! not scattered across init sites.

use kasumi_core::state::{fixup_active_id, AppState};

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

/// Null a dangling `active_id` after the edit. The single invariant
/// [`kasumi_core::core_config`] depends on (it looks the active profile up by id and
/// fails when it's missing); enforced here so backup imports, headless sub-updates
/// that drop the active, and direct `profiles.json` edits can't leave it pointing at
/// a profile that no longer exists. Runs last, after any rule that removes profiles.
pub struct FixupDanglingActiveId;

impl WriteMiddleware for FixupDanglingActiveId {
    fn name(&self) -> &'static str {
        "fixup-dangling-active-id"
    }

    fn apply(&self, _prev: &AppState, next: &mut AppState) {
        fixup_active_id(next);
    }
}

/// Build the canonical chain of write-side rules, in dependency order.
///
/// Centralizing construction here keeps rule ordering auditable in one spot;
/// individual modules own their rule's *implementation* but not where it sits in
/// the sequence. Add new rules here as the dependency graph grows.
pub fn default_chain() -> WriteChain {
    let mut chain = WriteChain::new();
    // Runs last so it sees the final profile set; add profile-removing rules before
    // it as the graph grows.
    chain.push(FixupDanglingActiveId);
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_core::profile::Profile;
    use kasumi_core::share::parse_share_link;
    use kasumi_core::state::default_app_state;

    fn p(uri: &str) -> Profile {
        parse_share_link(uri, None).unwrap()
    }

    #[test]
    fn fixup_nulls_dangling_active_id() {
        let mut a = p("vless://u1@e.x:443?type=tcp#A");
        a.meta_mut().id = "live".into();
        let prev = default_app_state();
        let mut next = default_app_state();
        next.profiles = vec![a];
        next.active_id = Some("ghost".into()); // not in profiles
        default_chain().run(&prev, &mut next);
        assert_eq!(next.active_id, None);

        // A live active id survives.
        next.active_id = Some("live".into());
        default_chain().run(&prev, &mut next);
        assert_eq!(next.active_id.as_deref(), Some("live"));
    }

    #[test]
    fn default_chain_has_the_fixup_rule() {
        assert_eq!(default_chain().len(), 1);
    }

    #[test]
    fn chain_runs_rules_in_registration_order() {
        // Two sentinels writing the same field; the later one wins, proving order.
        struct SetMtu(i64);
        impl WriteMiddleware for SetMtu {
            fn name(&self) -> &'static str {
                "set-mtu"
            }
            fn apply(&self, _prev: &AppState, next: &mut AppState) {
                next.settings.mtu = self.0;
            }
        }
        let mut chain = WriteChain::new();
        chain.push(SetMtu(1111));
        chain.push(SetMtu(2222));
        assert_eq!(chain.len(), 2);
        let prev = default_app_state();
        let mut next = default_app_state();
        chain.run(&prev, &mut next);
        assert_eq!(next.settings.mtu, 2222);
    }
}
