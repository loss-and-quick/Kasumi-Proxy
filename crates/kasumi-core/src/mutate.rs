//! Intent-based state mutation: the single source of truth for *how* an edit
//! changes [`AppState`].
//!
//! The UI dispatches a [`MutationIntent`] (a verb: "remove these profiles", "move
//! this subscription's group", "set the active profile") rather than computing and
//! shipping a whole new state. [`apply_mutation`] applies that verb to the state in
//! place — pure, no I/O, so the desktop IPC handler and the Android daemon apply it
//! identically. Cross-cutting *invariants* (a dangling `active_id` is nulled, a
//! deleted group's profiles are pruned) are enforced after the verb by the backend's
//! write-side middleware chain, not here, so each intent only expresses its own
//! intended change.
//!
//! Id generation and i18n stay on the caller: intents that create entities carry
//! the new id (and any localized text) as fields, so this module needs no `uid()`
//! and no locale.

use serde::{Deserialize, Serialize};

use crate::profile::Profile;
use crate::state::{
    AdvancedSettings, AppState, AssetFile, RoutingRule, Subscription, BASE_GROUP_ID,
};
use crate::sub_apply::{
    deduplicate_profiles_scoped, migrate_profiles_to_new_group, remove_profiles_by_sub_id,
};

/// Merge vs replace, shared by list-import and backup-restore intents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    Merge,
    Replace,
}

/// A single state-changing verb dispatched by the UI. The tag `kind` selects the
/// variant; fields are its inputs. Applied by [`apply_mutation`].
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum MutationIntent {
    // ---- profiles ----
    /// Add a profile (front) or replace the one with the same `meta.id`.
    UpsertProfile {
        profile: Box<Profile>,
    },
    /// Remove every profile whose id is listed.
    RemoveProfiles {
        ids: Vec<String>,
    },
    /// Copy the profile `id` into a fresh one (`new_id`, `remarks`), inserted right
    /// after the source; the copy is detached from any subscription and untested.
    #[serde(rename_all = "camelCase")]
    CloneProfile {
        id: String,
        new_id: String,
        remarks: String,
    },
    /// Move the listed profiles into `group_id`.
    #[serde(rename_all = "camelCase")]
    MoveProfiles {
        ids: Vec<String>,
        group_id: String,
    },
    /// Prepend a batch of profiles (share-link / file import).
    AddProfiles {
        profiles: Vec<Profile>,
    },
    /// Drop profiles whose last ping was unreachable (`-1`) within the scope
    /// (`None`/`"all"` = every group).
    #[serde(rename_all = "camelCase")]
    RemoveUnreachable {
        #[serde(default)]
        group_id: Option<String>,
    },
    /// Drop duplicate endpoints within the scope, always keeping the active one.
    #[serde(rename_all = "camelCase")]
    DeduplicateProfiles {
        #[serde(default)]
        active_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
    },

    // ---- groups ----
    AddGroup {
        id: String,
        name: String,
    },
    RenameGroup {
        id: String,
        name: String,
    },
    RemoveGroup {
        id: String,
    },
    /// Reorder by index; `g-main` stays pinned at 0.
    ReorderGroups {
        from: u32,
        to: u32,
    },

    // ---- subscriptions ----
    /// Add or replace a subscription (by `id`).
    UpsertSub {
        subscription: Box<Subscription>,
    },
    /// Remove a subscription and prune the profiles it still owns in its group.
    RemoveSub {
        id: String,
    },

    // ---- routing rules ----
    /// Add or replace a routing rule (by `id`).
    UpsertRoutingRule {
        rule: Box<RoutingRule>,
    },
    RemoveRoutingRule {
        id: String,
    },
    ReorderRoutingRules {
        from: u32,
        to: u32,
    },
    /// Append (merge) or replace the routing-rule list with `rules`.
    ImportRoutingRules {
        rules: Vec<RoutingRule>,
        mode: ImportMode,
    },

    // ---- asset files ----
    /// Add or replace an asset entry (by `id`).
    UpsertAssetFile {
        asset: Box<AssetFile>,
    },
    RemoveAssetFile {
        id: String,
    },

    // ---- settings / active ----
    /// Replace the whole settings block (the UI builds the next one from the prev).
    SetSettings {
        settings: Box<AdvancedSettings>,
    },
    /// Set (or clear) the active profile id.
    SetActive {
        #[serde(default)]
        id: Option<String>,
    },

    // ---- bulk ----
    /// Restore a backup, merging into or replacing the current state. Replace keeps
    /// the current profiles (backups carry none).
    ImportBackup {
        incoming: Box<AppState>,
        mode: ImportMode,
    },
    /// Replace the whole persisted state wholesale (profiles included). The bulk
    /// escape hatch for one-time client migrations on hydrate; not the per-edit path.
    ReplaceState {
        state: Box<AppState>,
    },
}

/// Apply one [`MutationIntent`] to `state` in place. Pure: no I/O. Invariants that
/// span the edit (dangling `active_id`, orphaned-group profiles) are left to the
/// write-side middleware chain, which runs after this.
pub fn apply_mutation(state: &mut AppState, intent: &MutationIntent) {
    match intent {
        MutationIntent::UpsertProfile { profile } => {
            upsert_profile_front(&mut state.profiles, (**profile).clone());
        }
        MutationIntent::RemoveProfiles { ids } => {
            let remove: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
            state
                .profiles
                .retain(|p| !remove.contains(p.meta().id.as_str()));
        }
        MutationIntent::CloneProfile {
            id,
            new_id,
            remarks,
        } => {
            if let Some(idx) = state.profiles.iter().position(|p| p.meta().id == *id) {
                let mut copy = state.profiles[idx].clone();
                let m = copy.meta_mut();
                m.id = new_id.clone();
                m.remarks = remarks.clone();
                m.sub_id = None;
                m.ping = None;
                m.speed = None;
                state.profiles.insert(idx + 1, copy);
            }
        }
        MutationIntent::MoveProfiles { ids, group_id } => {
            let selected: std::collections::HashSet<&str> =
                ids.iter().map(String::as_str).collect();
            for p in state.profiles.iter_mut() {
                if selected.contains(p.meta().id.as_str()) {
                    p.meta_mut().group_id = group_id.clone();
                }
            }
        }
        MutationIntent::AddProfiles { profiles } => {
            let mut next = profiles.clone();
            next.append(&mut state.profiles);
            state.profiles = next;
        }
        MutationIntent::RemoveUnreachable { group_id } => {
            let in_scope = |p: &Profile| match group_id.as_deref() {
                None | Some("all") => true,
                Some(g) => p.meta().group_id == g,
            };
            state
                .profiles
                .retain(|p| !(in_scope(p) && p.meta().ping == Some(-1)));
        }
        MutationIntent::DeduplicateProfiles {
            active_id,
            group_id,
        } => {
            let (kept, _) = deduplicate_profiles_scoped(
                &state.profiles,
                active_id.as_deref(),
                group_id.as_deref(),
            );
            state.profiles = kept;
        }

        MutationIntent::AddGroup { id, name } => {
            state.groups.push(crate::state::Group {
                id: id.clone(),
                name: name.clone(),
                sub_id: None,
            });
        }
        MutationIntent::RenameGroup { id, name } => {
            if let Some(g) = state.groups.iter_mut().find(|g| g.id == *id) {
                g.name = name.clone();
            }
        }
        MutationIntent::RemoveGroup { id } => {
            // The base group can never be removed.
            if id == BASE_GROUP_ID {
                return;
            }
            state.groups.retain(|g| g.id != *id);
            // The group's profiles go with it; the orphaned-group middleware would
            // also catch any stragglers, but prune here so the intent is complete.
            state.profiles.retain(|p| p.meta().group_id != *id);
        }
        MutationIntent::ReorderGroups { from, to } => {
            // g-main stays pinned at index 0: never move it, never drop above it.
            let pinned = usize::from(
                state
                    .groups
                    .first()
                    .map(|g| g.id == BASE_GROUP_ID)
                    .unwrap_or(false),
            );
            let from = *from as usize;
            if from < pinned {
                return;
            }
            move_item_by_index(&mut state.groups, from, (*to as usize).max(pinned));
        }

        MutationIntent::UpsertSub { subscription } => {
            // A subscription drags its profiles with its group. The sub currently in
            // state is still the old one here, so compare groups and move the
            // profiles before replacing it — the intent owns its own migration.
            //
            // - `Some(old) → Some(new)`: profiles still in `old` follow; ones the
            //   user dragged to a third group stay put.
            // - `None → Some(new)`: first group assignment — pull *all* of the sub's
            //   profiles in (no previous target to preserve).
            if let Some(old_group) = state
                .subscriptions
                .iter()
                .find(|s| s.id == subscription.id)
                .map(|s| s.group_id.clone())
            {
                match (old_group, &subscription.group_id) {
                    (Some(old_g), Some(new_g)) if old_g != *new_g => {
                        migrate_profiles_to_new_group(
                            &mut state.profiles,
                            &subscription.id,
                            &old_g,
                            new_g,
                        );
                    }
                    (None, Some(new_g)) => {
                        for p in state.profiles.iter_mut() {
                            if p.meta().sub_id.as_deref() == Some(subscription.id.as_str())
                                && p.meta().group_id != *new_g
                            {
                                p.meta_mut().group_id = new_g.clone();
                            }
                        }
                    }
                    _ => {}
                }
            }
            upsert_by_id(&mut state.subscriptions, (**subscription).clone());
        }
        MutationIntent::RemoveSub { id } => {
            let group = state
                .subscriptions
                .iter()
                .find(|s| s.id == *id)
                .and_then(|s| s.group_id.clone());
            state.profiles = remove_profiles_by_sub_id(&state.profiles, id, group.as_deref());
            state.subscriptions.retain(|s| s.id != *id);
        }

        MutationIntent::UpsertRoutingRule { rule } => {
            upsert_by_id(&mut state.routing_rules, (**rule).clone());
        }
        MutationIntent::RemoveRoutingRule { id } => {
            state.routing_rules.retain(|r| r.id != *id);
        }
        MutationIntent::ReorderRoutingRules { from, to } => {
            move_item_by_index(&mut state.routing_rules, *from as usize, *to as usize);
        }
        MutationIntent::ImportRoutingRules { rules, mode } => match mode {
            ImportMode::Replace => state.routing_rules = rules.clone(),
            ImportMode::Merge => state.routing_rules.extend(rules.iter().cloned()),
        },

        MutationIntent::UpsertAssetFile { asset } => {
            upsert_by_id(&mut state.asset_files, (**asset).clone());
        }
        MutationIntent::RemoveAssetFile { id } => {
            state.asset_files.retain(|a| a.id != *id);
        }

        MutationIntent::SetSettings { settings } => {
            state.settings = (**settings).clone();
        }
        MutationIntent::SetActive { id } => {
            state.active_id = id.clone();
        }

        MutationIntent::ImportBackup { incoming, mode } => match mode {
            ImportMode::Replace => {
                // Keep the current profiles (backups carry none); take everything
                // else from the backup. A now-dangling active_id is nulled by the
                // middleware that runs after this.
                let profiles = std::mem::take(&mut state.profiles);
                *state = (**incoming).clone();
                state.profiles = profiles;
            }
            ImportMode::Merge => {
                state.profiles.extend(incoming.profiles.iter().cloned());
                state.groups.extend(incoming.groups.iter().cloned());
                state
                    .subscriptions
                    .extend(incoming.subscriptions.iter().cloned());
                state
                    .routing_rules
                    .extend(incoming.routing_rules.iter().cloned());
                state
                    .asset_files
                    .extend(incoming.asset_files.iter().cloned());
                // Per-field override by the backup, matching the UI's prior merge.
                state.settings = incoming.settings.clone();
            }
        },
        MutationIntent::ReplaceState { state: replacement } => {
            *state = (**replacement).clone();
        }
    }
}

/// Add `profile` at the front, or replace the existing one with the same `meta.id`.
fn upsert_profile_front(profiles: &mut Vec<Profile>, profile: Profile) {
    if let Some(slot) = profiles
        .iter_mut()
        .find(|p| p.meta().id == profile.meta().id)
    {
        *slot = profile;
    } else {
        profiles.insert(0, profile);
    }
}

/// Trait for the `{ id }`-keyed entities (subs, rules, assets) so one upsert serves
/// all three: replace in place by id, else append.
trait HasId {
    fn entity_id(&self) -> &str;
}
impl HasId for Subscription {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl HasId for RoutingRule {
    fn entity_id(&self) -> &str {
        &self.id
    }
}
impl HasId for AssetFile {
    fn entity_id(&self) -> &str {
        &self.id
    }
}

fn upsert_by_id<T: HasId>(items: &mut Vec<T>, item: T) {
    if let Some(slot) = items.iter_mut().find(|x| x.entity_id() == item.entity_id()) {
        *slot = item;
    } else {
        items.push(item);
    }
}

/// Move `items[from]` to index `to`, clamping out-of-range / no-op moves to nothing.
fn move_item_by_index<T>(items: &mut [T], from: usize, to: usize) {
    if from == to || from >= items.len() || to >= items.len() {
        return;
    }
    if from < to {
        items[from..=to].rotate_left(1);
    } else {
        items[to..=from].rotate_right(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::parse_share_link;
    use crate::state::{default_app_state, Group};

    fn p(uri: &str) -> Profile {
        parse_share_link(uri, None).unwrap()
    }

    fn with_id(uri: &str, id: &str, group: &str) -> Profile {
        let mut prof = p(uri);
        prof.meta_mut().id = id.into();
        prof.meta_mut().group_id = group.into();
        prof
    }

    fn base() -> AppState {
        let mut s = default_app_state();
        s.groups.push(Group {
            id: "g2".into(),
            name: "Two".into(),
            sub_id: None,
        });
        s
    }

    #[test]
    fn upsert_profile_adds_front_then_replaces() {
        let mut s = base();
        let mut a = with_id("trojan://pw@a.com:443#A", "a", "g-main");
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertProfile {
                profile: Box::new(a.clone()),
            },
        );
        assert_eq!(s.profiles.len(), 1);
        // Same id replaces, doesn't duplicate.
        a.meta_mut().remarks = "A2".into();
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertProfile {
                profile: Box::new(a),
            },
        );
        assert_eq!(s.profiles.len(), 1);
        assert_eq!(s.profiles[0].meta().remarks, "A2");
    }

    #[test]
    fn remove_profiles_drops_by_id() {
        let mut s = base();
        s.profiles = vec![
            with_id("trojan://pw@a.com:443#A", "a", "g-main"),
            with_id("trojan://pw@b.com:443#B", "b", "g-main"),
        ];
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveProfiles {
                ids: vec!["a".into()],
            },
        );
        let ids: Vec<&str> = s.profiles.iter().map(|p| p.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["b"]);
    }

    #[test]
    fn clone_profile_inserts_after_and_detaches() {
        let mut s = base();
        let mut src = with_id("trojan://pw@a.com:443#A", "a", "g-main");
        src.meta_mut().sub_id = Some("s1".into());
        src.meta_mut().ping = Some(50);
        s.profiles = vec![src, with_id("trojan://pw@b.com:443#B", "b", "g-main")];
        apply_mutation(
            &mut s,
            &MutationIntent::CloneProfile {
                id: "a".into(),
                new_id: "a-copy".into(),
                remarks: "A (copy)".into(),
            },
        );
        let ids: Vec<&str> = s.profiles.iter().map(|p| p.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["a", "a-copy", "b"]);
        let copy = &s.profiles[1];
        assert_eq!(copy.meta().remarks, "A (copy)");
        assert_eq!(copy.meta().sub_id, None);
        assert_eq!(copy.meta().ping, None);
    }

    #[test]
    fn move_profiles_changes_group() {
        let mut s = base();
        s.profiles = vec![
            with_id("trojan://pw@a.com:443#A", "a", "g-main"),
            with_id("trojan://pw@b.com:443#B", "b", "g-main"),
        ];
        apply_mutation(
            &mut s,
            &MutationIntent::MoveProfiles {
                ids: vec!["a".into()],
                group_id: "g2".into(),
            },
        );
        assert_eq!(s.profiles[0].meta().group_id, "g2");
        assert_eq!(s.profiles[1].meta().group_id, "g-main");
    }

    #[test]
    fn add_profiles_prepends() {
        let mut s = base();
        s.profiles = vec![with_id("trojan://pw@b.com:443#B", "b", "g-main")];
        apply_mutation(
            &mut s,
            &MutationIntent::AddProfiles {
                profiles: vec![with_id("trojan://pw@a.com:443#A", "a", "g-main")],
            },
        );
        let ids: Vec<&str> = s.profiles.iter().map(|p| p.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn remove_unreachable_scoped() {
        let mut s = base();
        let mut dead = with_id("trojan://pw@a.com:443#A", "a", "g-main");
        dead.meta_mut().ping = Some(-1);
        let mut dead_other = with_id("trojan://pw@b.com:443#B", "b", "g2");
        dead_other.meta_mut().ping = Some(-1);
        let mut alive = with_id("trojan://pw@c.com:443#C", "c", "g-main");
        alive.meta_mut().ping = Some(40);
        s.profiles = vec![dead, dead_other, alive];
        // Scope g-main: only "a" goes; "b" (other group) survives.
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveUnreachable {
                group_id: Some("g-main".into()),
            },
        );
        let ids: Vec<&str> = s.profiles.iter().map(|p| p.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c"]);
    }

    #[test]
    fn dedup_keeps_active() {
        let mut s = base();
        let a = with_id("trojan://pw@e.com:443#A", "a", "g-main");
        let b = with_id("trojan://pw@e.com:443#B", "b", "g-main"); // dup endpoint of a
        s.profiles = vec![a, b];
        apply_mutation(
            &mut s,
            &MutationIntent::DeduplicateProfiles {
                active_id: Some("b".into()),
                group_id: None,
            },
        );
        assert_eq!(s.profiles.len(), 1);
        assert_eq!(s.profiles[0].meta().id, "b"); // active survived the dedup
    }

    #[test]
    fn group_add_rename_remove_prunes_profiles() {
        let mut s = base();
        s.profiles = vec![with_id("trojan://pw@a.com:443#A", "a", "g2")];
        apply_mutation(
            &mut s,
            &MutationIntent::AddGroup {
                id: "g3".into(),
                name: "Three".into(),
            },
        );
        assert!(s.groups.iter().any(|g| g.id == "g3"));
        apply_mutation(
            &mut s,
            &MutationIntent::RenameGroup {
                id: "g3".into(),
                name: "Tri".into(),
            },
        );
        assert_eq!(s.groups.iter().find(|g| g.id == "g3").unwrap().name, "Tri");
        // Removing g2 drops its profile too.
        apply_mutation(&mut s, &MutationIntent::RemoveGroup { id: "g2".into() });
        assert!(!s.groups.iter().any(|g| g.id == "g2"));
        assert!(s.profiles.is_empty());
        // The base group is protected.
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveGroup {
                id: "g-main".into(),
            },
        );
        assert!(s.groups.iter().any(|g| g.id == "g-main"));
    }

    #[test]
    fn reorder_groups_pins_g_main() {
        let mut s = default_app_state(); // [g-main]
        for (i, name) in ["A", "B", "C"].iter().enumerate() {
            s.groups.push(Group {
                id: format!("g{i}"),
                name: (*name).into(),
                sub_id: None,
            });
        }
        // groups: g-main, g0, g1, g2 → move g2 (idx 3) to front; clamps to idx 1.
        apply_mutation(&mut s, &MutationIntent::ReorderGroups { from: 3, to: 0 });
        let ids: Vec<&str> = s.groups.iter().map(|g| g.id.as_str()).collect();
        assert_eq!(ids, vec!["g-main", "g2", "g0", "g1"]);
        // Trying to move g-main itself is a no-op.
        apply_mutation(&mut s, &MutationIntent::ReorderGroups { from: 0, to: 2 });
        assert_eq!(s.groups[0].id, "g-main");
    }

    #[test]
    fn remove_sub_prunes_owned_profiles() {
        let mut s = base();
        s.subscriptions.push(Subscription {
            id: "s1".into(),
            remarks: "S".into(),
            url: String::new(),
            enabled: true,
            group_id: Some("g-main".into()),
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
        });
        let mut owned = with_id("trojan://pw@a.com:443#A", "a", "g-main");
        owned.meta_mut().sub_id = Some("s1".into());
        // Dragged out of the sub's group → must survive the removal.
        let mut moved = with_id("trojan://pw@b.com:443#B", "b", "g2");
        moved.meta_mut().sub_id = Some("s1".into());
        s.profiles = vec![owned, moved];
        apply_mutation(&mut s, &MutationIntent::RemoveSub { id: "s1".into() });
        assert!(s.subscriptions.is_empty());
        let ids: Vec<&str> = s.profiles.iter().map(|p| p.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["b"]);
    }

    fn mksub(id: &str, group: Option<&str>) -> Subscription {
        Subscription {
            id: id.into(),
            remarks: "S".into(),
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

    fn owned(uri: &str, id: &str, group: &str, sub: &str) -> Profile {
        let mut p = with_id(uri, id, group);
        p.meta_mut().sub_id = Some(sub.into());
        p
    }

    #[test]
    fn upsert_sub_group_change_drags_profiles_preserving_manual_moves() {
        let mut s = base(); // groups: g-main, g2
        s.groups.push(crate::state::Group {
            id: "g3".into(),
            name: "Three".into(),
            sub_id: None,
        });
        s.subscriptions = vec![mksub("s1", Some("g-main"))];
        s.profiles = vec![
            owned("trojan://pw@a.com:443#A", "a", "g-main", "s1"), // follows
            owned("trojan://pw@b.com:443#B", "b", "g3", "s1"),     // dragged out → stays
            owned("trojan://pw@c.com:443#C", "c", "g-main", "s2"), // other sub → untouched
        ];
        // Edit the sub: g-main → g2.
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(mksub("s1", Some("g2"))),
            },
        );
        let group_of = |id: &str| {
            s.profiles
                .iter()
                .find(|p| p.meta().id == id)
                .unwrap()
                .meta()
                .group_id
                .clone()
        };
        assert_eq!(group_of("a"), "g2");
        assert_eq!(group_of("b"), "g3");
        assert_eq!(group_of("c"), "g-main");
        assert_eq!(s.subscriptions[0].group_id.as_deref(), Some("g2"));
    }

    #[test]
    fn upsert_sub_first_group_assignment_pulls_all_profiles() {
        let mut s = base();
        s.subscriptions = vec![mksub("s1", None)];
        s.profiles = vec![
            owned("trojan://pw@a.com:443#A", "a", "g-main", "s1"),
            owned("trojan://pw@b.com:443#B", "b", "g2", "s1"),
        ];
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(mksub("s1", Some("g2"))),
            },
        );
        assert!(s.profiles.iter().all(|p| p.meta().group_id == "g2"));
    }

    #[test]
    fn upsert_new_sub_leaves_profiles_alone() {
        let mut s = base();
        s.profiles = vec![owned("trojan://pw@a.com:443#A", "a", "g-main", "s1")];
        // s1 is new (not in state) → nothing to migrate from.
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(mksub("s1", Some("g2"))),
            },
        );
        assert_eq!(s.profiles[0].meta().group_id, "g-main");
        assert_eq!(s.subscriptions.len(), 1);
    }

    #[test]
    fn import_routing_rules_merge_and_replace() {
        let mut s = base();
        let rule = |id: &str| RoutingRule {
            id: id.into(),
            remarks: id.into(),
            enabled: true,
            outbound_tag: "proxy".into(),
            domain: None,
            ip: None,
            port: None,
            network: None,
            protocol: None,
        };
        s.routing_rules = vec![rule("r1")];
        apply_mutation(
            &mut s,
            &MutationIntent::ImportRoutingRules {
                rules: vec![rule("r2")],
                mode: ImportMode::Merge,
            },
        );
        let ids: Vec<&str> = s.routing_rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r1", "r2"]);
        apply_mutation(
            &mut s,
            &MutationIntent::ImportRoutingRules {
                rules: vec![rule("r3")],
                mode: ImportMode::Replace,
            },
        );
        let ids: Vec<&str> = s.routing_rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["r3"]);
    }

    #[test]
    fn set_active_and_settings() {
        let mut s = base();
        apply_mutation(
            &mut s,
            &MutationIntent::SetActive {
                id: Some("x".into()),
            },
        );
        assert_eq!(s.active_id.as_deref(), Some("x"));
        let mut settings = s.settings.clone();
        settings.mtu = 1280;
        apply_mutation(
            &mut s,
            &MutationIntent::SetSettings {
                settings: Box::new(settings),
            },
        );
        assert_eq!(s.settings.mtu, 1280);
    }

    #[test]
    fn import_backup_replace_keeps_current_profiles() {
        let mut s = base();
        s.profiles = vec![with_id("trojan://pw@a.com:443#A", "a", "g-main")];
        let mut incoming = default_app_state();
        incoming.active_id = Some("ghost".into());
        incoming.groups.push(Group {
            id: "gx".into(),
            name: "X".into(),
            sub_id: None,
        });
        apply_mutation(
            &mut s,
            &MutationIntent::ImportBackup {
                incoming: Box::new(incoming),
                mode: ImportMode::Replace,
            },
        );
        // Current profiles preserved, backup's groups adopted, dangling active left
        // for the middleware to null.
        assert_eq!(s.profiles.len(), 1);
        assert!(s.groups.iter().any(|g| g.id == "gx"));
        assert_eq!(s.active_id.as_deref(), Some("ghost"));
    }

    #[test]
    fn import_backup_merge_concats_lists() {
        let mut s = base();
        s.subscriptions.clear();
        let mut incoming = default_app_state();
        incoming.subscriptions.push(Subscription {
            id: "s9".into(),
            remarks: "S".into(),
            url: String::new(),
            enabled: true,
            group_id: None,
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
        });
        apply_mutation(
            &mut s,
            &MutationIntent::ImportBackup {
                incoming: Box::new(incoming),
                mode: ImportMode::Merge,
            },
        );
        assert!(s.subscriptions.iter().any(|x| x.id == "s9"));
    }

    #[test]
    fn replace_state_swaps_wholesale() {
        let mut s = base();
        s.profiles = vec![with_id("trojan://pw@a.com:443#A", "a", "g-main")];
        let mut replacement = default_app_state();
        replacement.active_id = Some("z".into());
        apply_mutation(
            &mut s,
            &MutationIntent::ReplaceState {
                state: Box::new(replacement),
            },
        );
        assert!(s.profiles.is_empty());
        assert_eq!(s.active_id.as_deref(), Some("z"));
    }

    #[test]
    fn intent_wire_shape_is_kind_tagged() {
        let intent: MutationIntent = serde_json::from_value(serde_json::json!({
            "kind": "removeProfiles",
            "ids": ["a", "b"]
        }))
        .unwrap();
        assert!(matches!(intent, MutationIntent::RemoveProfiles { .. }));
        let v = serde_json::to_value(MutationIntent::SetActive { id: None }).unwrap();
        assert_eq!(v, serde_json::json!({ "kind": "setActive", "id": null }));
    }
}
