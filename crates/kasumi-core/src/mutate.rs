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

use crate::profile::{CustomOrigin, Profile};
use crate::route::{
    DEFAULT_ROUTE_ID, Route, RuleBlock, fold_legacy_rules, set_profile_route, upsert_route,
};
use crate::state::{
    AdvancedSettings, AppState, AssetFile, BASE_GROUP_ID, RoutingRule, Subscription,
};
use crate::sub_apply::{
    deduplicate_profiles_scoped, migrate_profiles_to_new_group, remove_profiles_by_sub_id,
};
use crate::sub_changes::{
    import_routing_link, remove_provider_routing, resolve_changes, withdraw_provider_configs,
};
use crate::sub_meta_types::RoutingImport;

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
    /// Drop duplicate endpoints within the scope, always keeping the active one.
    #[serde(rename_all = "camelCase")]
    DeduplicateProfiles {
        #[serde(default)]
        active_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
    },

    // ---- groups ----
    /// Add a group. `sub_id` marks a group made for that subscription: it follows
    /// the subscription's renames and can be removed along with it.
    #[serde(rename_all = "camelCase")]
    AddGroup {
        id: String,
        name: String,
        #[serde(default)]
        sub_id: Option<String>,
    },
    RenameGroup {
        id: String,
        name: String,
    },
    /// Remove a group and its profiles. Subscriptions that fetched into it move to
    /// the base group.
    RemoveGroup {
        id: String,
    },
    /// Reorder by index; `g-main` stays pinned at 0.
    ReorderGroups {
        from: u32,
        to: u32,
    },

    // ---- subscriptions ----
    /// Add a subscription, or replace the user's settings of the one with the
    /// same `id`. Fetch results and the provider proposals with their answers
    /// stay as stored.
    UpsertSub {
        subscription: Box<Subscription>,
        /// The copy the edit started from. With it, only the settings that differ
        /// from it are applied, so a fetch that changed the others meanwhile stays.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original: Option<Box<Subscription>>,
    },
    /// Show `message` as the subscription's last error, for a failure the UI
    /// detects itself (the backend wasn't reached, or the proxy isn't running).
    SetSubError {
        id: String,
        message: String,
    },
    /// Remove a subscription and prune the profiles it still owns in its group.
    /// With `delete_group`, also remove the group made for it when nothing else
    /// is left in it.
    #[serde(rename_all = "camelCase")]
    RemoveSub {
        id: String,
        #[serde(default)]
        delete_group: bool,
    },
    /// Accept or reject provider-proposed changes of a subscription, by digest.
    /// `activate` is the user's choice for a routing import; `at` stamps the answer.
    #[serde(rename_all = "camelCase")]
    ResolveSubChange {
        sub_id: String,
        digests: Vec<String>,
        accept: bool,
        #[serde(default)]
        activate: Option<bool>,
        at: String,
    },
    /// Take back the permission to import a subscription's full Xray configs and
    /// remove the ones it imported.
    #[serde(rename_all = "camelCase")]
    WithdrawProviderConfigs {
        sub_id: String,
    },

    // ---- routing rules (inside a block) ----
    /// Add or replace a routing rule (by `id`) in block `block_id`.
    #[serde(rename_all = "camelCase")]
    UpsertRoutingRule {
        block_id: String,
        rule: Box<RoutingRule>,
    },
    #[serde(rename_all = "camelCase")]
    RemoveRoutingRule {
        block_id: String,
        id: String,
    },
    #[serde(rename_all = "camelCase")]
    ReorderRoutingRules {
        block_id: String,
        from: u32,
        to: u32,
    },
    /// Append (merge) or replace block `block_id`'s rules with `rules`.
    #[serde(rename_all = "camelCase")]
    ImportRoutingRules {
        block_id: String,
        rules: Vec<RoutingRule>,
        mode: ImportMode,
    },

    // ---- rule blocks and routes ----
    /// Add or replace a rule block (by `id`), rules included.
    UpsertRuleBlock {
        block: Box<RuleBlock>,
    },
    /// Remove a block and take it out of every route.
    RemoveRuleBlock {
        id: String,
    },
    /// Add or replace a route (by `id`). The profiles and groups it lists leave
    /// every other route.
    UpsertRoute {
        route: Box<Route>,
    },
    /// Remove a route; its profiles fall back to their group's route or the
    /// default. The default route stays.
    RemoveRoute {
        id: String,
    },
    /// Make a routing profile from a pasted `happ://routing` link the route of
    /// `group_id`, switched on when `activate`.
    #[serde(rename_all = "camelCase")]
    ImportRoutingLink {
        routing: Box<RoutingImport>,
        group_id: String,
        activate: bool,
    },
    /// Run profile `profile_id` with route `route_id` (`None` or the default:
    /// whatever its group gets).
    #[serde(rename_all = "camelCase")]
    SetProfileRoute {
        profile_id: String,
        #[serde(default)]
        route_id: Option<String>,
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
        // Same wire shape; the deserializer only upgrades older documents first.
        #[serde(deserialize_with = "migrated_backup")]
        #[specta(type = Box<AppState>)]
        incoming: Box<AppState>,
        mode: ImportMode,
    },
    /// Replace the whole persisted state wholesale (profiles included). The bulk
    /// escape hatch for one-time client migrations on hydrate; not the per-edit path.
    ReplaceState {
        state: Box<AppState>,
    },
}

/// A backup read for a restore: migrated like stored state and typed. A profile
/// that still doesn't fit is left out and counted, so one bad entry doesn't cost
/// the whole restore.
#[derive(Debug, Clone, PartialEq)]
pub struct Backup {
    pub state: AppState,
    pub skipped_profiles: u32,
}

impl Backup {
    /// Read a backup document of any past schema; a newer one is refused.
    pub fn read(mut doc: serde_json::Value) -> Result<Self, String> {
        crate::migrate::migrate_backup(&mut doc)?;
        // Taken out to be typed one at a time.
        let profiles = doc
            .as_object_mut()
            .and_then(|o| o.remove("profiles"))
            .and_then(|v| match v {
                serde_json::Value::Array(items) => Some(items),
                _ => None,
            })
            .unwrap_or_default();
        let mut state: AppState = serde_json::from_value(doc).map_err(|e| e.to_string())?;
        let total = profiles.len();
        state.profiles = profiles
            .into_iter()
            .filter_map(|p| serde_json::from_value(p).ok())
            .collect();
        let skipped_profiles = u32::try_from(total - state.profiles.len()).unwrap_or(u32::MAX);
        Ok(Self {
            state,
            skipped_profiles,
        })
    }
}

impl<'de> Deserialize<'de> for Backup {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        Self::read(serde_json::Value::deserialize(d)?).map_err(D::Error::custom)
    }
}

/// Written as the state it carries, the shape [`Backup::read`] takes back.
impl Serialize for Backup {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.state.serialize(s)
    }
}

/// Read a backup of any past schema through the migration ladder before typing
/// it, since typing would default the fields the migrations read.
fn migrated_backup<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Box<AppState>, D::Error> {
    Backup::deserialize(d).map(|b| Box::new(b.state))
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

        MutationIntent::AddGroup { id, name, sub_id } => {
            state.groups.push(crate::state::Group {
                id: id.clone(),
                name: name.clone(),
                sub_id: sub_id.clone(),
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
            state.profiles.retain(|p| p.meta().group_id != *id);
            // A subscription left pointing at the removed group would stamp its
            // next fetch with a group nobody lists, and its profiles would vanish.
            for sub in &mut state.subscriptions {
                if sub.group_id.as_deref() == Some(id.as_str()) {
                    sub.group_id = Some(BASE_GROUP_ID.into());
                }
            }
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

        MutationIntent::UpsertSub {
            subscription,
            original,
        } => {
            let mut next = (**subscription).clone();
            if let Some(stored) = state.subscriptions.iter().find(|s| s.id == next.id) {
                merge_sub_edit(&mut next, stored, original.as_deref());
            }
            let subscription = &next;
            rename_owned_group(state, subscription);
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
            upsert_by_id(&mut state.subscriptions, next);
        }
        MutationIntent::SetSubError { id, message } => {
            if let Some(sub) = state.subscriptions.iter_mut().find(|s| s.id == *id) {
                sub.last_error = Some(message.clone());
                sub.last_error_kind = None;
            }
        }
        MutationIntent::RemoveSub { id, delete_group } => {
            let group = state
                .subscriptions
                .iter()
                .find(|s| s.id == *id)
                .and_then(|s| s.group_id.clone());
            state.profiles = remove_profiles_by_sub_id(&state.profiles, id, group.as_deref());
            state.subscriptions.retain(|s| s.id != *id);
            remove_provider_routing(state, id);
            if *delete_group && let Some(g) = group.filter(|g| owned_group_is_empty(state, id, g)) {
                state.groups.retain(|x| x.id != g);
            }
            // A group this subscription made is an ordinary one from now on.
            for g in &mut state.groups {
                if g.sub_id.as_deref() == Some(id.as_str()) {
                    g.sub_id = None;
                }
            }
        }

        MutationIntent::ResolveSubChange {
            sub_id,
            digests,
            accept,
            activate,
            at,
        } => resolve_changes(state, sub_id, digests, *accept, *activate, at),
        MutationIntent::WithdrawProviderConfigs { sub_id } => {
            withdraw_provider_configs(state, sub_id);
        }

        MutationIntent::UpsertRoutingRule { block_id, rule } => {
            if let Some(b) = block_mut(state, block_id) {
                upsert_by_id(&mut b.rules, (**rule).clone());
            }
        }
        MutationIntent::RemoveRoutingRule { block_id, id } => {
            if let Some(b) = block_mut(state, block_id) {
                b.rules.retain(|r| r.id != *id);
            }
        }
        MutationIntent::ReorderRoutingRules { block_id, from, to } => {
            if let Some(b) = block_mut(state, block_id) {
                move_item_by_index(&mut b.rules, *from as usize, *to as usize);
            }
        }
        MutationIntent::ImportRoutingRules {
            block_id,
            rules,
            mode,
        } => {
            if let Some(b) = block_mut(state, block_id) {
                match mode {
                    ImportMode::Replace => b.rules = rules.clone(),
                    ImportMode::Merge => b.rules.extend(rules.iter().cloned()),
                }
            }
        }

        MutationIntent::UpsertRuleBlock { block } => {
            upsert_by_id(&mut state.rule_blocks, (**block).clone());
        }
        MutationIntent::RemoveRuleBlock { id } => {
            state.rule_blocks.retain(|b| b.id != *id);
            for r in &mut state.routes {
                r.blocks.retain(|b| b.block_id != *id);
            }
        }
        MutationIntent::UpsertRoute { route } => {
            upsert_route(state, (**route).clone());
        }
        MutationIntent::RemoveRoute { id } => {
            if id != DEFAULT_ROUTE_ID {
                state.routes.retain(|r| r.id != *id);
            }
        }
        MutationIntent::ImportRoutingLink {
            routing,
            group_id,
            activate,
        } => import_routing_link(state, group_id, routing, *activate),
        MutationIntent::SetProfileRoute {
            profile_id,
            route_id,
        } => set_profile_route(state, profile_id, route_id.as_deref()),

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
                // Take everything else from the backup, but never drop a profile:
                // keep the current ones and add the backup's (its hand-made
                // profiles; subscription ones are fetched again). A profile the
                // backup shares by id is the one already here. A now-dangling
                // active_id, or a profile whose group the backup lacks, is fixed
                // by the middleware that runs after this.
                let mut profiles = std::mem::take(&mut state.profiles);
                let known: std::collections::HashSet<String> =
                    profiles.iter().map(|p| p.meta().id.clone()).collect();
                profiles.extend(
                    incoming
                        .profiles
                        .iter()
                        .filter(|p| !known.contains(&p.meta().id))
                        .cloned(),
                );
                *state = (**incoming).clone();
                state.profiles = profiles;
            }
            ImportMode::Merge => {
                merge_backup(state, incoming);
                // Per-field override by the backup, matching the UI's prior merge.
                state.settings = incoming.settings.clone();
            }
        },
        MutationIntent::ReplaceState { state: replacement } => {
            *state = (**replacement).clone();
        }
    }
}

fn block_mut<'a>(state: &'a mut AppState, id: &str) -> Option<&'a mut RuleBlock> {
    state.rule_blocks.iter_mut().find(|b| b.id == id)
}

/// Add a backup's groups, subscriptions, resource files, profiles, blocks and
/// routes to the current ones. An incoming item that is already here is
/// skipped, and the backup's references to it follow the current one:
/// - a group: the same id or the same name;
/// - a subscription: the same id or URL, since it would fetch the same profiles;
/// - a resource file: the same id or URL;
/// - a profile: the same id, or the same protocol, endpoint and name
///   (`same_profile_identity`, the match a subscription refresh uses).
fn merge_backup(state: &mut AppState, incoming: &AppState) {
    let mut incoming = incoming.clone();
    // Legacy rules can name profiles, so they are folded before the re-pointing.
    fold_legacy_rules(&mut incoming);

    let groups = matched_ids(
        &state.groups,
        &incoming.groups,
        |a, b| a.id == b.id || a.name == b.name,
        |g| &g.id,
    );
    let subs = matched_ids(
        &state.subscriptions,
        &incoming.subscriptions,
        |a, b| a.id == b.id || (!a.url.is_empty() && a.url == b.url),
        |s| &s.id,
    );
    let assets = matched_ids(
        &state.asset_files,
        &incoming.asset_files,
        |a, b| a.id == b.id || (!a.url.is_empty() && a.url == b.url),
        |a| &a.id,
    );
    let profiles = matched_ids(
        &state.profiles,
        &incoming.profiles,
        |a, b| a.meta().id == b.meta().id || crate::sub_apply::same_profile_identity(a, b),
        |p| &p.meta().id,
    );
    let follow = |map: &std::collections::HashMap<String, String>, id: &mut String| {
        if let Some(kept) = map.get(id.as_str()) {
            id.clone_from(kept);
        }
    };

    for g in &mut incoming.groups {
        g.sub_id.iter_mut().for_each(|s| follow(&subs, s));
    }
    for s in &mut incoming.subscriptions {
        s.group_id.iter_mut().for_each(|g| follow(&groups, g));
    }
    for p in &mut incoming.profiles {
        let meta = p.meta_mut();
        follow(&groups, &mut meta.group_id);
        meta.sub_id.iter_mut().for_each(|s| follow(&subs, s));
        meta.via.iter_mut().for_each(|v| follow(&profiles, v));
    }
    for route in &mut incoming.routes {
        route.groups.iter_mut().for_each(|g| follow(&groups, g));
        route
            .source_sub_id
            .iter_mut()
            .for_each(|s| follow(&subs, s));
    }
    for block in &mut incoming.rule_blocks {
        block
            .source_sub_id
            .iter_mut()
            .for_each(|s| follow(&subs, s));
    }
    crate::route::repoint_profile_ids(&mut incoming, &|id| {
        Some(profiles.get(id).cloned().unwrap_or_else(|| id.to_owned()))
    });

    state.groups.extend(
        incoming
            .groups
            .iter()
            .filter(|g| !groups.contains_key(&g.id))
            .cloned(),
    );
    state.subscriptions.extend(
        incoming
            .subscriptions
            .iter()
            .filter(|s| !subs.contains_key(&s.id))
            .cloned(),
    );
    state.asset_files.extend(
        incoming
            .asset_files
            .iter()
            .filter(|a| !assets.contains_key(&a.id))
            .cloned(),
    );
    state.profiles.extend(
        incoming
            .profiles
            .iter()
            .filter(|p| !profiles.contains_key(&p.meta().id))
            .cloned(),
    );
    merge_routes(state, &incoming);
}

/// Each incoming item that matches a current one, keyed by its id, mapped to the
/// id of the current item it matches.
fn matched_ids<T>(
    current: &[T],
    incoming: &[T],
    same: impl Fn(&T, &T) -> bool,
    id: impl Fn(&T) -> &String,
) -> std::collections::HashMap<String, String> {
    incoming
        .iter()
        .filter_map(|new| {
            let kept = current
                .iter()
                .find(|old| id(old) == id(new))
                .or_else(|| current.iter().find(|old| same(old, new)))?;
            Some((id(new).clone(), id(kept).clone()))
        })
        .collect()
}

/// Add a backup's blocks and routes to the current ones. Its default route's
/// blocks join the end of the current default route; a block or route already
/// here by id is the one kept. A backup from before routes brings a flat rule
/// list, which becomes a block first.
fn merge_routes(state: &mut AppState, incoming: &AppState) {
    let mut incoming = incoming.clone();
    fold_legacy_rules(&mut incoming);
    for block in incoming.rule_blocks {
        if !state.rule_blocks.iter().any(|b| b.id == block.id) {
            state.rule_blocks.push(block);
        }
    }
    for route in incoming.routes {
        if route.id == DEFAULT_ROUTE_ID {
            if let Some(default) = state.routes.iter_mut().find(|r| r.id == DEFAULT_ROUTE_ID) {
                default.blocks.extend(route.blocks);
            } else {
                state.routes.insert(0, route);
            }
        } else if !state.routes.iter().any(|r| r.id == route.id) {
            state.routes.push(route);
        }
    }
}

/// Whether `group` was made for subscription `sub_id` and holds nothing else: no
/// profiles and no other subscription fetching into it. Only such a group goes
/// away with its subscription.
pub fn owned_group_is_empty(state: &AppState, sub_id: &str, group: &str) -> bool {
    group != BASE_GROUP_ID
        && state
            .groups
            .iter()
            .any(|g| g.id == group && g.sub_id.as_deref() == Some(sub_id))
        && !state.profiles.iter().any(|p| p.meta().group_id == group)
        && !state
            .subscriptions
            .iter()
            .any(|s| s.id != sub_id && s.group_id.as_deref() == Some(group))
}

/// A group made for a subscription carries its name until the user renames the
/// group: when the subscription's name changes and the group still has the old
/// one, the group follows.
pub fn rename_owned_group(state: &mut AppState, next: &Subscription) {
    let Some(prev) = state.subscriptions.iter().find(|s| s.id == next.id) else {
        return;
    };
    if prev.remarks == next.remarks {
        return;
    }
    let old = prev.remarks.clone();
    if let Some(g) = state.groups.iter_mut().find(|g| {
        Some(g.id.as_str()) == next.group_id.as_deref()
            && g.sub_id.as_deref() == Some(next.id.as_str())
            && g.name == old
    }) {
        g.name = next.remarks.clone();
    }
}

/// Merge `next`, the UI's copy of a subscription, with `stored`. A fetch can land
/// while the edit sheet is open, and saving the older copy must not undo it: the
/// fetch results and the provider proposals with their answers always stay as
/// stored, and with `original`, the copy the edit started from, so does every
/// setting the user left as it was. The destructuring is exhaustive, so a new
/// field has to be sorted to one side.
fn merge_sub_edit(next: &mut Subscription, stored: &Subscription, original: Option<&Subscription>) {
    let Subscription {
        last_updated,
        count,
        last_error,
        last_error_kind,
        prev_profile,
        next_profile,
        provider,
        provider_interval_hours,
        request_timeout_secs,
        body_encrypted,
        warnings,
        pending_changes,
        decisions,
        audit,
        // The user's settings. Taking back an accepted provider setting
        // (`fallback_url`, `insecure_by_provider`, `allow_provider_configs`)
        // is an edit too.
        id: _,
        remarks,
        url,
        enabled,
        group_id,
        auto_update,
        interval,
        allow_insecure,
        user_agent,
        filter,
        update_mode,
        manual_title,
        interval_override,
        request,
        fallback_url,
        insecure_by_provider,
        allow_provider_configs,
    } = stored.clone();
    next.last_updated = last_updated;
    next.count = count;
    next.last_error = last_error;
    next.last_error_kind = last_error_kind;
    next.prev_profile = prev_profile;
    next.next_profile = next_profile;
    next.provider = provider;
    next.provider_interval_hours = provider_interval_hours;
    next.request_timeout_secs = request_timeout_secs;
    next.body_encrypted = body_encrypted;
    next.warnings = warnings;
    next.pending_changes = pending_changes;
    next.decisions = decisions;
    next.audit = audit;
    let Some(original) = original else {
        return;
    };
    macro_rules! keep_unedited {
        ($($field:ident),* $(,)?) => {$(
            if next.$field == original.$field {
                next.$field = $field;
            }
        )*};
    }
    keep_unedited!(
        remarks,
        url,
        enabled,
        group_id,
        auto_update,
        interval,
        allow_insecure,
        user_agent,
        filter,
        update_mode,
        manual_title,
        interval_override,
        request,
        fallback_url,
        insecure_by_provider,
        allow_provider_configs,
    );
}

/// Add `profile` at the front, or replace the existing one with the same `meta.id`.
fn upsert_profile_front(profiles: &mut Vec<Profile>, mut profile: Profile) {
    if let Some(slot) = profiles
        .iter_mut()
        .find(|p| p.meta().id == profile.meta().id)
    {
        // Saving a provider's config from the editor must not make it trusted.
        if let (Profile::Custom(old), Profile::Custom(new)) = (&*slot, &mut profile)
            && old.origin == CustomOrigin::Provider
        {
            new.origin = CustomOrigin::Provider;
        }
        *slot = profile;
    } else {
        profiles.insert(0, profile);
    }
}

/// Trait for the `{ id }`-keyed entities (subs, rules, blocks, assets) so one
/// upsert serves them all: replace in place by id, else append.
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
impl HasId for RuleBlock {
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
    use crate::state::{Group, default_app_state};
    use serde_json::{Value, json};

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
    fn upsert_keeps_a_provider_custom_untrusted() {
        let custom = |origin: &str| -> Profile {
            serde_json::from_value(serde_json::json!({
                "protocol": "custom",
                "meta": { "id": "c", "remarks": "C", "groupId": "g-main" },
                "raw": "{}",
                "origin": origin,
            }))
            .unwrap()
        };
        let mut s = base();
        s.profiles = vec![custom("provider")];
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertProfile {
                profile: Box::new(custom("user")),
            },
        );
        let Profile::Custom(c) = &s.profiles[0] else {
            panic!()
        };
        assert_eq!(c.origin, CustomOrigin::Provider);
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
                sub_id: None,
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
            ..Default::default()
        });
        let mut owned = with_id("trojan://pw@a.com:443#A", "a", "g-main");
        owned.meta_mut().sub_id = Some("s1".into());
        // Dragged out of the sub's group → must survive the removal.
        let mut moved = with_id("trojan://pw@b.com:443#B", "b", "g2");
        moved.meta_mut().sub_id = Some("s1".into());
        s.profiles = vec![owned, moved];
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveSub {
                id: "s1".into(),
                delete_group: false,
            },
        );
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
            ..Default::default()
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
                original: None,
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
                original: None,
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
                original: None,
            },
        );
        assert_eq!(s.profiles[0].meta().group_id, "g-main");
        assert_eq!(s.subscriptions.len(), 1);
    }

    type SubField = (&'static str, fn(&mut Subscription));

    /// Each field a fetch or a provider answer writes, set to a non-default value.
    const FETCH_RESULTS: &[SubField] = &[
        ("last_updated", |s| {
            s.last_updated = "2026-10-13T10:00:00Z".into()
        }),
        ("count", |s| s.count = 7),
        ("last_error", |s| s.last_error = Some("timed out".into())),
        ("last_error_kind", |s| {
            s.last_error_kind = Some(crate::state::SubErrorKind::Network);
        }),
        ("prev_profile", |s| s.prev_profile = Some("p0".into())),
        ("next_profile", |s| s.next_profile = Some("p2".into())),
        ("provider", |s| {
            s.provider = Some(crate::state::ProviderInfo {
                title: Some("Provider".into()),
                ..Default::default()
            });
        }),
        ("provider_interval_hours", |s| {
            s.provider_interval_hours = Some(12);
        }),
        ("request_timeout_secs", |s| {
            s.request_timeout_secs = Some(10)
        }),
        ("body_encrypted", |s| s.body_encrypted = true),
        ("warnings", |s| {
            s.warnings = vec![crate::state::SubWarning::LegacyParser];
        }),
        ("pending_changes", |s| {
            crate::sub_changes::offer_provider_configs(s, "2026-10-13T10:00:00Z");
        }),
        ("decisions", |s| {
            s.decisions = vec![crate::state::ChangeDecision {
                key: "fallback-url".into(),
                digest: "d".into(),
                accepted: false,
                at: "2026-10-13T10:00:00Z".into(),
            }];
        }),
        ("audit", |s| {
            s.audit = vec![crate::state::AuditEntry {
                at: "2026-10-13T10:00:00Z".into(),
                key: "profile-title".into(),
                outcome: crate::state::AuditOutcome::AutoApplied,
                summary: "Provider".into(),
            }];
        }),
    ];

    /// The edit sheet's copy, taken before the fetch, with the user's edits.
    fn edited_copy() -> Subscription {
        let mut s = mksub("s1", Some("g-main"));
        s.remarks = "Mine".into();
        s.manual_title = true;
        s.filter = "DE".into();
        s
    }

    #[test]
    fn upsert_sub_keeps_each_fetch_result_a_stale_copy_lacks() {
        for (field, set) in FETCH_RESULTS {
            let mut s = base();
            let mut fetched = mksub("s1", Some("g-main"));
            set(&mut fetched);
            s.subscriptions = vec![fetched];
            apply_mutation(
                &mut s,
                &MutationIntent::UpsertSub {
                    subscription: Box::new(edited_copy()),
                    original: None,
                },
            );
            let mut want = edited_copy();
            set(&mut want);
            assert_eq!(s.subscriptions[0], want, "{field}");
        }
    }

    #[test]
    fn upsert_sub_does_not_bring_back_what_a_fetch_cleared() {
        for (field, set) in FETCH_RESULTS {
            let mut s = base();
            s.subscriptions = vec![mksub("s1", Some("g-main"))];
            let mut stale = edited_copy();
            set(&mut stale);
            apply_mutation(
                &mut s,
                &MutationIntent::UpsertSub {
                    subscription: Box::new(stale),
                    original: None,
                },
            );
            assert_eq!(s.subscriptions[0], edited_copy(), "{field}");
        }
    }

    #[test]
    fn upsert_sub_takes_back_accepted_provider_settings() {
        let mut s = base();
        let mut granted = mksub("s1", Some("g-main"));
        granted.fallback_url = Some("https://backup.example/sub".into());
        granted.allow_insecure = true;
        granted.insecure_by_provider = true;
        granted.allow_provider_configs = true;
        s.subscriptions = vec![granted];
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(mksub("s1", Some("g-main"))),
                original: None,
            },
        );
        assert_eq!(s.subscriptions[0], mksub("s1", Some("g-main")));
    }

    /// The sheet opened on `opened`; then a fetch renamed the subscription (and
    /// the group made for it) and switched auto-update on.
    fn fetched_while_editing() -> (AppState, Subscription) {
        let mut s = base();
        let mut opened = mksub("s1", Some("gs"));
        opened.remarks = "Old Title".into();
        let mut fetched = opened.clone();
        fetched.remarks = "New Title".into();
        fetched.auto_update = true;
        fetched.provider_interval_hours = Some(12);
        owned_group(&mut s, "gs", "New Title", "s1");
        s.subscriptions = vec![fetched];
        (s, opened)
    }

    fn save_edit(s: &mut AppState, edited: Subscription, opened: &Subscription) {
        apply_mutation(
            s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(edited),
                original: Some(Box::new(opened.clone())),
            },
        );
    }

    #[test]
    fn an_edit_keeps_the_settings_a_fetch_changed_meanwhile() {
        let (mut s, opened) = fetched_while_editing();
        let mut edited = opened.clone();
        edited.filter = "DE".into();
        save_edit(&mut s, edited, &opened);
        let sub = &s.subscriptions[0];
        assert_eq!(sub.filter, "DE");
        assert_eq!(sub.remarks, "New Title");
        assert!(sub.auto_update);
        assert_eq!(sub.provider_interval_hours, Some(12));
        assert_eq!(
            s.groups.iter().find(|g| g.id == "gs").unwrap().name,
            "New Title"
        );
    }

    #[test]
    fn an_edit_applies_what_the_user_changed() {
        let (mut s, opened) = fetched_while_editing();
        s.groups.push(Group {
            id: "g3".into(),
            name: "Three".into(),
            sub_id: None,
        });
        s.profiles = vec![owned("trojan://pw@a.com:443#A", "a", "gs", "s1")];
        let mut edited = opened.clone();
        edited.remarks = "Mine".into();
        edited.manual_title = true;
        edited.group_id = Some("g3".into());
        save_edit(&mut s, edited, &opened);
        let sub = &s.subscriptions[0];
        assert_eq!(sub.remarks, "Mine");
        assert!(sub.manual_title);
        assert_eq!(sub.group_id.as_deref(), Some("g3"));
        assert_eq!(s.profiles[0].meta().group_id, "g3");
    }

    #[test]
    fn set_sub_error_replaces_the_error_and_its_kind() {
        let mut s = base();
        let mut sub = mksub("s1", Some("g-main"));
        sub.last_error = Some("HTTP 404".into());
        sub.last_error_kind = Some(crate::state::SubErrorKind::Network);
        s.subscriptions = vec![sub];
        apply_mutation(
            &mut s,
            &MutationIntent::SetSubError {
                id: "s1".into(),
                message: "proxy is not running".into(),
            },
        );
        assert_eq!(
            s.subscriptions[0].last_error.as_deref(),
            Some("proxy is not running")
        );
        assert_eq!(s.subscriptions[0].last_error_kind, None);
        apply_mutation(
            &mut s,
            &MutationIntent::SetSubError {
                id: "gone".into(),
                message: "x".into(),
            },
        );
        assert_eq!(s.subscriptions.len(), 1);
    }

    fn rule(id: &str) -> RoutingRule {
        RoutingRule {
            id: id.into(),
            remarks: id.into(),
            enabled: true,
            outbound_tag: "proxy".into(),
            domain: None,
            ip: None,
            port: None,
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        }
    }

    fn with_block(rules: &[&str]) -> AppState {
        let mut s = base();
        s.rule_blocks = vec![RuleBlock {
            id: "b1".into(),
            name: "B".into(),
            rules: rules.iter().map(|id| rule(id)).collect(),
            source_sub_id: None,
        }];
        s
    }

    fn rule_ids(s: &AppState) -> Vec<&str> {
        s.rule_blocks[0]
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect()
    }

    #[test]
    fn import_routing_rules_merge_and_replace() {
        let mut s = with_block(&["r1"]);
        apply_mutation(
            &mut s,
            &MutationIntent::ImportRoutingRules {
                block_id: "b1".into(),
                rules: vec![rule("r2")],
                mode: ImportMode::Merge,
            },
        );
        assert_eq!(rule_ids(&s), vec!["r1", "r2"]);
        apply_mutation(
            &mut s,
            &MutationIntent::ImportRoutingRules {
                block_id: "b1".into(),
                rules: vec![rule("r3")],
                mode: ImportMode::Replace,
            },
        );
        assert_eq!(rule_ids(&s), vec!["r3"]);
    }

    #[test]
    fn rule_edits_land_in_their_block_and_skip_an_unknown_one() {
        let mut s = with_block(&["r1", "r2"]);
        let upsert = |block: &str, id: &str| MutationIntent::UpsertRoutingRule {
            block_id: block.into(),
            rule: Box::new(rule(id)),
        };
        apply_mutation(&mut s, &upsert("b1", "r3"));
        apply_mutation(&mut s, &upsert("nope", "r4"));
        assert_eq!(rule_ids(&s), vec!["r1", "r2", "r3"]);
        apply_mutation(
            &mut s,
            &MutationIntent::ReorderRoutingRules {
                block_id: "b1".into(),
                from: 2,
                to: 0,
            },
        );
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveRoutingRule {
                block_id: "b1".into(),
                id: "r1".into(),
            },
        );
        assert_eq!(rule_ids(&s), vec!["r3", "r2"]);
    }

    #[test]
    fn removing_a_block_takes_it_out_of_every_route() {
        let mut s = with_block(&["r1"]);
        let link = crate::route::RouteBlockRef {
            block_id: "b1".into(),
            enabled: true,
        };
        s.routes[0].blocks = vec![link.clone()];
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertRoute {
                route: Box::new(Route {
                    id: "work".into(),
                    name: "Work".into(),
                    blocks: vec![link],
                    ..crate::route::default_route()
                }),
            },
        );
        apply_mutation(&mut s, &MutationIntent::RemoveRuleBlock { id: "b1".into() });
        assert!(s.rule_blocks.is_empty());
        assert!(s.routes.iter().all(|r| r.blocks.is_empty()));
    }

    #[test]
    fn the_default_route_cannot_be_removed() {
        let mut s = base();
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveRoute {
                id: DEFAULT_ROUTE_ID.into(),
            },
        );
        assert_eq!(s.routes.len(), 1);
    }

    #[test]
    fn merging_an_old_backup_folds_its_rules_into_the_default_route() {
        let mut s = with_block(&["r1"]);
        s.routes[0].blocks = vec![crate::route::RouteBlockRef {
            block_id: "b1".into(),
            enabled: true,
        }];
        let mut incoming = base();
        incoming.routes.clear();
        incoming.rule_blocks.clear();
        incoming.routing_rules = vec![rule("old")];
        apply_mutation(
            &mut s,
            &MutationIntent::ImportBackup {
                incoming: Box::new(incoming),
                mode: ImportMode::Merge,
            },
        );
        let blocks: Vec<&str> = s.routes[0]
            .blocks
            .iter()
            .map(|b| b.block_id.as_str())
            .collect();
        assert_eq!(blocks, vec!["b1", "block-main"]);
        assert_eq!(s.rule_blocks[1].rules[0].id, "old");
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
        settings.tun_mtu = 1280;
        apply_mutation(
            &mut s,
            &MutationIntent::SetSettings {
                settings: Box::new(settings),
            },
        );
        assert_eq!(s.settings.tun_mtu, 1280);
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
    fn import_backup_replace_adds_the_backups_profiles() {
        let mut s = base();
        s.profiles = vec![with_id("trojan://pw@a.com:443#A", "a", "g-main")];
        let mut incoming = default_app_state();
        incoming.profiles = vec![
            // Already here by id: the current one wins.
            with_id("trojan://pw@other.com:443#A2", "a", "g-main"),
            with_id("trojan://pw@b.com:443#B", "b", "g-main"),
        ];
        apply_mutation(
            &mut s,
            &MutationIntent::ImportBackup {
                incoming: Box::new(incoming),
                mode: ImportMode::Replace,
            },
        );
        let ids: Vec<&str> = s.profiles.iter().map(|p| p.meta().id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(s.profiles[0].meta().remarks, "A");
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
            ..Default::default()
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

    fn subscription(id: &str, url: &str, group: Option<&str>) -> Subscription {
        Subscription {
            id: id.into(),
            remarks: id.into(),
            url: url.into(),
            enabled: true,
            group_id: group.map(str::to_owned),
            interval: 60,
            ..Default::default()
        }
    }

    fn asset(id: &str, url: &str) -> AssetFile {
        AssetFile {
            id: id.into(),
            remarks: id.into(),
            url: url.into(),
            last_updated: None,
            locked: false,
        }
    }

    fn merge(state: &mut AppState, incoming: AppState) {
        apply_mutation(
            state,
            &MutationIntent::ImportBackup {
                incoming: Box::new(incoming),
                mode: ImportMode::Merge,
            },
        );
    }

    #[test]
    fn import_backup_merge_skips_what_is_already_here() {
        let mut s = base();
        s.subscriptions = vec![subscription("s1", "https://sub.example/a", Some("g2"))];
        s.asset_files = vec![asset("geoip", "https://geo.example/geoip.dat")];
        s.profiles = vec![with_id("trojan://pw@a.com:443#A", "a", "g-main")];

        let mut incoming = default_app_state();
        incoming.groups.push(Group {
            id: "g-two".into(),
            name: "Two".into(),
            sub_id: None,
        });
        incoming.subscriptions = vec![
            subscription("s9", "https://sub.example/a", Some("g-two")),
            subscription("s10", "https://sub.example/b", None),
        ];
        incoming.asset_files = vec![
            asset("geoip", "https://mirror.example/geoip.dat"),
            asset("geo-copy", "https://geo.example/geoip.dat"),
        ];
        let mut chained = with_id("trojan://pw@c.com:443#C", "c", "g-two");
        chained.meta_mut().sub_id = Some("s9".into());
        chained.meta_mut().via = Some("a-copy".into());
        incoming.profiles = vec![
            // Same id, other server: the current one stays.
            with_id("trojan://pw@other.com:443#Other", "a", "g-main"),
            // Same server and name under a new id: the same profile.
            with_id("trojan://pw@a.com:443#A", "a-copy", "g-main"),
            chained,
        ];
        let mut work = crate::route::default_route();
        work.id = "work".into();
        work.profiles = vec!["a-copy".into()];
        work.groups = vec!["g-two".into()];
        work.final_outbound = "a-copy".into();
        incoming.routes.push(work);

        merge(&mut s, incoming);

        let ids = |v: Vec<&str>| v.join(",");
        assert_eq!(
            ids(s.groups.iter().map(|g| g.id.as_str()).collect()),
            "g-main,g2"
        );
        assert_eq!(
            ids(s.subscriptions.iter().map(|x| x.id.as_str()).collect()),
            "s1,s10"
        );
        assert_eq!(
            ids(s.asset_files.iter().map(|a| a.id.as_str()).collect()),
            "geoip"
        );
        assert_eq!(
            s.asset_files[0].url, "https://geo.example/geoip.dat",
            "the current file wins"
        );
        assert_eq!(
            ids(s.profiles.iter().map(|p| p.meta().id.as_str()).collect()),
            "a,c"
        );
        assert_eq!(s.profiles[0].address(), "a.com");

        // What the backup pointed at follows the item that stayed.
        let c = s.profiles[1].meta();
        assert_eq!(
            (c.group_id.as_str(), c.sub_id.as_deref(), c.via.as_deref()),
            ("g2", Some("s1"), Some("a"))
        );
        let work = s.routes.iter().find(|r| r.id == "work").unwrap();
        assert_eq!(work.profiles, vec!["a".to_string()]);
        assert_eq!(work.groups, vec!["g2".to_string()]);
        assert_eq!(work.final_outbound, "a");
    }

    #[test]
    fn import_backup_merge_of_the_same_state_changes_nothing() {
        let mut s = base();
        s.subscriptions = vec![subscription("s1", "https://sub.example/a", Some("g2"))];
        s.asset_files = vec![asset("geoip", "https://geo.example/geoip.dat")];
        s.profiles = vec![with_id("trojan://pw@a.com:443#A", "a", "g2")];
        let before = s.clone();
        merge(&mut s, before.clone());
        assert_eq!(s.groups, before.groups);
        assert_eq!(s.subscriptions, before.subscriptions);
        assert_eq!(s.asset_files, before.asset_files);
        assert_eq!(s.profiles, before.profiles);
        assert_eq!(s.routes, before.routes);
    }

    fn import_intent(incoming: &Value, mode: &str) -> Result<MutationIntent, serde_json::Error> {
        serde_json::from_value(
            json!({ "kind": "importBackup", "incoming": incoming, "mode": mode }),
        )
    }

    fn import(state: &mut AppState, incoming: &Value, mode: &str) {
        apply_mutation(state, &import_intent(incoming, mode).unwrap());
    }

    fn sub(state: &AppState, id: &str) -> Subscription {
        state
            .subscriptions
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .unwrap_or_else(|| panic!("subscription {id} missing"))
    }

    /// What the Backup screen exported before `manualTitle` (schema v1): no
    /// `schemaVersion`, a flat rule list, settings without the request identity.
    fn v1_backup() -> Value {
        let mut settings = serde_json::to_value(AdvancedSettings::default()).unwrap();
        settings.as_object_mut().unwrap().remove("requestIdentity");
        let v1_sub = |id: &str, remarks: &str, url: &str, ua: &str| {
            json!({
                "id": id, "remarks": remarks, "url": url, "enabled": true,
                "autoUpdate": false, "interval": 60, "allowInsecure": false,
                "userAgent": ua, "filter": "", "lastUpdated": "", "count": 3,
            })
        };
        json!({
            "profiles": [],
            "groups": [{ "id": "g-main", "name": "Main" }],
            "subscriptions": [
                v1_sub("s1", "My VPN", "https://sub.example.org/s/1", "v2rayNG/1.10.16"),
                v1_sub("s2", "sub.example.org", "https://sub.example.org/s/2", ""),
            ],
            "routingRules": [],
            "assetFiles": [],
            "settings": settings,
            "activeId": null,
        })
    }

    /// A backup written by this build, with a provider-renamed subscription that
    /// sends a custom User-Agent and inherits the device headers.
    fn current_backup() -> Value {
        let mut state = default_app_state();
        state.subscriptions.push(Subscription {
            id: "s1".into(),
            remarks: "Provider Title".into(),
            url: "https://sub.example.org/s/1".into(),
            user_agent: "v2rayNG/1.10.16".into(),
            manual_title: false,
            ..Default::default()
        });
        serde_json::to_value(state).unwrap()
    }

    #[test]
    fn importing_a_v1_backup_runs_the_migrations() {
        for mode in ["replace", "merge"] {
            let mut s = base();
            import(&mut s, &v1_backup(), mode);
            let typed = sub(&s, "s1");
            assert!(typed.manual_title, "{mode}: a typed name stays the user's");
            assert_eq!(typed.request.send_hwid, Some(false), "{mode}: custom UA");
            let host = sub(&s, "s2");
            assert!(
                !host.manual_title,
                "{mode}: the host default stays replaceable"
            );
            assert_eq!(host.request.send_hwid, None, "{mode}");
            assert_eq!(s.schema_version, crate::migrate::SCHEMA_VERSION, "{mode}");
        }
    }

    #[test]
    fn importing_a_current_backup_changes_nothing() {
        let stamped = current_backup();
        // The Backup screen has never written `schemaVersion`.
        let mut unstamped = stamped.clone();
        unstamped.as_object_mut().unwrap().remove("schemaVersion");
        let expected: AppState = serde_json::from_value(stamped.clone()).unwrap();
        for backup in [stamped, unstamped] {
            let MutationIntent::ImportBackup { incoming, .. } =
                import_intent(&backup, "replace").unwrap()
            else {
                panic!("not an import");
            };
            assert_eq!(*incoming, expected);
        }
    }

    #[test]
    fn importing_a_backup_from_a_newer_schema_is_refused() {
        let mut backup = current_backup();
        backup["schemaVersion"] = json!(crate::migrate::SCHEMA_VERSION + 1);
        let err = import_intent(&backup, "merge").unwrap_err().to_string();
        assert!(err.contains("newer"), "{err}");
    }

    #[test]
    fn a_backup_profile_that_does_not_fit_is_left_out_and_counted() {
        let mut backup = current_backup();
        let good = serde_json::to_value(p("trojan://pw@a.com:443#A")).unwrap();
        let bad = json!({ "protocol": "vless", "meta": { "id": "x" } });
        backup["profiles"] = json!([good, bad]);
        let read = Backup::read(backup.clone()).unwrap();
        assert_eq!(read.skipped_profiles, 1);
        assert_eq!(read.state.profiles.len(), 1);
        // The intent reads it the same way rather than failing the restore.
        let mut s = base();
        import(&mut s, &backup, "merge");
        assert_eq!(s.profiles.len(), 1);
    }

    #[test]
    fn importing_a_v0_backup_lifts_its_flat_profiles() {
        // The first Backup screen exported profiles with every field at the top level.
        let flat = json!({
            "protocol": "trojan", "id": "t1", "remarks": "Home", "groupId": "g-main",
            "address": "ex.com", "port": 443, "network": "tcp", "headerType": "none",
            "security": "tls", "sni": "ex.com", "fingerprint": "chrome", "alpn": "",
            "password": "pw", "muxEnabled": false
        });
        let mut backup = v1_backup();
        backup["profiles"] = json!([flat]);
        let mut s = base();
        import(&mut s, &backup, "merge");
        let Some(Profile::Trojan(t)) = s.profiles.iter().find(|p| p.meta().id == "t1") else {
            panic!("{:?}", s.profiles);
        };
        assert_eq!(t.endpoint.address, "ex.com");
        assert_eq!(t.tls.sni, "ex.com");
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

    fn owned_group(s: &mut AppState, id: &str, name: &str, sub: &str) {
        s.groups.push(Group {
            id: id.into(),
            name: name.into(),
            sub_id: Some(sub.into()),
        });
    }

    #[test]
    fn remove_group_moves_its_subs_to_main() {
        let mut s = base();
        s.subscriptions = vec![mksub("s1", Some("g2")), mksub("s2", Some("g-main"))];
        apply_mutation(&mut s, &MutationIntent::RemoveGroup { id: "g2".into() });
        assert_eq!(s.subscriptions[0].group_id.as_deref(), Some("g-main"));
        assert_eq!(s.subscriptions[1].group_id.as_deref(), Some("g-main"));
    }

    #[test]
    fn remove_sub_takes_its_own_empty_group() {
        let mut s = base();
        owned_group(&mut s, "gs", "S", "s1");
        s.subscriptions = vec![mksub("s1", Some("gs"))];
        s.profiles = vec![owned("trojan://pw@a.com:443#A", "a", "gs", "s1")];
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveSub {
                id: "s1".into(),
                delete_group: true,
            },
        );
        assert!(!s.groups.iter().any(|g| g.id == "gs"));
        assert!(s.profiles.is_empty());
    }

    #[test]
    fn remove_sub_keeps_a_group_that_still_holds_something() {
        // A hand-added profile in the group.
        let mut s = base();
        owned_group(&mut s, "gs", "S", "s1");
        s.subscriptions = vec![mksub("s1", Some("gs"))];
        s.profiles = vec![with_id("trojan://pw@b.com:443#B", "b", "gs")];
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveSub {
                id: "s1".into(),
                delete_group: true,
            },
        );
        let g = s.groups.iter().find(|g| g.id == "gs").unwrap();
        assert_eq!(g.sub_id, None);

        // Another subscription fetching into it.
        let mut s = base();
        owned_group(&mut s, "gs", "S", "s1");
        s.subscriptions = vec![mksub("s1", Some("gs")), mksub("s2", Some("gs"))];
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveSub {
                id: "s1".into(),
                delete_group: true,
            },
        );
        assert!(s.groups.iter().any(|g| g.id == "gs"));

        // A group the subscription didn't make.
        let mut s = base();
        s.subscriptions = vec![mksub("s1", Some("g2"))];
        apply_mutation(
            &mut s,
            &MutationIntent::RemoveSub {
                id: "s1".into(),
                delete_group: true,
            },
        );
        assert!(s.groups.iter().any(|g| g.id == "g2"));
    }

    #[test]
    fn renaming_a_sub_renames_the_group_made_for_it() {
        let mut s = base();
        owned_group(&mut s, "gs", "S", "s1");
        s.subscriptions = vec![mksub("s1", Some("gs"))];
        let mut next = mksub("s1", Some("gs"));
        next.remarks = "Provider".into();
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(next.clone()),
                original: None,
            },
        );
        assert_eq!(
            s.groups.iter().find(|g| g.id == "gs").unwrap().name,
            "Provider"
        );

        // Once the user names the group themselves, it keeps that name.
        apply_mutation(
            &mut s,
            &MutationIntent::RenameGroup {
                id: "gs".into(),
                name: "Mine".into(),
            },
        );
        next.remarks = "Other".into();
        apply_mutation(
            &mut s,
            &MutationIntent::UpsertSub {
                subscription: Box::new(next),
                original: None,
            },
        );
        assert_eq!(s.groups.iter().find(|g| g.id == "gs").unwrap().name, "Mine");
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
        let intent: MutationIntent = serde_json::from_value(serde_json::json!({
            "kind": "resolveSubChange",
            "subId": "s1",
            "digests": ["d"],
            "accept": true,
            "at": "2026-10-13T00:00:00Z"
        }))
        .unwrap();
        assert!(matches!(
            intent,
            MutationIntent::ResolveSubChange { activate: None, .. }
        ));
        let intent: MutationIntent = serde_json::from_value(serde_json::json!({
            "kind": "withdrawProviderConfigs",
            "subId": "s1"
        }))
        .unwrap();
        assert!(matches!(
            intent,
            MutationIntent::WithdrawProviderConfigs { sub_id } if sub_id == "s1"
        ));
        let intent: MutationIntent = serde_json::from_value(serde_json::json!({
            "kind": "importRoutingLink",
            "routing": { "name": "R", "directSites": [], "directIp": [], "proxySites": [],
                "proxyIp": [], "blockSites": ["geosite:ads"], "blockIp": [] },
            "groupId": "g-main",
            "activate": true
        }))
        .unwrap();
        let mut s = default_app_state();
        apply_mutation(&mut s, &intent);
        assert!(
            s.routes
                .iter()
                .any(|r| r.id == "link-route-g-main" && r.enabled)
        );
    }
}
