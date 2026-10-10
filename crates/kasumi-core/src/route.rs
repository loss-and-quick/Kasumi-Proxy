//! Routes: which routing rules a profile runs with.
//!
//! Rules live in named [`RuleBlock`]s ("Block ads", "Work domains direct"). A
//! [`Route`] lines blocks up in order and says what happens to the traffic no
//! rule matched; one block can sit in several routes, so a shared piece of the
//! rules is written once. A route applies to the profiles and groups it lists;
//! the default route (always present, always first) covers everyone else.
//!
//! The cores check rules top to bottom and stop at the first match, so however
//! routes are drawn, what a profile gets is still one flat list:
//! [`resolve_route`] picks the profile's route and concatenates its blocks.
//!
//! A profile or group is listed by at most one route, so picking the route is
//! never ambiguous: the route listing the profile, else the one listing its
//! group, else the default.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::profile::Profile;
use crate::state::{AppState, RoutingRule, RuleNetwork};

/// The route that covers every profile no other route lists.
pub const DEFAULT_ROUTE_ID: &str = "route-default";
const DEFAULT_ROUTE_NAME: &str = "Default";
/// The block the flat rule list of older versions is folded into.
const LEGACY_BLOCK_ID: &str = "block-main";
const LEGACY_BLOCK_NAME: &str = "My rules";
/// Id of the rule [`resolve_route`] appends for a route's final outbound.
const FINAL_RULE_ID: &str = "route-final";
/// The outbound that unmatched traffic takes when a route names none: the
/// builders end every rule list with this already.
pub const PROXY_OUTBOUND: &str = "proxy";

/// A named, ordered list of routing rules that routes can share.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RuleBlock {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

/// One block's place in a route. Turning it off keeps it in place (and in
/// other routes) while this route skips its rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RouteBlockRef {
    pub block_id: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

/// Which blocks, in what order, a set of profiles runs with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct Route {
    pub id: String,
    pub name: String,
    /// A switched-off route lets its profiles fall back to the default route.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Profile ids this route applies to. Empty on the default route.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// Group ids this route applies to (every profile in them, unless a route
    /// lists the profile itself). Empty on the default route.
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub blocks: Vec<RouteBlockRef>,
    /// Where traffic no rule matched goes: `proxy`, `direct`, `block` or a
    /// profile id.
    #[serde(default = "proxy_outbound")]
    pub final_outbound: String,
}

fn enabled_by_default() -> bool {
    true
}

fn proxy_outbound() -> String {
    PROXY_OUTBOUND.into()
}

/// The default route of a fresh install: no blocks, everything to the proxy.
pub fn default_route() -> Route {
    Route {
        id: DEFAULT_ROUTE_ID.into(),
        name: DEFAULT_ROUTE_NAME.into(),
        enabled: true,
        profiles: Vec::new(),
        groups: Vec::new(),
        blocks: Vec::new(),
        final_outbound: PROXY_OUTBOUND.into(),
    }
}

/// The route `profile` runs with: the enabled route listing it, else the one
/// listing its group, else the default. `None` only when state has no routes
/// at all (before [`normalize_routes`] ran).
pub fn route_for<'a>(state: &'a AppState, profile: &Profile) -> Option<&'a Route> {
    let meta = profile.meta();
    let live = || state.routes.iter().filter(|r| r.enabled);
    live()
        .find(|r| r.profiles.contains(&meta.id))
        .or_else(|| live().find(|r| r.groups.contains(&meta.group_id)))
        .or_else(|| state.routes.iter().find(|r| r.id == DEFAULT_ROUTE_ID))
}

/// The flat rule list `profile` runs with: the rules of its route's enabled
/// blocks in order, then a catch-all to the route's final outbound when that
/// isn't the proxy (the builders already end with one to the proxy).
pub fn resolve_route(state: &AppState, profile: &Profile) -> Vec<RoutingRule> {
    let Some(route) = route_for(state, profile) else {
        return Vec::new();
    };
    let mut rules: Vec<RoutingRule> = route
        .blocks
        .iter()
        .filter(|b| b.enabled)
        .filter_map(|b| state.rule_blocks.iter().find(|x| x.id == b.block_id))
        .flat_map(|b| b.rules.iter().cloned())
        .collect();
    let last = route.final_outbound.trim();
    if !last.is_empty() && last != PROXY_OUTBOUND {
        rules.push(catch_all_rule(last));
    }
    rules
}

/// A rule that every connection matches: both transports, no other condition.
fn catch_all_rule(outbound: &str) -> RoutingRule {
    RoutingRule {
        id: FINAL_RULE_ID.into(),
        remarks: String::new(),
        enabled: true,
        outbound_tag: outbound.into(),
        domain: None,
        ip: None,
        port: None,
        network: Some(RuleNetwork::TcpUdp),
        protocol: None,
        process: None,
        package_name: None,
        source_ip: None,
    }
}

/// Bring routes to their invariant shape. Pure; idempotent.
///
/// - The flat rule list of older versions (and of older backups) becomes a
///   block at the end of the default route.
/// - The default route exists, comes first, is on, and lists no one (it covers
///   whoever the others don't).
/// - A route only names blocks that exist, each once.
/// - A profile or group is listed by one route only (the first that lists it),
///   and only while it exists.
pub fn normalize_routes(state: &mut AppState) {
    fold_legacy_rules(state);
    ensure_default_route(state);

    let blocks: HashSet<&str> = state.rule_blocks.iter().map(|b| b.id.as_str()).collect();
    let profiles: HashSet<&str> = state
        .profiles
        .iter()
        .map(|p| p.meta().id.as_str())
        .collect();
    let groups: HashSet<&str> = state.groups.iter().map(|g| g.id.as_str()).collect();
    let mut taken_profiles: HashSet<String> = HashSet::new();
    let mut taken_groups: HashSet<String> = HashSet::new();
    for route in &mut state.routes {
        let mut seen: HashSet<String> = HashSet::new();
        route
            .blocks
            .retain(|b| blocks.contains(b.block_id.as_str()) && seen.insert(b.block_id.clone()));
        if route.id == DEFAULT_ROUTE_ID {
            route.profiles.clear();
            route.groups.clear();
            route.enabled = true;
            continue;
        }
        route
            .profiles
            .retain(|id| profiles.contains(id.as_str()) && taken_profiles.insert(id.clone()));
        route
            .groups
            .retain(|id| groups.contains(id.as_str()) && taken_groups.insert(id.clone()));
    }
}

fn ensure_default_route(state: &mut AppState) {
    match state.routes.iter().position(|r| r.id == DEFAULT_ROUTE_ID) {
        Some(0) => {}
        Some(i) => {
            let route = state.routes.remove(i);
            state.routes.insert(0, route);
        }
        None => state.routes.insert(0, default_route()),
    }
}

/// Move a flat `routing_rules` list (pre-routes state or backup) into a block
/// at the end of the default route.
pub fn fold_legacy_rules(state: &mut AppState) {
    if state.routing_rules.is_empty() {
        return;
    }
    ensure_default_route(state);
    let id = unique_block_id(state, LEGACY_BLOCK_ID);
    state.rule_blocks.push(RuleBlock {
        id: id.clone(),
        name: LEGACY_BLOCK_NAME.into(),
        rules: std::mem::take(&mut state.routing_rules),
    });
    state.routes[0].blocks.push(RouteBlockRef {
        block_id: id,
        enabled: true,
    });
}

fn unique_block_id(state: &AppState, base: &str) -> String {
    let taken = |id: &str| state.rule_blocks.iter().any(|b| b.id == id);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|id| !taken(id))
        .expect("an unused id")
}

/// List `route` as given, taking its profiles and groups away from every other
/// route: picking a route for a profile moves it there.
pub fn upsert_route(state: &mut AppState, route: Route) {
    let profiles: HashSet<&str> = route.profiles.iter().map(String::as_str).collect();
    let groups: HashSet<&str> = route.groups.iter().map(String::as_str).collect();
    for other in state.routes.iter_mut().filter(|r| r.id != route.id) {
        other.profiles.retain(|id| !profiles.contains(id.as_str()));
        other.groups.retain(|id| !groups.contains(id.as_str()));
    }
    match state.routes.iter_mut().find(|r| r.id == route.id) {
        Some(slot) => *slot = route,
        None => state.routes.push(route),
    }
}

/// Make `profile_id` run with `route_id`: listed there and nowhere else. The
/// default route (or `None`) only takes it off the others, so its group's route
/// or the default applies again.
pub fn set_profile_route(state: &mut AppState, profile_id: &str, route_id: Option<&str>) {
    for route in &mut state.routes {
        route.profiles.retain(|id| id != profile_id);
    }
    if let Some(route) = route_id
        .filter(|id| *id != DEFAULT_ROUTE_ID)
        .and_then(|id| state.routes.iter_mut().find(|r| r.id == id))
    {
        route.profiles.push(profile_id.to_string());
    }
}

/// Where profile references in routes and rules point after a subscription
/// refresh gave its profiles new ids. `refreshed` maps an old id to its new one
/// (or `None` when the profile is gone); ids it doesn't know are kept.
pub fn repoint_profile_ids(state: &mut AppState, refreshed: &dyn Fn(&str) -> Option<String>) {
    for route in &mut state.routes {
        route.profiles = route
            .profiles
            .iter()
            .filter_map(|id| refreshed(id))
            .collect();
        if let Some(next) = refreshed(&route.final_outbound) {
            route.final_outbound = next;
        } else {
            route.final_outbound = PROXY_OUTBOUND.into();
        }
    }
    for rule in state
        .rule_blocks
        .iter_mut()
        .flat_map(|b| b.rules.iter_mut())
    {
        // A rule whose profile is gone falls back to the proxy, as the builders
        // already treat a missing profile.
        rule.outbound_tag = refreshed(&rule.outbound_tag).unwrap_or_else(|| PROXY_OUTBOUND.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::parse_share_link;
    use crate::state::{Group, default_app_state};

    fn rule(id: &str, outbound: &str) -> RoutingRule {
        RoutingRule {
            id: id.into(),
            remarks: id.into(),
            enabled: true,
            outbound_tag: outbound.into(),
            domain: Some(vec![format!("{id}.example")]),
            ip: None,
            port: None,
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        }
    }

    fn block(id: &str, rules: &[&str]) -> RuleBlock {
        RuleBlock {
            id: id.into(),
            name: id.into(),
            rules: rules.iter().map(|r| rule(r, "direct")).collect(),
        }
    }

    fn refs(ids: &[&str]) -> Vec<RouteBlockRef> {
        ids.iter()
            .map(|id| RouteBlockRef {
                block_id: (*id).into(),
                enabled: true,
            })
            .collect()
    }

    fn route(id: &str, blocks: &[&str]) -> Route {
        Route {
            id: id.into(),
            name: id.into(),
            blocks: refs(blocks),
            ..default_route()
        }
    }

    fn profile(id: &str, group: &str) -> Profile {
        let mut p = parse_share_link("vless://u@e.x:443?type=tcp#P", None).unwrap();
        p.meta_mut().id = id.into();
        p.meta_mut().group_id = group.into();
        p
    }

    /// Profiles a (group g-main), b and c (group g2); blocks ads, work, ru;
    /// default runs ads → ru.
    fn state() -> AppState {
        let mut s = default_app_state();
        s.groups.push(Group {
            id: "g2".into(),
            name: "Two".into(),
            sub_id: None,
        });
        s.profiles = vec![
            profile("a", "g-main"),
            profile("b", "g2"),
            profile("c", "g2"),
        ];
        s.rule_blocks = vec![
            block("ads", &["ad"]),
            block("work", &["corp"]),
            block("ru", &["ru"]),
        ];
        s.routes = vec![route(DEFAULT_ROUTE_ID, &["ads", "ru"])];
        s
    }

    fn ids(rules: &[RoutingRule]) -> Vec<&str> {
        rules.iter().map(|r| r.id.as_str()).collect()
    }

    #[test]
    fn profile_route_beats_group_route_beats_default() {
        let mut s = state();
        let mut by_group = route("team", &["ads"]);
        by_group.groups = vec!["g2".into()];
        let mut by_profile = route("work", &["work", "ads", "ru"]);
        by_profile.profiles = vec!["c".into()];
        s.routes.extend([by_group, by_profile]);

        assert_eq!(ids(&resolve_route(&s, &s.profiles[0])), ["ad", "ru"]);
        assert_eq!(ids(&resolve_route(&s, &s.profiles[1])), ["ad"]);
        assert_eq!(
            ids(&resolve_route(&s, &s.profiles[2])),
            ["corp", "ad", "ru"]
        );
    }

    #[test]
    fn a_switched_off_route_falls_back_to_the_default() {
        let mut s = state();
        let mut work = route("work", &["work"]);
        work.profiles = vec!["a".into()];
        work.enabled = false;
        s.routes.push(work);
        assert_eq!(ids(&resolve_route(&s, &s.profiles[0])), ["ad", "ru"]);
    }

    #[test]
    fn a_switched_off_block_is_skipped_in_that_route_only() {
        let mut s = state();
        s.routes[0].blocks[0].enabled = false;
        let mut work = route("work", &["ads"]);
        work.profiles = vec!["a".into()];
        s.routes.push(work);
        assert_eq!(ids(&resolve_route(&s, &s.profiles[0])), ["ad"]);
        assert_eq!(ids(&resolve_route(&s, &s.profiles[1])), ["ru"]);
    }

    #[test]
    fn a_shared_block_edit_reaches_every_route() {
        let mut s = state();
        let mut work = route("work", &["ads"]);
        work.profiles = vec!["a".into()];
        s.routes.push(work);
        s.rule_blocks[0].rules.push(rule("tracker", "block"));
        assert_eq!(ids(&resolve_route(&s, &s.profiles[0])), ["ad", "tracker"]);
        assert_eq!(
            ids(&resolve_route(&s, &s.profiles[1])),
            ["ad", "tracker", "ru"]
        );
    }

    #[test]
    fn a_final_outbound_other_than_proxy_ends_with_a_catch_all() {
        let mut s = state();
        s.routes[0].final_outbound = "direct".into();
        let rules = resolve_route(&s, &s.profiles[0]);
        let last = rules.last().unwrap();
        assert_eq!(last.outbound_tag, "direct");
        assert_eq!(last.network, Some(RuleNetwork::TcpUdp));
        assert!(last.domain.is_none() && last.ip.is_none() && last.port.is_none());

        s.routes[0].final_outbound = PROXY_OUTBOUND.into();
        assert_eq!(ids(&resolve_route(&s, &s.profiles[0])), ["ad", "ru"]);
    }

    #[test]
    fn legacy_rules_fold_into_a_block_of_the_default_route() {
        let mut s = default_app_state();
        s.routes.clear();
        s.routing_rules = vec![rule("r1", "direct"), rule("r2", "block")];
        normalize_routes(&mut s);
        assert!(s.routing_rules.is_empty());
        assert_eq!(s.routes[0].id, DEFAULT_ROUTE_ID);
        assert_eq!(s.rule_blocks.len(), 1);
        assert_eq!(s.routes[0].blocks, refs(&[LEGACY_BLOCK_ID]));
        let p = profile("x", "g-main");
        assert_eq!(ids(&resolve_route(&s, &p)), ["r1", "r2"]);

        // Folding again (an old backup merged in) never reuses the id.
        s.routing_rules = vec![rule("r3", "direct")];
        normalize_routes(&mut s);
        assert_eq!(s.routes[0].blocks, refs(&[LEGACY_BLOCK_ID, "block-main-2"]));
        assert_eq!(ids(&resolve_route(&s, &p)), ["r1", "r2", "r3"]);
    }

    #[test]
    fn normalize_puts_the_default_first_and_drops_what_is_gone() {
        let mut s = state();
        let mut work = route("work", &["work", "gone", "work"]);
        work.profiles = vec!["a".into(), "deleted".into()];
        work.groups = vec!["g2".into(), "g-gone".into()];
        let mut late = route("late", &[]);
        late.profiles = vec!["a".into()];
        late.groups = vec!["g2".into()];
        let mut default = s.routes.remove(0);
        default.profiles = vec!["b".into()];
        default.enabled = false;
        s.routes = vec![work, default, late];

        normalize_routes(&mut s);
        let again = s.clone();
        normalize_routes(&mut s);
        assert_eq!(s, again, "idempotent");

        assert_eq!(s.routes[0].id, DEFAULT_ROUTE_ID);
        assert!(s.routes[0].enabled && s.routes[0].profiles.is_empty());
        let work = &s.routes[1];
        assert_eq!(work.blocks, refs(&["work"]));
        assert_eq!(work.profiles, ["a"]);
        assert_eq!(work.groups, ["g2"]);
        let late = &s.routes[2];
        assert!(late.profiles.is_empty() && late.groups.is_empty());
    }

    #[test]
    fn upsert_and_set_profile_route_move_the_profile() {
        let mut s = state();
        let mut work = route("work", &["work"]);
        work.profiles = vec!["a".into()];
        work.groups = vec!["g2".into()];
        upsert_route(&mut s, work);
        let mut team = route("team", &["ads"]);
        team.groups = vec!["g2".into()];
        upsert_route(&mut s, team);
        assert!(s.routes[1].groups.is_empty(), "g2 moved to team");
        assert_eq!(s.routes[2].groups, ["g2"]);

        set_profile_route(&mut s, "a", Some("team"));
        assert!(s.routes[1].profiles.is_empty());
        assert_eq!(s.routes[2].profiles, ["a"]);
        set_profile_route(&mut s, "a", Some(DEFAULT_ROUTE_ID));
        assert!(s.routes.iter().all(|r| r.profiles.is_empty()));
    }

    #[test]
    fn repoint_follows_refreshed_ids_and_drops_gone_ones() {
        let mut s = state();
        let mut work = route("work", &["work"]);
        work.profiles = vec!["a".into(), "b".into(), "manual".into()];
        work.final_outbound = "b".into();
        s.routes.push(work);
        s.rule_blocks[1].rules[0].outbound_tag = "a".into();
        s.rule_blocks[0].rules[0].outbound_tag = "b".into();
        let refreshed = |id: &str| match id {
            "a" => Some("a2".to_string()),
            "b" => None,
            other => Some(other.to_string()),
        };
        repoint_profile_ids(&mut s, &refreshed);
        assert_eq!(s.routes[1].profiles, ["a2", "manual"]);
        assert_eq!(s.routes[1].final_outbound, PROXY_OUTBOUND);
        assert_eq!(s.rule_blocks[1].rules[0].outbound_tag, "a2");
        assert_eq!(s.rule_blocks[0].rules[0].outbound_tag, PROXY_OUTBOUND);
        assert_eq!(s.rule_blocks[2].rules[0].outbound_tag, "direct");
    }
}
