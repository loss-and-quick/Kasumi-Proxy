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
    /// The subscription whose provider routing this block was imported from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_sub_id: Option<String>,
}

/// A route as it travels between devices: its blocks come along, the profiles
/// and groups it applies to don't.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RoutePackage {
    pub name: String,
    pub final_outbound: String,
    pub blocks: Vec<PackageBlock>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct PackageBlock {
    pub name: String,
    pub enabled: bool,
    pub rules: Vec<RoutingRule>,
}

/// The export texts and profile-outbound warning for sharing a route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct RouteSharePayload {
    pub export_json: String,
    pub flat_json: String,
    pub names_profiles: bool,
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
    /// Profile ids this route applies to. On the default route: profiles pinned
    /// to it against their group's route.
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
    /// The subscription whose provider routing this route was imported from.
    #[serde(default)]
    pub source_sub_id: Option<String>,
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
        source_sub_id: None,
    }
}

/// The route `profile` runs with: the enabled route listing it (the default
/// route too, which pins it there), else the one listing its group, else the
/// default. `None` only when state has no routes at all (before
/// [`normalize_routes`] ran).
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
/// - The default route exists, comes first, is on, and lists no group (it covers
///   whoever the others don't); the profiles it lists are pinned to it.
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
            route.groups.clear();
            route.enabled = true;
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
        source_sub_id: None,
    });
    state.routes[0].blocks.push(RouteBlockRef {
        block_id: id,
        enabled: true,
    });
}

pub fn unique_block_id(state: &AppState, base: &str) -> String {
    let taken = |id: &str| state.rule_blocks.iter().any(|b| b.id == id);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|id| !taken(id))
        .expect("an unused id")
}

pub fn unique_route_id(state: &AppState, base: &str) -> String {
    let taken = |id: &str| state.routes.iter().any(|r| r.id == id);
    if !taken(base) {
        return base.to_string();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|id| !taken(id))
        .expect("an unused id")
}

pub const PACKAGE_KEY: &str = "kasumiRoute";
pub const PACKAGE_VERSION: u32 = 1;

const SPECIAL_OUTBOUNDS: &[&str] = &["proxy", "direct", "block"];

pub fn is_special_outbound(tag: &str) -> bool {
    SPECIAL_OUTBOUNDS.contains(&tag)
}

pub fn portable_outbound(tag: &str) -> String {
    if is_special_outbound(tag) {
        tag.to_string()
    } else {
        PROXY_OUTBOUND.to_string()
    }
}

/// Whether sharing the route turns some profile outbound into the proxy.
pub fn route_names_profiles(route: &Route, blocks: &[RuleBlock]) -> bool {
    let final_tag = route.final_outbound.trim();
    let final_tag = if final_tag.is_empty() {
        PROXY_OUTBOUND
    } else {
        final_tag
    };
    if !is_special_outbound(final_tag) {
        return true;
    }
    route.blocks.iter().any(|r_ref| {
        blocks
            .iter()
            .find(|b| b.id == r_ref.block_id)
            .map(|b| {
                b.rules.iter().any(|r| {
                    let tag = r.outbound_tag.trim();
                    let tag = if tag.is_empty() { PROXY_OUTBOUND } else { tag };
                    !is_special_outbound(tag)
                })
            })
            .unwrap_or(false)
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SerializedRoutePackage {
    #[serde(rename = "kasumiRoute")]
    version: u32,
    name: String,
    #[serde(default = "proxy_outbound")]
    final_outbound: String,
    blocks: Vec<PackageBlock>,
}

/// Export a route and its referenced blocks into a portable JSON package string.
pub fn export_route_package(route: &Route, blocks: &[RuleBlock]) -> String {
    let package_blocks: Vec<PackageBlock> = route
        .blocks
        .iter()
        .filter_map(|r_ref| {
            let block = blocks.iter().find(|b| b.id == r_ref.block_id)?;
            let rules: Vec<RoutingRule> = block
                .rules
                .iter()
                .cloned()
                .map(|mut r| {
                    r.outbound_tag = portable_outbound(&r.outbound_tag);
                    r
                })
                .collect();
            Some(PackageBlock {
                name: block.name.clone(),
                enabled: r_ref.enabled,
                rules,
            })
        })
        .collect();

    let export = SerializedRoutePackage {
        version: PACKAGE_VERSION,
        name: route.name.clone(),
        final_outbound: portable_outbound(&route.final_outbound),
        blocks: package_blocks,
    };

    serde_json::to_string_pretty(&export).unwrap_or_default()
}

/// The route's rules as one flat list for clients taking a plain rule array.
pub fn flatten_route(route: &Route, blocks: &[RuleBlock]) -> String {
    let mut rules: Vec<RoutingRule> = route
        .blocks
        .iter()
        .filter(|r_ref| r_ref.enabled)
        .filter_map(|r_ref| blocks.iter().find(|b| b.id == r_ref.block_id))
        .flat_map(|b| b.rules.iter().cloned())
        .map(|mut r| {
            r.outbound_tag = portable_outbound(&r.outbound_tag);
            r
        })
        .collect();

    let last = portable_outbound(&route.final_outbound);
    if last != PROXY_OUTBOUND {
        rules.push(catch_all_rule(&last));
    }

    serde_json::to_string_pretty(&rules).unwrap_or_default()
}

/// Parse a shared route package from JSON text, returning `None` if invalid.
pub fn parse_route_package(text: &str) -> Option<RoutePackage> {
    let raw: SerializedRoutePackage = serde_json::from_str(text).ok()?;
    if raw.version != PACKAGE_VERSION {
        return None;
    }
    let blocks: Vec<PackageBlock> = raw
        .blocks
        .into_iter()
        .map(|mut b| {
            for rule in &mut b.rules {
                rule.outbound_tag = portable_outbound(&rule.outbound_tag);
            }
            b
        })
        .collect();
    let name = if raw.name.trim().is_empty() {
        "Route".to_string()
    } else {
        raw.name
    };
    Some(RoutePackage {
        name,
        final_outbound: portable_outbound(&raw.final_outbound),
        blocks,
    })
}

/// Build both the exported package JSON and flat JSON, with profile outbound detection.
pub fn build_route_share(route: &Route, blocks: &[RuleBlock]) -> RouteSharePayload {
    RouteSharePayload {
        export_json: export_route_package(route, blocks),
        flat_json: flatten_route(route, blocks),
        names_profiles: route_names_profiles(route, blocks),
    }
}

/// Check if an existing block has the same name and rule contents (ids aside).
pub fn same_block(a: &RuleBlock, b_name: &str, b_rules: &[RoutingRule]) -> bool {
    if a.name != b_name || a.rules.len() != b_rules.len() {
        return false;
    }
    a.rules.iter().zip(b_rules.iter()).all(|(r1, r2)| {
        r1.remarks == r2.remarks
            && r1.enabled == r2.enabled
            && r1.outbound_tag == r2.outbound_tag
            && r1.domain == r2.domain
            && r1.ip == r2.ip
            && r1.port == r2.port
            && r1.network == r2.network
            && r1.protocol == r2.protocol
            && r1.process == r2.process
            && r1.package_name == r2.package_name
            && r1.source_ip == r2.source_ip
    })
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

/// Make `profile_id` run with `route_id`: listed there and nowhere else, the
/// default route included (which pins it against its group's route). `None`
/// only takes it off every route, so its group's route or the default applies.
pub fn set_profile_route(state: &mut AppState, profile_id: &str, route_id: Option<&str>) {
    for route in &mut state.routes {
        route.profiles.retain(|id| id != profile_id);
    }
    if let Some(route) = route_id.and_then(|id| state.routes.iter_mut().find(|r| r.id == id)) {
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

/// Analysis of a rule block's catch-all rules and whether the primary catch-all is redundant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct BlockCatchAllReport {
    pub block_id: String,
    pub catch_all_rule_ids: Vec<String>,
    pub redundant: bool,
}

/// Analyze a block's rules for catch-all matching and whether the first catch-all is redundant.
pub fn analyze_rule_block(block_id: &str, rules: &[RoutingRule]) -> BlockCatchAllReport {
    let mut catch_all_rule_ids = Vec::new();
    let mut first_catch_all_idx = None;

    for (idx, rule) in rules.iter().enumerate() {
        if crate::singbox_config::matches_every_connection(rule) {
            catch_all_rule_ids.push(rule.id.clone());
            if first_catch_all_idx.is_none() {
                first_catch_all_idx = Some(idx);
            }
        }
    }

    let redundant = match first_catch_all_idx {
        Some(idx) => {
            rules[idx].outbound_tag == PROXY_OUTBOUND && !rules[idx + 1..].iter().any(|r| r.enabled)
        }
        None => false,
    };

    BlockCatchAllReport {
        block_id: block_id.to_string(),
        catch_all_rule_ids,
        redundant,
    }
}

/// Parse routing rules from JSON, accepting native Kasumi rules or third-party (e.g. V2rayNG) format.
pub fn parse_routing_rules_json(text: &str) -> Vec<RoutingRule> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    if arr.is_empty() {
        return Vec::new();
    }

    let mut rules = Vec::with_capacity(arr.len());
    for item in arr {
        let Some(obj) = item.as_object() else {
            return Vec::new();
        };
        let Some(outbound_tag) = obj.get("outboundTag").and_then(|v| v.as_str()) else {
            return Vec::new();
        };
        if outbound_tag.is_empty() {
            return Vec::new();
        }

        let mut rule_val = serde_json::Value::Object(obj.clone());
        let id_is_valid = obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !id_is_valid {
            rule_val["id"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        }
        if !obj.contains_key("remarks") {
            rule_val["remarks"] = serde_json::Value::String(String::new());
        }
        if !obj.contains_key("enabled") {
            rule_val["enabled"] = serde_json::Value::Bool(true);
        }

        let Ok(rule) = serde_json::from_value::<RoutingRule>(rule_val) else {
            return Vec::new();
        };
        rules.push(rule);
    }
    rules
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
            source_sub_id: None,
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
        default.profiles = vec!["b".into(), "deleted".into()];
        default.enabled = false;
        s.routes = vec![work, default, late];

        normalize_routes(&mut s);
        let again = s.clone();
        normalize_routes(&mut s);
        assert_eq!(s, again, "idempotent");

        assert_eq!(s.routes[0].id, DEFAULT_ROUTE_ID);
        assert!(s.routes[0].enabled);
        assert_eq!(
            s.routes[0].profiles,
            ["b"],
            "a pin to the default route stays"
        );
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
        assert_eq!(s.routes[0].profiles, ["a"]);
        assert!(s.routes[1..].iter().all(|r| r.profiles.is_empty()));
        set_profile_route(&mut s, "a", None);
        assert!(s.routes.iter().all(|r| r.profiles.is_empty()));
    }

    #[test]
    fn a_profile_pinned_to_the_default_route_leaves_its_groups_route() {
        let mut s = state();
        let mut team = route("team", &["work"]);
        team.groups = vec!["g2".into()];
        s.routes.push(team);
        let (b, c) = (s.profiles[1].clone(), s.profiles[2].clone());

        set_profile_route(&mut s, "b", Some(DEFAULT_ROUTE_ID));
        normalize_routes(&mut s);
        assert_eq!(route_for(&s, &b).unwrap().id, DEFAULT_ROUTE_ID);
        assert_eq!(ids(&resolve_route(&s, &b)), ["ad", "ru"]);
        // The rest of the group still runs the group's route.
        assert_eq!(route_for(&s, &c).unwrap().id, "team");

        // Listing the profile on another route takes the pin away.
        let mut solo = route("solo", &["ru"]);
        solo.profiles = vec!["b".into()];
        upsert_route(&mut s, solo);
        assert!(s.routes[0].profiles.is_empty());
        assert_eq!(route_for(&s, &b).unwrap().id, "solo");
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

    #[test]
    fn route_sharing_export_parse_roundtrip_and_flatten() {
        let mut r = route("r1", &["ads", "work"]);
        r.name = "My Route".into();
        r.final_outbound = "direct".into();

        let mut blocks = vec![block("ads", &["ad"]), block("work", &["corp"])];
        // One rule points to a profile id
        blocks[0].rules[0].outbound_tag = "profile-123".into();

        assert!(route_names_profiles(&r, &blocks));

        let payload = build_route_share(&r, &blocks);
        assert!(payload.names_profiles);

        let parsed = parse_route_package(&payload.export_json).expect("valid route package");
        assert_eq!(parsed.name, "My Route");
        assert_eq!(parsed.final_outbound, "direct");
        assert_eq!(parsed.blocks.len(), 2);
        // Profile id was ported to proxy
        assert_eq!(parsed.blocks[0].rules[0].outbound_tag, "proxy");
        assert_eq!(parsed.blocks[1].rules[0].outbound_tag, "direct");

        let flat_rules: Vec<RoutingRule> =
            serde_json::from_str(&payload.flat_json).expect("valid flat rules JSON");
        assert_eq!(flat_rules.len(), 3); // 2 rules + 1 catch-all route-final
        assert_eq!(flat_rules[0].outbound_tag, "proxy");
        assert_eq!(flat_rules[1].outbound_tag, "direct");
        assert_eq!(flat_rules[2].id, FINAL_RULE_ID);
        assert_eq!(flat_rules[2].outbound_tag, "direct");

        // Invalid package checks
        assert!(parse_route_package("not json").is_none());
        let missing_key = format!(r#"{{"otherKey": {PACKAGE_VERSION}}}"#);
        assert!(parse_route_package(&missing_key).is_none());
        let invalid_version = format!(r#"{{"{PACKAGE_KEY}": 99}}"#);
        assert!(parse_route_package(&invalid_version).is_none());
    }

    #[test]
    fn same_block_detects_equivalent_rules_regardless_of_ids() {
        let b1 = block("b1", &["r1", "r2"]);
        let mut b2_rules = b1.rules.clone();
        b2_rules[0].id = "different-id-1".into();
        b2_rules[1].id = "different-id-2".into();

        assert!(same_block(&b1, "b1", &b2_rules));

        // Different remarks
        b2_rules[0].remarks = "Changed".into();
        assert!(!same_block(&b1, "b1", &b2_rules));

        // Different name
        assert!(!same_block(&b1, "b2", &b1.rules));
    }

    #[test]
    fn analyze_rule_block_finds_catch_alls_and_redundancy() {
        let mut r_dns = rule("dns", "direct");
        r_dns.port = Some("53".into());

        let mut r_catchall_proxy = rule("all-proxy", "proxy");
        r_catchall_proxy.ip = Some(vec!["geoip:private".into()]); // not catch all
        let mut r_plain_catchall = rule("plain-all", "proxy");
        r_plain_catchall.domain = None;
        r_plain_catchall.port = Some("0-65535".into()); // matches every connection

        // No catch-all
        let rep1 = analyze_rule_block("b1", &[r_dns.clone(), r_catchall_proxy.clone()]);
        assert_eq!(rep1.catch_all_rule_ids.len(), 0);
        assert!(!rep1.redundant);

        // Catch-all to proxy with no enabled rule after -> redundant
        let rep2 = analyze_rule_block("b2", &[r_dns.clone(), r_plain_catchall.clone()]);
        assert_eq!(rep2.catch_all_rule_ids, vec!["plain-all"]);
        assert!(rep2.redundant);

        // Catch-all to proxy with enabled rule after -> not redundant
        let rep3 = analyze_rule_block("b3", &[r_plain_catchall.clone(), r_dns.clone()]);
        assert_eq!(rep3.catch_all_rule_ids, vec!["plain-all"]);
        assert!(!rep3.redundant);

        // Catch-all to direct -> not redundant
        let mut r_catchall_direct = r_plain_catchall.clone();
        r_catchall_direct.outbound_tag = "direct".into();
        let rep4 = analyze_rule_block("b4", &[r_catchall_direct]);
        assert!(!rep4.redundant);
    }

    #[test]
    fn parse_routing_rules_json_accepts_native_and_v2rayng() {
        let native = r#"[{
            "id": "abc-123",
            "remarks": "block ads",
            "enabled": true,
            "outboundTag": "block",
            "domain": ["geosite:category-ads"]
        }]"#;
        let rules = parse_routing_rules_json(native);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "abc-123");
        assert_eq!(rules[0].remarks, "block ads");
        assert_eq!(rules[0].outbound_tag, "block");

        let v2rayng = r#"[{
            "remarks": "direct cn",
            "enabled": true,
            "outboundTag": "direct",
            "ip": ["geoip:cn"]
        }]"#;
        let rules = parse_routing_rules_json(v2rayng);
        assert_eq!(rules.len(), 1);
        assert!(!rules[0].id.is_empty());
        assert_eq!(rules[0].remarks, "direct cn");
        assert_eq!(rules[0].outbound_tag, "direct");

        // Unique IDs for v2rayng items
        let multi = format!(
            r#"[{v2rayng_inner}, {v2rayng_inner}]"#,
            v2rayng_inner = r#"{"outboundTag": "proxy"}"#
        );
        let multi_rules = parse_routing_rules_json(&multi);
        assert_eq!(multi_rules.len(), 2);
        assert_ne!(multi_rules[0].id, multi_rules[1].id);

        // Invalid cases
        assert!(parse_routing_rules_json("[]").is_empty());
        assert!(parse_routing_rules_json("not json").is_empty());
        assert!(parse_routing_rules_json(r#"[{"foo": "bar"}]"#).is_empty());
    }
}
