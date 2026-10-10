// ============================================================
// src/lib/routes.ts
// Rule blocks and routes as the UI reads them. Rust (`kasumi_core::route`) owns
// the model and resolves what a profile runs with; these helpers answer the
// same questions for display (which route a profile is on, where a route's
// rules stop being reachable) and back the mock bridge's copy of the reducer.
// ============================================================

import type { Profile, Route, RouteBlockRef, RoutingRule } from "../generated/bindings";
import { DEFAULT_ROUTE_ID } from "../generated/defaults";
import { isCatchAllRule } from "./routing-rules";

export { DEFAULT_ROUTE_ID };

/** A block as the UI holds it (every field present). */
export type RuleBlock = { id: string; name: string; rules: RoutingRule[] };

/** Unmatched traffic goes here unless a route names another outbound. */
export const PROXY_OUTBOUND = "proxy";

export const isDefaultRoute = (route: Pick<Route, "id">) => route.id === DEFAULT_ROUTE_ID;

export const routeBlocks = (route: Route): RouteBlockRef[] => route.blocks ?? [];
export const routeProfiles = (route: Route): string[] => route.profiles ?? [];
export const routeGroups = (route: Route): string[] => route.groups ?? [];
export const routeEnabled = (route: Route) => route.enabled ?? true;
export const refEnabled = (ref: RouteBlockRef) => ref.enabled ?? true;
export const routeFinal = (route: Route) => route.finalOutbound || PROXY_OUTBOUND;

export function newRoute(id: string, name: string): Route {
  return {
    id,
    name,
    enabled: true,
    profiles: [],
    groups: [],
    blocks: [],
    finalOutbound: PROXY_OUTBOUND,
  };
}

/** Mirrors `route_for`: the route listing the profile, else its group, else the default. */
export function routeFor(
  routes: Route[],
  profile: Pick<Profile, "meta"> | undefined,
): Route | undefined {
  const fallback = routes.find(isDefaultRoute);
  if (!profile) return fallback;
  const live = routes.filter(routeEnabled);
  return (
    live.find((r) => routeProfiles(r).includes(profile.meta.id)) ??
    live.find((r) => routeGroups(r).includes(profile.meta.groupId)) ??
    fallback
  );
}

/** How a profile came to its route: listed itself, through its group, or neither. */
export function routeReason(
  route: Route | undefined,
  profile: Pick<Profile, "meta">,
): "profile" | "group" | "default" {
  if (!route || isDefaultRoute(route)) return "default";
  return routeProfiles(route).includes(profile.meta.id) ? "profile" : "group";
}

/** The routes a block sits in. */
export const routesUsing = (routes: Route[], blockId: string) =>
  routes.filter((r) => routeBlocks(r).some((b) => b.blockId === blockId));

/**
 * Where a route stops being reachable: the index of the block holding the first
 * enabled catch-all rule (every later block and the final outbound never see
 * traffic), or -1 when the end of the route is reached.
 */
export function catchAllBlockIndex(route: Route, blocks: RuleBlock[]): number {
  return routeBlocks(route).findIndex(
    (ref) =>
      refEnabled(ref) &&
      (blocks.find((b) => b.id === ref.blockId)?.rules.some(isCatchAllRule) ?? false),
  );
}

/** Mirrors `upsert_route`: the route's profiles and groups leave every other route. */
export function upsertRoute(routes: Route[], route: Route): Route[] {
  const profiles = new Set(routeProfiles(route));
  const groups = new Set(routeGroups(route));
  const next = routes.map((r) =>
    r.id === route.id
      ? route
      : {
          ...r,
          profiles: routeProfiles(r).filter((id) => !profiles.has(id)),
          groups: routeGroups(r).filter((id) => !groups.has(id)),
        },
  );
  return next.some((r) => r.id === route.id) ? next : [...next, route];
}

/** Mirrors `set_profile_route`. */
export function setProfileRoute(
  routes: Route[],
  profileId: string,
  routeId: string | null,
): Route[] {
  return routes.map((r) => {
    const profiles = routeProfiles(r).filter((id) => id !== profileId);
    if (r.id === routeId && !isDefaultRoute(r)) profiles.push(profileId);
    return { ...r, profiles };
  });
}

/**
 * Mirrors `normalize_routes` for the mock bridge: a legacy flat rule list
 * becomes a block of the default route, the default route comes first, and no
 * route names a missing block, profile or group, or one another route took.
 */
export function normalizeRoutes<
  S extends {
    routes: Route[];
    ruleBlocks: RuleBlock[];
    routingRules?: RoutingRule[];
    profiles: Profile[];
    groups: { id: string }[];
  },
>(state: S, newBlockId: () => string): S {
  let routes = [...state.routes];
  let ruleBlocks = [...state.ruleBlocks];
  if (!routes.some(isDefaultRoute)) routes.unshift(newRoute(DEFAULT_ROUTE_ID, "Default"));
  routes.sort((a, b) => Number(isDefaultRoute(b)) - Number(isDefaultRoute(a)));
  if (state.routingRules?.length) {
    const id = newBlockId();
    ruleBlocks = [...ruleBlocks, { id, name: "My rules", rules: state.routingRules }];
    routes[0] = {
      ...routes[0],
      blocks: [...routeBlocks(routes[0]), { blockId: id, enabled: true }],
    };
  }
  const blocks = new Set(ruleBlocks.map((b) => b.id));
  const profiles = new Set(state.profiles.map((p) => p.meta.id));
  const groups = new Set(state.groups.map((g) => g.id));
  const takenProfiles = new Set<string>();
  const takenGroups = new Set<string>();
  routes = routes.map((r) => {
    const seen = new Set<string>();
    const refs = routeBlocks(r).filter(
      (b) => blocks.has(b.blockId) && !seen.has(b.blockId) && seen.add(b.blockId),
    );
    if (isDefaultRoute(r)) return { ...r, blocks: refs, profiles: [], groups: [], enabled: true };
    const keep = (ids: string[], live: Set<string>, taken: Set<string>) =>
      ids.filter((id) => live.has(id) && !taken.has(id) && taken.add(id));
    return {
      ...r,
      blocks: refs,
      profiles: keep(routeProfiles(r), profiles, takenProfiles),
      groups: keep(routeGroups(r), groups, takenGroups),
    };
  });
  return { ...state, routes, ruleBlocks, routingRules: undefined };
}

/** Same name and the same rules (ids aside): importing it again reuses the block. */
export function sameBlock(a: RuleBlock, b: { name: string; rules: RoutingRule[] }): boolean {
  const strip = (rules: RoutingRule[]) => JSON.stringify(rules.map(({ id: _, ...r }) => r));
  return a.name === b.name && strip(a.rules) === strip(b.rules);
}

// ---- sharing a route ----
// A route travels without the profiles and groups it applies to: their ids
// mean nothing on another device. A rule or final outbound that names a
// profile turns into the proxy for the same reason.

const PACKAGE_KEY = "kasumiRoute";
const PACKAGE_VERSION = 1;

export type RoutePackage = {
  name: string;
  finalOutbound: string;
  blocks: { name: string; enabled: boolean; rules: RoutingRule[] }[];
};

const SPECIAL_OUTBOUNDS = new Set(["proxy", "direct", "block"]);
const portable = (tag: string) => (SPECIAL_OUTBOUNDS.has(tag) ? tag : PROXY_OUTBOUND);

/** Whether sharing the route turns some profile outbound into the proxy. */
export function routeNamesProfiles(route: Route, blocks: RuleBlock[]): boolean {
  if (!SPECIAL_OUTBOUNDS.has(routeFinal(route))) return true;
  return routeBlocks(route).some((ref) =>
    blocks
      .find((b) => b.id === ref.blockId)
      ?.rules.some((r) => !SPECIAL_OUTBOUNDS.has(r.outboundTag || PROXY_OUTBOUND)),
  );
}

export function exportRoutePackage(route: Route, blocks: RuleBlock[]): string {
  const pkg = {
    [PACKAGE_KEY]: PACKAGE_VERSION,
    name: route.name,
    finalOutbound: portable(routeFinal(route)),
    blocks: routeBlocks(route).flatMap((ref) => {
      const block = blocks.find((b) => b.id === ref.blockId);
      if (!block) return [];
      return [
        {
          name: block.name,
          enabled: refEnabled(ref),
          rules: block.rules.map((r) => ({ ...r, outboundTag: portable(r.outboundTag) })),
        },
      ];
    }),
  };
  return JSON.stringify(pkg, null, 2);
}

/**
 * The route's rules as one flat list, the way the core sees them, for clients
 * (or the Custom mode) that take a plain rule array. The final outbound
 * becomes a last rule matching every connection.
 */
export function flattenRoute(route: Route, blocks: RuleBlock[]): string {
  const rules = routeBlocks(route)
    .filter(refEnabled)
    .flatMap((ref) => blocks.find((b) => b.id === ref.blockId)?.rules ?? [])
    .map((r) => ({ ...r, outboundTag: portable(r.outboundTag) }));
  const last = portable(routeFinal(route));
  if (last !== PROXY_OUTBOUND)
    rules.push({
      id: "route-final",
      remarks: "",
      enabled: true,
      outboundTag: last,
      network: "tcp,udp",
    });
  return JSON.stringify(rules, null, 2);
}

/** A shared route package, or `null` when the text isn't one. */
export function parseRoutePackage(text: string): RoutePackage | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || !(PACKAGE_KEY in value)) return null;
  const raw = value as Record<string, unknown>;
  if (!Array.isArray(raw.blocks)) return null;
  const blocks: RoutePackage["blocks"] = [];
  for (const item of raw.blocks) {
    if (!item || typeof item !== "object") return null;
    const b = item as Record<string, unknown>;
    if (typeof b.name !== "string" || !Array.isArray(b.rules)) return null;
    const rules = b.rules
      .filter(isRule)
      .map((r) => ({ ...r, outboundTag: portable(r.outboundTag) }));
    blocks.push({ name: b.name, enabled: b.enabled !== false, rules });
  }
  return {
    name: typeof raw.name === "string" && raw.name.trim() ? raw.name : "Route",
    finalOutbound: portable(typeof raw.finalOutbound === "string" ? raw.finalOutbound : ""),
    blocks,
  };
}

function isRule(value: unknown): value is RoutingRule {
  if (!value || typeof value !== "object") return false;
  const r = value as Record<string, unknown>;
  return typeof r.outboundTag === "string" && typeof r.remarks === "string";
}
