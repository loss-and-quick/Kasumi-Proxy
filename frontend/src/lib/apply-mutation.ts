// ============================================================
// src/lib/apply-mutation.ts
// Dev-only TS port of the backend's `kasumi_core::mutate::apply_mutation` plus its
// write-side middleware chain (FixupDanglingActiveId, FixupRoutes). The real
// transports round-trip a MutationIntent to the Rust backend and render the
// canonical AppState it returns; the mock bridge has no backend, so it applies the
// same intent locally here. Production never imports this — it is the mock's
// stand-in for the one source of truth that lives in Rust. Keep it in sync with
// `crates/kasumi-core/src/mutate.rs`.
// ============================================================

import type { Profile, RoutingRule } from "../generated/bindings";
import { mergeSettings } from "../store/defaults";
import type { AppState, ChangeAction, MutationIntent, RoutingImport, Subscription } from "./bridge";
import { providerConfigsOf } from "./groups";
import { uid } from "./profile-utils";
import {
  DEFAULT_ROUTE_ID,
  normalizeRoutes,
  type RoutePackage,
  setProfileRoute,
  upsertRoute,
} from "./routes";

const BASE_GROUP_ID = "g-main";

function dedupKey(p: Profile): string {
  // Narrow across the protocol union by key presence (mirrors profile-utils'
  // accessors) instead of casting the shape open: uuid protocols first, then the
  // password ones, else no secret.
  const secret = "uuid" in p ? p.uuid : "password" in p ? (p.password ?? "") : "";
  const ep = "endpoint" in p ? p.endpoint : undefined;
  return `${p.protocol}|${ep?.address ?? ""}|${ep?.port ?? "null"}|${secret}`;
}

/** Mirrors `owned_group_is_empty`: the group was made for `subId` and nothing
 *  else is left in it. `state` is taken after the sub and its profiles are gone. */
export function ownedGroupIsEmpty(state: AppState, subId: string, group: string): boolean {
  return (
    group !== BASE_GROUP_ID &&
    state.groups.some((g) => g.id === group && g.subId === subId) &&
    !state.profiles.some((p) => p.meta.groupId === group) &&
    !state.subscriptions.some((s) => s.id !== subId && s.groupId === group)
  );
}

/** Drop duplicate endpoints within scope, always keeping the active one. */
function deduplicate(
  profiles: Profile[],
  activeId: string | null,
  groupId?: string | null,
): Profile[] {
  const inScope = (p: Profile) => !groupId || groupId === "all" || p.meta.groupId === groupId;
  const keep = new Map<string, string>();
  for (const p of profiles) {
    if (!inScope(p)) continue;
    const k = dedupKey(p);
    if (!keep.has(k) || p.meta.id === activeId) keep.set(k, p.meta.id);
  }
  return profiles.filter((p) => !inScope(p) || keep.get(dedupKey(p)) === p.meta.id);
}

function moveItem<T>(items: T[], from: number, to: number): T[] {
  if (from === to || from < 0 || to < 0 || from >= items.length || to >= items.length) return items;
  const next = [...items];
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
}

function upsertById<T extends { id: string }>(items: T[], item: T): T[] {
  const i = items.findIndex((x) => x.id === item.id);
  if (i < 0) return [...items, item];
  const next = [...items];
  next[i] = item;
  return next;
}

function editBlock(
  state: AppState,
  blockId: string,
  edit: (rules: RoutingRule[]) => RoutingRule[],
): AppState {
  return {
    ...state,
    ruleBlocks: state.ruleBlocks.map((b) =>
      b.id === blockId ? { ...b, rules: edit(b.rules) } : b,
    ),
  };
}

/** Mirrors `merge_routes`: the backup's blocks and routes join the current ones. */
function mergeRoutes(state: AppState, raw: AppState): Pick<AppState, "ruleBlocks" | "routes"> {
  const incoming = normalizeRoutes(raw, uid);
  const blockIds = new Set(state.ruleBlocks.map((b) => b.id));
  const routeIds = new Set(state.routes.map((r) => r.id));
  const routes = state.routes.map((r) => {
    const theirs = incoming.routes.find((x) => x.id === r.id);
    return r.id === DEFAULT_ROUTE_ID && theirs
      ? { ...r, blocks: [...(r.blocks ?? []), ...(theirs.blocks ?? [])] }
      : r;
  });
  return {
    ruleBlocks: [...state.ruleBlocks, ...incoming.ruleBlocks.filter((b) => !blockIds.has(b.id))],
    routes: [...routes, ...incoming.routes.filter((r) => !routeIds.has(r.id))],
  };
}

type ResolveIntent = Extract<MutationIntent, { kind: "resolveSubChange" }>;

const AUDIT_MAX = 50;
const DECISIONS_MAX = 100;

/** Mirrors `remove_provider_routing`: drop what a subscription's routing imported. */
function removeProviderRouting(state: AppState, subId: string): AppState {
  const gone = new Set(state.ruleBlocks.filter((b) => b.sourceSubId === subId).map((b) => b.id));
  return {
    ...state,
    ruleBlocks: state.ruleBlocks.filter((b) => b.sourceSubId !== subId),
    routes: state.routes
      .filter((r) => r.sourceSubId !== subId)
      .map((r) => ({ ...r, blocks: (r.blocks ?? []).filter((b) => !gone.has(b.blockId)) })),
  };
}

type RoutingTarget = {
  blockId: string;
  routeId: string;
  group: string;
  sourceSubId: string | null;
};

/** Mirrors `provider_ids`. */
const providerTarget = (sub: Subscription): RoutingTarget => ({
  blockId: `sub-block-${sub.id}`,
  routeId: `sub-route-${sub.id}`,
  group: sub.groupId ?? BASE_GROUP_ID,
  sourceSubId: sub.id,
});

/** Mirrors `import_routing_link`. */
const linkTarget = (group: string): RoutingTarget => ({
  blockId: `link-block-${group}`,
  routeId: `link-route-${group}`,
  group,
  sourceSubId: null,
});

/** Mirrors `routing_rules`: block, direct, proxy, Happ's default order. */
function routingRules(idPrefix: string, r: RoutingImport): RoutingRule[] {
  const lists: [string, string, string[], boolean][] = [
    ["BlockSites", "block", r.blockSites, true],
    ["BlockIp", "block", r.blockIp, false],
    ["DirectSites", "direct", r.directSites, true],
    ["DirectIp", "direct", r.directIp, false],
    ["ProxySites", "proxy", r.proxySites, true],
    ["ProxyIp", "proxy", r.proxyIp, false],
  ];
  return lists
    .filter(([, , entries]) => entries.length > 0)
    .map(([name, outbound, entries, sites]) => ({
      id: `${idPrefix}-${name.toLowerCase()}`,
      remarks: name,
      enabled: true,
      outboundTag: outbound,
      domain: sites ? entries : null,
      ip: sites ? null : entries,
    }));
}

const routingFinal = (r: RoutingImport) => (r.globalProxy === false ? "direct" : "proxy");

/** Mirrors `routing_package`. */
export function routingPackage(r: RoutingImport): RoutePackage {
  return {
    name: r.name,
    finalOutbound: routingFinal(r),
    blocks: [{ name: r.name, enabled: true, rules: routingRules("happ", r) }],
  };
}

/** Mirrors `import_routing`: one block and one route per target. */
function importRouting(
  state: AppState,
  { blockId, routeId, group, sourceSubId }: RoutingTarget,
  r: RoutingImport,
  enabled: boolean,
): AppState {
  const block = { id: blockId, name: r.name, rules: routingRules(blockId, r), sourceSubId };
  const route = {
    id: routeId,
    name: r.name,
    enabled,
    profiles: [],
    groups: [group],
    blocks: [{ blockId, enabled: true }],
    finalOutbound: routingFinal(r),
    sourceSubId,
  };
  return {
    ...state,
    ruleBlocks: upsertById(state.ruleBlocks, block),
    routes: upsertRoute(state.routes, route),
  };
}

/** Mirrors `apply_action` for one accepted change. */
function applyChange(
  state: AppState,
  sub: Subscription,
  action: ChangeAction,
  activate: boolean | null | undefined,
): AppState {
  const withSub = (patch: Partial<Subscription>) => ({
    ...state,
    subscriptions: state.subscriptions.map((s) => (s.id === sub.id ? { ...s, ...patch } : s)),
  });
  switch (action.kind) {
    case "replaceUrl":
    case "replaceDomain":
      return withSub({ url: action.url });
    case "setFallbackUrl":
      return withSub({ fallbackUrl: action.url });
    case "lockUserAgent":
      return action.on ? withSub({ userAgent: "" }) : state;
    case "setInsecure":
      return withSub({ allowInsecure: action.on, insecureByProvider: action.on });
    case "allowProviderConfigs":
      return withSub({ allowProviderConfigs: true });
    case "setRoutingEnabled":
      return {
        ...state,
        routes: state.routes.map((r) =>
          r.sourceSubId === sub.id ? { ...r, enabled: action.on } : r,
        ),
      };
    case "importRouting":
      return importRouting(state, providerTarget(sub), action.routing, activate ?? action.activate);
    case "tunnelSetting": {
      const s = action.setting;
      const patch: Partial<AppState["settings"]> =
        s.kind === "mux"
          ? { mux: s.on }
          : s.kind === "fragment"
            ? { fragment: s.on }
            : s.kind === "sniffing"
              ? { domainSniffing: s.on }
              : s.kind === "fragmentPackets"
                ? { fragmentPackets: s.value }
                : s.kind === "fragmentLength"
                  ? { fragmentLength: s.value }
                  : { fragmentDelay: s.value };
      return { ...state, settings: { ...state.settings, ...patch } };
    }
    default:
      return state;
  }
}

/** Mirrors `resolve_changes`: record each answer, audit it, apply what was accepted. */
function resolveSubChange(state: AppState, intent: ResolveIntent): AppState {
  let next = state;
  for (const digest of intent.digests) {
    const sub = next.subscriptions.find((s) => s.id === intent.subId);
    const change = sub?.pendingChanges?.find((p) => p.digest === digest);
    if (!sub || !change) continue;
    const accepted = intent.accept && change.action.kind !== "unsupported";
    const answered: Subscription = {
      ...sub,
      pendingChanges: (sub.pendingChanges ?? []).filter((p) => p.digest !== digest),
      decisions: [
        { key: change.key, digest, accepted, at: intent.at },
        ...(sub.decisions ?? []),
      ].slice(0, DECISIONS_MAX),
      audit: [
        {
          at: intent.at,
          key: change.key,
          outcome: accepted ? ("accepted" as const) : ("rejected" as const),
          summary: change.value,
        },
        ...(sub.audit ?? []),
      ].slice(0, AUDIT_MAX),
    };
    next = { ...next, subscriptions: upsertById(next.subscriptions, answered) };
    if (accepted) next = applyChange(next, answered, change.action, intent.activate);
  }
  return next;
}

/** Apply one intent to `state`, returning a new state. Mirrors Rust `apply_mutation`. */
function applyIntent(state: AppState, intent: MutationIntent): AppState {
  switch (intent.kind) {
    case "upsertProfile": {
      const p = intent.profile as Profile;
      const i = state.profiles.findIndex((x) => x.meta.id === p.meta.id);
      const profiles =
        i >= 0 ? state.profiles.map((x, j) => (j === i ? p : x)) : [p, ...state.profiles];
      return { ...state, profiles };
    }
    case "removeProfiles": {
      const ids = new Set(intent.ids);
      return { ...state, profiles: state.profiles.filter((p) => !ids.has(p.meta.id)) };
    }
    case "cloneProfile": {
      const i = state.profiles.findIndex((p) => p.meta.id === intent.id);
      if (i < 0) return state;
      const copy: Profile = {
        ...state.profiles[i],
        meta: {
          ...state.profiles[i].meta,
          id: intent.newId,
          remarks: intent.remarks,
          subId: null,
        },
      };
      const profiles = [...state.profiles];
      profiles.splice(i + 1, 0, copy);
      return { ...state, profiles };
    }
    case "moveProfiles": {
      const ids = new Set(intent.ids);
      return {
        ...state,
        profiles: state.profiles.map((p) =>
          ids.has(p.meta.id) ? { ...p, meta: { ...p.meta, groupId: intent.groupId } } : p,
        ),
      };
    }
    case "addProfiles":
      return { ...state, profiles: [...(intent.profiles as Profile[]), ...state.profiles] };
    case "deduplicateProfiles":
      return {
        ...state,
        profiles: deduplicate(state.profiles, intent.activeId ?? null, intent.groupId),
      };

    case "addGroup":
      return {
        ...state,
        groups: [
          ...state.groups,
          { id: intent.id, name: intent.name, ...(intent.subId ? { subId: intent.subId } : {}) },
        ],
      };
    case "renameGroup":
      return {
        ...state,
        groups: state.groups.map((g) => (g.id === intent.id ? { ...g, name: intent.name } : g)),
      };
    case "removeGroup":
      if (intent.id === BASE_GROUP_ID) return state;
      return {
        ...state,
        groups: state.groups.filter((g) => g.id !== intent.id),
        profiles: state.profiles.filter((p) => p.meta.groupId !== intent.id),
        subscriptions: state.subscriptions.map((s) =>
          s.groupId === intent.id ? { ...s, groupId: BASE_GROUP_ID } : s,
        ),
      };
    case "reorderGroups": {
      const pinned = state.groups[0]?.id === BASE_GROUP_ID ? 1 : 0;
      if (intent.from < pinned) return state;
      return { ...state, groups: moveItem(state.groups, intent.from, Math.max(pinned, intent.to)) };
    }

    case "upsertSub": {
      // The intent drags the sub's profiles with its group (mirrors the Rust
      // UpsertSub arm): the sub still in state is the old one here.
      const old = state.subscriptions.find((s) => s.id === intent.subscription.id);
      let profiles = state.profiles;
      const newG = intent.subscription.groupId ?? null;
      if (old && newG != null) {
        const oldG = old.groupId ?? null;
        if (oldG != null && oldG !== newG) {
          profiles = profiles.map((p) =>
            p.meta.subId === intent.subscription.id && p.meta.groupId === oldG
              ? { ...p, meta: { ...p.meta, groupId: newG } }
              : p,
          );
        } else if (oldG == null) {
          profiles = profiles.map((p) =>
            p.meta.subId === intent.subscription.id && p.meta.groupId !== newG
              ? { ...p, meta: { ...p.meta, groupId: newG } }
              : p,
          );
        }
      }
      // A group made for the sub follows its renames while it still has the old name.
      const groups =
        old && old.remarks !== intent.subscription.remarks
          ? state.groups.map((g) =>
              g.id === newG && g.subId === old.id && g.name === old.remarks
                ? { ...g, name: intent.subscription.remarks }
                : g,
            )
          : state.groups;
      return {
        ...state,
        groups,
        profiles,
        subscriptions: upsertById(state.subscriptions, intent.subscription),
      };
    }
    case "removeSub": {
      const sub = state.subscriptions.find((s) => s.id === intent.id);
      const group = sub?.groupId ?? null;
      const profiles = state.profiles.filter((p) => {
        if (p.meta.subId !== intent.id) return true;
        if (group != null && p.meta.groupId !== group) return true;
        return false;
      });
      const subscriptions = state.subscriptions.filter((s) => s.id !== intent.id);
      const dropGroup =
        intent.deleteGroup &&
        group != null &&
        ownedGroupIsEmpty({ ...state, profiles, subscriptions }, intent.id, group);
      const groups = state.groups
        .filter((g) => !(dropGroup && g.id === group))
        .map((g) => (g.subId === intent.id ? { id: g.id, name: g.name } : g));
      return removeProviderRouting({ ...state, groups, profiles, subscriptions }, intent.id);
    }
    case "resolveSubChange":
      return resolveSubChange(state, intent);
    case "withdrawProviderConfigs": {
      // The mock picks no successor for a removed active config: the
      // dangling-active fixup unsets it.
      const sub = state.subscriptions.find((s) => s.id === intent.subId);
      if (!sub) return state;
      const gone = new Set(providerConfigsOf(state.profiles, sub));
      return {
        ...state,
        profiles: state.profiles.filter((p) => !gone.has(p)),
        subscriptions: upsertById(state.subscriptions, { ...sub, allowProviderConfigs: false }),
      };
    }

    case "upsertRoutingRule":
      return editBlock(state, intent.blockId, (rules) => upsertById(rules, intent.rule));
    case "removeRoutingRule":
      return editBlock(state, intent.blockId, (rules) => rules.filter((r) => r.id !== intent.id));
    case "reorderRoutingRules":
      return editBlock(state, intent.blockId, (rules) => moveItem(rules, intent.from, intent.to));
    case "importRoutingRules":
      return editBlock(state, intent.blockId, (rules) =>
        intent.mode === "replace" ? intent.rules : [...rules, ...intent.rules],
      );

    case "upsertRuleBlock":
      return { ...state, ruleBlocks: upsertById(state.ruleBlocks, intent.block) };
    case "removeRuleBlock":
      return {
        ...state,
        ruleBlocks: state.ruleBlocks.filter((b) => b.id !== intent.id),
        routes: state.routes.map((r) => ({
          ...r,
          blocks: (r.blocks ?? []).filter((b) => b.blockId !== intent.id),
        })),
      };
    case "upsertRoute":
      return { ...state, routes: upsertRoute(state.routes, intent.route) };
    case "removeRoute":
      return intent.id === DEFAULT_ROUTE_ID
        ? state
        : { ...state, routes: state.routes.filter((r) => r.id !== intent.id) };
    case "importRoutingLink":
      return importRouting(state, linkTarget(intent.groupId), intent.routing, intent.activate);
    case "setProfileRoute":
      return {
        ...state,
        routes: setProfileRoute(state.routes, intent.profileId, intent.routeId ?? null),
      };

    case "upsertAssetFile":
      return { ...state, assetFiles: upsertById(state.assetFiles, intent.asset) };
    case "removeAssetFile":
      return { ...state, assetFiles: state.assetFiles.filter((a) => a.id !== intent.id) };

    case "setSettings":
      return { ...state, settings: intent.settings };
    case "setActive":
      return { ...state, activeId: intent.id ?? null };

    case "importBackup": {
      const incoming = intent.incoming;
      if (intent.mode === "replace") {
        // Current profiles stay; the backup's are added unless one shares an id.
        const known = new Set(state.profiles.map((p) => p.meta.id));
        return {
          ...incoming,
          profiles: [...state.profiles, ...incoming.profiles.filter((p) => !known.has(p.meta.id))],
          settings: mergeSettings(incoming.settings),
        };
      }
      return {
        ...state,
        profiles: [...state.profiles, ...incoming.profiles],
        groups: [...state.groups, ...incoming.groups],
        subscriptions: [...state.subscriptions, ...incoming.subscriptions],
        ...mergeRoutes(state, incoming),
        assetFiles: [...state.assetFiles, ...incoming.assetFiles],
        settings: mergeSettings(incoming.settings),
      };
    }
    case "replaceState":
      return intent.state;
    default:
      return state;
  }
}

/** Null a dangling active id (mirrors `FixupDanglingActiveId`). */
function fixupActiveId(next: AppState): AppState {
  if (next.activeId && !next.profiles.some((p) => p.meta.id === next.activeId)) {
    return { ...next, activeId: null };
  }
  return next;
}

/** Apply an intent and run the write-side chain, mirroring the backend `Mutate`. */
export function applyMutation(prev: AppState, intent: MutationIntent): AppState {
  let next = applyIntent(prev, intent);
  next = fixupActiveId(next);
  next = normalizeRoutes(next, uid);
  return next;
}
