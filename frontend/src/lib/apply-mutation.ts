// ============================================================
// src/lib/apply-mutation.ts
// Dev-only TS port of the backend's `kasumi_core::mutate::apply_mutation` plus its
// write-side middleware chain (FixupDanglingActiveId). The real
// transports round-trip a MutationIntent to the Rust backend and render the
// canonical AppState it returns; the mock bridge has no backend, so it applies the
// same intent locally here. Production never imports this — it is the mock's
// stand-in for the one source of truth that lives in Rust. Keep it in sync with
// `crates/kasumi-core/src/mutate.rs`.
// ============================================================

import type { Profile } from "../generated/bindings";
import { mergeSettings } from "../store/defaults";
import type { AppState, MutationIntent } from "./bridge";

const BASE_GROUP_ID = "g-main";

function dedupKey(p: Profile): string {
  // Narrow across the protocol union by key presence (mirrors profile-utils'
  // accessors) instead of casting the shape open: uuid protocols first, then the
  // password ones, else no secret.
  const secret = "uuid" in p ? p.uuid : "password" in p ? (p.password ?? "") : "";
  const ep = "endpoint" in p ? p.endpoint : undefined;
  return `${p.protocol}|${ep?.address ?? ""}|${ep?.port ?? "null"}|${secret}`;
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
      return { ...state, groups: [...state.groups, { id: intent.id, name: intent.name }] };
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
      return {
        ...state,
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
      return {
        ...state,
        profiles,
        subscriptions: state.subscriptions.filter((s) => s.id !== intent.id),
      };
    }

    case "upsertRoutingRule":
      return { ...state, routingRules: upsertById(state.routingRules, intent.rule) };
    case "removeRoutingRule":
      return { ...state, routingRules: state.routingRules.filter((r) => r.id !== intent.id) };
    case "reorderRoutingRules":
      return { ...state, routingRules: moveItem(state.routingRules, intent.from, intent.to) };
    case "importRoutingRules":
      return {
        ...state,
        routingRules:
          intent.mode === "replace" ? intent.rules : [...state.routingRules, ...intent.rules],
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
        return {
          ...incoming,
          profiles: state.profiles,
          settings: mergeSettings(incoming.settings),
        };
      }
      return {
        ...state,
        profiles: [...state.profiles, ...incoming.profiles],
        groups: [...state.groups, ...incoming.groups],
        subscriptions: [...state.subscriptions, ...incoming.subscriptions],
        routingRules: [...state.routingRules, ...incoming.routingRules],
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
  return next;
}
