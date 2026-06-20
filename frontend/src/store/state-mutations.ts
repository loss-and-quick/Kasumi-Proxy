import type { Profile } from "../generated/bindings";
import type { AppState } from "../lib/bridge";
import { mergeSettings } from "./defaults";

export function upsertById<T extends { id: string }>(
  items: T[],
  item: T,
  insertAt: "front" | "back" = "back",
): T[] {
  const index = items.findIndex((x) => x.id === item.id);
  if (index >= 0) {
    const next = [...items];
    next[index] = item;
    return next;
  }
  return insertAt === "front" ? [item, ...items] : [...items, item];
}

export function insertAfterId<T extends { id: string }>(items: T[], afterId: string, item: T): T[] {
  const index = items.findIndex((x) => x.id === afterId);
  if (index < 0) return items;
  const next = [...items];
  next.splice(index + 1, 0, item);
  return next;
}

export function moveItemByIndex<T>(items: T[], from: number, to: number): T[] {
  if (from === to || from < 0 || to < 0 || from >= items.length || to >= items.length) return items;
  const next = [...items];
  const [item] = next.splice(from, 1);
  next.splice(to, 0, item);
  return next;
}

// Profiles key their identity on `meta.id` (nested model), so they get their own
// upsert/insert instead of the generic root-`id` helpers above.
export function upsertProfileFront(profiles: Profile[], p: Profile): Profile[] {
  const index = profiles.findIndex((x) => x.meta.id === p.meta.id);
  if (index >= 0) {
    const next = [...profiles];
    next[index] = p;
    return next;
  }
  return [p, ...profiles];
}

export function insertProfileAfter(profiles: Profile[], afterId: string, p: Profile): Profile[] {
  const index = profiles.findIndex((x) => x.meta.id === afterId);
  if (index < 0) return profiles;
  const next = [...profiles];
  next.splice(index + 1, 0, p);
  return next;
}

export function moveProfilesToGroup(
  profiles: Profile[],
  ids: string[],
  groupId: string,
): Profile[] {
  const selected = new Set(ids);
  return profiles.map((profile) =>
    selected.has(profile.meta.id) ? { ...profile, meta: { ...profile.meta, groupId } } : profile,
  );
}

export function removeProfilesByIds(profiles: Profile[], ids: Set<string>): Profile[] {
  return profiles.filter((profile) => !ids.has(profile.meta.id));
}

export function activeIdAfterProfileRemoval(
  activeId: string | null,
  removedIds: Set<string>,
): string | null {
  return activeId && removedIds.has(activeId) ? null : activeId;
}

export function activeIdAfterSubRemoval(
  profiles: Profile[],
  activeId: string | null,
  subId: string,
): string | null {
  const activeProfile = profiles.find((profile) => profile.meta.id === activeId);
  return activeProfile?.meta.subId === subId ? null : activeId;
}

export function mergeBackupState(
  current: AppState,
  incoming: AppState,
  mode: "merge" | "replace",
): AppState {
  if (mode === "replace") {
    // Keep current profiles — backups no longer include them
    return { ...incoming, profiles: current.profiles, settings: mergeSettings(incoming.settings) };
  }

  return {
    ...current,
    profiles: [...current.profiles, ...incoming.profiles],
    groups: [...current.groups, ...incoming.groups],
    subscriptions: [...current.subscriptions, ...incoming.subscriptions],
    routingRules: [...current.routingRules, ...incoming.routingRules],
    assetFiles: [...current.assetFiles, ...incoming.assetFiles],
    settings: mergeSettings({ ...current.settings, ...incoming.settings }),
    activeId: current.activeId,
  };
}
