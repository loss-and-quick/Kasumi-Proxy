import type { AppState, Subscription } from "../lib/bridge";
import { profileAddress, profilePort } from "../lib/profile";
import type { Profile } from "../lib/schema";
import { mergeSettings } from "./defaults";
import { profileMatchesFilter, sameProfileIdentity } from "./profile-filter";

function profileDedupKey(p: Profile): string {
  const secret =
    "uuid" in p ? p.uuid : "password" in p ? p.password : "privateKey" in p ? p.privateKey : "";
  return `${p.protocol}|${profileAddress(p)}|${profilePort(p)}|${secret}`;
}

export function deduplicateProfiles(
  profiles: Profile[],
  activeId: string | null,
): { kept: Profile[]; removedCount: number } {
  const seen = new Map<string, Profile>();
  for (const p of profiles) {
    const key = profileDedupKey(p);
    const existing = seen.get(key);
    if (!existing || p.id === activeId) seen.set(key, p);
  }
  const kept = profiles.filter((p) => seen.get(profileDedupKey(p))?.id === p.id);
  return { kept, removedCount: profiles.length - kept.length };
}

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

export function moveProfilesToGroup(
  profiles: Profile[],
  ids: string[],
  groupId: string,
): Profile[] {
  const selected = new Set(ids);
  return profiles.map((profile) => (selected.has(profile.id) ? { ...profile, groupId } : profile));
}

export function removeProfilesByIds(profiles: Profile[], ids: Set<string>): Profile[] {
  return profiles.filter((profile) => !ids.has(profile.id));
}

export function removeProfilesBySubId(profiles: Profile[], subId: string): Profile[] {
  return profiles.filter((profile) => profile.subId !== subId);
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
  const activeProfile = profiles.find((profile) => profile.id === activeId);
  return activeProfile?.subId === subId ? null : activeId;
}

export function mapFetchedSubscriptionProfiles(
  freshRaw: Profile[],
  sub: Subscription,
  filter: RegExp | null,
): Profile[] {
  return freshRaw
    .filter((profile) => profileMatchesFilter(profile, filter))
    .map((profile) => ({ ...profile, subId: sub.id, groupId: sub.groupId ?? profile.groupId }));
}

export function nextActiveIdAfterSubscriptionUpdate(
  current: AppState,
  subId: string,
  freshMapped: Profile[],
): string | null {
  const activeProfile = current.profiles.find((profile) => profile.id === current.activeId);
  const activeAffected = activeProfile?.subId === subId;
  if (!activeAffected) return current.activeId;
  return freshMapped.find((profile) => sameProfileIdentity(profile, activeProfile))?.id ?? null;
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
    profiles: [...current.profiles, ...incoming.profiles],
    groups: [...current.groups, ...incoming.groups],
    subscriptions: [...current.subscriptions, ...incoming.subscriptions],
    routingRules: [...current.routingRules, ...incoming.routingRules],
    assetFiles: [...current.assetFiles, ...incoming.assetFiles],
    settings: mergeSettings({ ...current.settings, ...incoming.settings }),
    activeId: current.activeId,
  };
}
