// ============================================================
// src/lib/groups.ts
// Picking a group in a form, where the group may not exist yet.
// ============================================================

import type { AppState, Group } from "./bridge";

export const BASE_GROUP_ID = "g-main";

/** A form's group: one that exists, or one to create when the form is saved.
 *  Creating on save (not when typed) leaves no empty group behind a cancelled form. */
export type GroupChoice = { id: string } | { newName: string };

/** Whether a form can save this choice: a new group needs a name, typed or
 *  suggested. */
export function groupChoiceReady(choice: GroupChoice, suggestedName = ""): boolean {
  return "id" in choice || !!(choice.newName.trim() || suggestedName.trim());
}

/** The group a pending name would land in: an existing one with the same name
 *  (case-insensitive), so saving twice doesn't make twins. */
export function groupNamed(groups: Group[], name: string): Group | undefined {
  const key = name.trim().toLocaleLowerCase();
  return key ? groups.find((g) => g.name.trim().toLocaleLowerCase() === key) : undefined;
}

/** A subscription's default name: the host it's fetched from. */
export function hostOf(url: string): string {
  const trimmed = url.trim();
  try {
    return new URL(trimmed).hostname || trimmed;
  } catch {
    return trimmed;
  }
}

/** Whether removing subscription `subId` would leave the group made for it empty,
 *  so it can go too. Mirrors the backend's `owned_group_is_empty`, applied to the
 *  state after the subscription's own profiles are pruned. */
export function ownedGroupLeftEmpty(
  state: Pick<AppState, "groups" | "profiles" | "subscriptions">,
  subId: string,
): Group | undefined {
  const sub = state.subscriptions.find((s) => s.id === subId);
  const group = state.groups.find((g) => g.id === sub?.groupId && g.subId === subId);
  if (!group || group.id === BASE_GROUP_ID) return undefined;
  const othersInGroup = state.profiles.some(
    (p) => p.meta.groupId === group.id && p.meta.subId !== subId,
  );
  const sharedWithSub = state.subscriptions.some((s) => s.id !== subId && s.groupId === group.id);
  return othersInGroup || sharedWithSub ? undefined : group;
}
