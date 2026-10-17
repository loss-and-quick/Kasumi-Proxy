// ============================================================
// features/profiles/locate.ts
// Pure helper to plan revealing the currently active profile.
// Determines whether groupFilter or search query need to be
// updated so the active card is rendered in the list.
// ============================================================

import type { Group, Profile } from "../../generated/bindings";
import { fuzzyScore, NO_MATCH } from "../../lib/fuzzy";
import { profileSearchText } from "../../lib/profile-utils";

export type LocateReason = "group_changed" | "search_cleared" | "both_changed";

export type LocatePlan = {
  targetId: string;
  nextGroupFilter?: string;
  nextQuery?: string;
  reason?: LocateReason;
};

export function planLocateActive({
  activeProfile,
  currentGroupFilter,
  currentQuery,
  groups,
}: {
  activeProfile: Profile | null | undefined;
  currentGroupFilter: string;
  currentQuery: string;
  groups: Group[];
}): LocatePlan | null {
  if (!activeProfile) {
    return null;
  }

  const targetId = activeProfile.meta.id;
  const targetGroup = activeProfile.meta.groupId;
  let nextGroupFilter: string | undefined;

  if (currentGroupFilter !== "all" && currentGroupFilter !== targetGroup) {
    // Reveal the active node by switching to its group if that group exists,
    // or to "all" if the group was deleted or missing.
    const groupExists = groups.some((g) => g.id === targetGroup);
    nextGroupFilter = groupExists ? targetGroup : "all";
  }

  let nextQuery: string | undefined;
  if (currentQuery.trim()) {
    const text = profileSearchText(activeProfile);
    const matches = fuzzyScore(text, currentQuery) > NO_MATCH;
    if (!matches) {
      nextQuery = "";
    }
  }

  const groupChanged = nextGroupFilter !== undefined;
  const searchCleared = nextQuery !== undefined;

  let reason: LocateReason | undefined;
  if (groupChanged && searchCleared) {
    reason = "both_changed";
  } else if (groupChanged) {
    reason = "group_changed";
  } else if (searchCleared) {
    reason = "search_cleared";
  }

  return {
    targetId,
    nextGroupFilter,
    nextQuery,
    reason,
  };
}
