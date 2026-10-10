// ============================================================
// features/profiles/order.ts
// The order the Profiles screen shows profiles in: group by group, and
// inside a group by the sort picked there (name, or ping). Other screens that
// list profiles use the same order, so a profile is found where it is
// expected.
// ============================================================

import { useMemo } from "react";
import type { Group, Profile } from "../../generated/bindings";
import { type ProfileTest, useAppStore } from "../../store/useAppStore";
import type { SortMode } from "./types";
import { useProfilesView } from "./viewState";

export function sortProfiles<P extends Pick<Profile, "meta">>(
  profiles: P[],
  sort: SortMode,
  testResults: Record<string, Pick<ProfileTest, "ping">>,
): P[] {
  const pingRank = (id: string) => {
    const p = testResults[id]?.ping;
    return p != null && p >= 0 ? p : Number.MAX_SAFE_INTEGER;
  };
  return [...profiles].sort((left, right) => {
    const byName = left.meta.remarks.localeCompare(right.meta.remarks);
    return sort === "ping" ? pingRank(left.meta.id) - pingRank(right.meta.id) || byName : byName;
  });
}

/** Sorted, then grouped in the order of `groups` (profiles of a missing group last). */
export function orderProfiles<P extends Pick<Profile, "meta">>(
  profiles: P[],
  groups: Pick<Group, "id">[],
  sort: SortMode,
  testResults: Record<string, Pick<ProfileTest, "ping">>,
): P[] {
  const rank = new Map(groups.map((g, i) => [g.id, i]));
  const at = (p: P) => rank.get(p.meta.groupId) ?? groups.length;
  // Array.sort is stable, so the sort above survives within each group.
  return sortProfiles(profiles, sort, testResults).sort((a, b) => at(a) - at(b));
}

/** Every profile, in the Profiles screen's order. */
export function useOrderedProfiles(): Profile[] {
  const profiles = useAppStore((s) => s.profiles);
  const groups = useAppStore((s) => s.groups);
  const testResults = useAppStore((s) => s.testResults);
  const sort = useProfilesView((s) => s.sort);
  return useMemo(
    () => orderProfiles(profiles, groups, sort, testResults),
    [profiles, groups, sort, testResults],
  );
}
