// ============================================================
// features/profiles/labels.ts
// How a profile is named where it is referenced rather than listed (a rule's
// target, a route's final outbound, a chain hop). Provider subscriptions ship
// many profiles under one name, so a name shared with other profiles gets just
// enough to tell them apart: the group, then the protocol, then host:port.
// ============================================================

import { useMemo } from "react";
import type { Group, Profile } from "../../generated/bindings";
import { profileEndpointLabel } from "../../lib/profile-utils";
import { useAppStore } from "../../store/useAppStore";

export type ProfileLabel = { name: string; detail: string[] };

/** Labels by profile id; an id missing here points at a deleted profile. */
export type ProfileLabels = ReadonlyMap<string, ProfileLabel>;

const displayName = (p: Profile) => p.meta.remarks.trim() || profileEndpointLabel(p);

export function profileLabels(
  profiles: readonly Profile[],
  groups: readonly Pick<Group, "id" | "name">[],
): ProfileLabels {
  const groupName = new Map(groups.map((g) => [g.id, g.name]));
  // Each step narrows the namesakes to those sharing this profile's value, and
  // speaks only when that value differs among them.
  const steps: { key: (p: Profile) => string; show: (p: Profile) => string | undefined }[] = [
    { key: (p) => p.meta.groupId, show: (p) => groupName.get(p.meta.groupId) },
    { key: (p) => p.protocol, show: (p) => p.protocol },
    { key: profileEndpointLabel, show: profileEndpointLabel },
  ];

  const byName = new Map<string, Profile[]>();
  for (const p of profiles) {
    const name = displayName(p);
    const same = byName.get(name);
    if (same) same.push(p);
    else byName.set(name, [p]);
  }

  const labels = new Map<string, ProfileLabel>();
  for (const [name, namesakes] of byName) {
    for (const p of namesakes) {
      const detail: string[] = [];
      let peers = namesakes;
      for (const step of steps) {
        if (peers.length < 2) break;
        const own = step.key(p);
        if (peers.every((q) => step.key(q) === own)) continue;
        const shown = step.show(p);
        if (shown) detail.push(shown);
        peers = peers.filter((q) => step.key(q) === own);
      }
      labels.set(p.meta.id, { name, detail });
    }
  }
  return labels;
}

/** "Finland (Gosha 2 · hysteria2)", or just the name when it is unique. */
export const profileLabelText = ({ name, detail }: ProfileLabel): string =>
  detail.length ? `${name} (${detail.join(" · ")})` : name;

/** Labels for every profile in the store. */
export function useProfileLabels(): ProfileLabels {
  const profiles = useAppStore((s) => s.profiles);
  const groups = useAppStore((s) => s.groups);
  return useMemo(() => profileLabels(profiles, groups), [profiles, groups]);
}

/** A referenced profile's label, or `deleted` when no profile has that id any more. */
export function profileRefText(labels: ProfileLabels, id: string, deleted: string): string {
  const label = labels.get(id);
  return label ? profileLabelText(label) : deleted;
}
