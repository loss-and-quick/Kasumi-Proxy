import { describe, expect, it } from "vitest";
import type { Group, Profile } from "../../../generated/bindings";
import { planLocateActive } from "../locate";

function mockProfile({
  id = "p-1",
  remarks = "Fast Node",
  groupId = "g-1",
}: {
  id?: string;
  remarks?: string;
  groupId?: string;
}): Profile {
  return {
    protocol: "shadowsocks",
    meta: {
      id,
      remarks,
      groupId,
    },
    endpoint: { address: "1.2.3.4", port: 8388 },
    password: "secret",
  };
}

const mockGroups: Group[] = [
  { id: "g-1", name: "Default" },
  { id: "g-2", name: "Backup" },
];

describe("planLocateActive", () => {
  it("returns null when no active profile exists", () => {
    const plan = planLocateActive({
      activeProfile: null,
      currentGroupFilter: "all",
      currentQuery: "",
      groups: mockGroups,
    });
    expect(plan).toBeNull();
  });

  it("plans locate with no filter changes when profile is visible in 'all' with no query", () => {
    const p = mockProfile({ id: "p-1", groupId: "g-1" });
    const plan = planLocateActive({
      activeProfile: p,
      currentGroupFilter: "all",
      currentQuery: "",
      groups: mockGroups,
    });
    expect(plan).toEqual({
      targetId: "p-1",
      nextGroupFilter: undefined,
      nextQuery: undefined,
      reason: undefined,
    });
  });

  it("switches group when current group filter hides active profile", () => {
    const p = mockProfile({ id: "p-1", groupId: "g-1" });
    const plan = planLocateActive({
      activeProfile: p,
      currentGroupFilter: "g-2",
      currentQuery: "",
      groups: mockGroups,
    });
    expect(plan).toEqual({
      targetId: "p-1",
      nextGroupFilter: "g-1",
      nextQuery: undefined,
      reason: "group_changed",
    });
  });

  it("falls back to 'all' if active profile's group does not exist in groups", () => {
    const p = mockProfile({ id: "p-1", groupId: "deleted-g" });
    const plan = planLocateActive({
      activeProfile: p,
      currentGroupFilter: "g-2",
      currentQuery: "",
      groups: mockGroups,
    });
    expect(plan).toEqual({
      targetId: "p-1",
      nextGroupFilter: "all",
      nextQuery: undefined,
      reason: "group_changed",
    });
  });

  it("preserves search query when it matches the active profile", () => {
    const p = mockProfile({ id: "p-1", remarks: "Tokyo VLESS", groupId: "g-1" });
    const plan = planLocateActive({
      activeProfile: p,
      currentGroupFilter: "all",
      currentQuery: "tokyo",
      groups: mockGroups,
    });
    expect(plan).toEqual({
      targetId: "p-1",
      nextGroupFilter: undefined,
      nextQuery: undefined,
      reason: undefined,
    });
  });

  it("clears search query when it excludes the active profile", () => {
    const p = mockProfile({ id: "p-1", remarks: "Tokyo VLESS", groupId: "g-1" });
    const plan = planLocateActive({
      activeProfile: p,
      currentGroupFilter: "all",
      currentQuery: "london",
      groups: mockGroups,
    });
    expect(plan).toEqual({
      targetId: "p-1",
      nextGroupFilter: undefined,
      nextQuery: "",
      reason: "search_cleared",
    });
  });

  it("updates both group and query when both exclude the active profile", () => {
    const p = mockProfile({ id: "p-1", remarks: "Tokyo VLESS", groupId: "g-1" });
    const plan = planLocateActive({
      activeProfile: p,
      currentGroupFilter: "g-2",
      currentQuery: "london",
      groups: mockGroups,
    });
    expect(plan).toEqual({
      targetId: "p-1",
      nextGroupFilter: "g-1",
      nextQuery: "",
      reason: "both_changed",
    });
  });
});
