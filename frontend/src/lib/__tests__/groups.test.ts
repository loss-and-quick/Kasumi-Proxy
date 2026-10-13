import { describe, expect, it } from "vitest";
import type { Profile } from "../../generated/bindings";
import type { Group, Subscription } from "../bridge";
import {
  groupChoiceReady,
  groupNamed,
  hostOf,
  ownedGroupLeftEmpty,
  providerConfigsOf,
} from "../groups";
import { emptyProfile } from "../profile-utils";

const profile = (groupId: string, subId: string | null): Profile => {
  const p = emptyProfile("vless", groupId);
  return { ...p, meta: { ...p.meta, subId } } as Profile;
};
const sub = (id: string, groupId: string) => ({ id, groupId }) as Subscription;

describe("groups", () => {
  it("defaults a subscription's name to its host", () => {
    expect(hostOf(" https://sub.example.com/x?token=1 ")).toBe("sub.example.com");
    expect(hostOf("not a url")).toBe("not a url");
  });

  it("needs a name, typed or suggested, for a new group", () => {
    expect(groupChoiceReady({ id: "g-main" })).toBe(true);
    expect(groupChoiceReady({ newName: "  " })).toBe(false);
    expect(groupChoiceReady({ newName: "" }, "example.com")).toBe(true);
  });

  it("finds a group by name regardless of case and spacing", () => {
    const groups: Group[] = [{ id: "g1", name: "Provider" }];
    expect(groupNamed(groups, " provider ")?.id).toBe("g1");
    expect(groupNamed(groups, "")).toBeUndefined();
  });

  it("offers to drop a subscription's group only when nothing else is in it", () => {
    const groups: Group[] = [
      { id: "g-main", name: "Main" },
      { id: "gs", name: "S", subId: "s1" },
    ];
    const base = { groups, profiles: [profile("gs", "s1")], subscriptions: [sub("s1", "gs")] };
    expect(ownedGroupLeftEmpty(base, "s1")?.id).toBe("gs");
    // A hand-added profile stays, so the group stays.
    expect(
      ownedGroupLeftEmpty({ ...base, profiles: [...base.profiles, profile("gs", null)] }, "s1"),
    ).toBeUndefined();
    // Another subscription still fetches into it.
    expect(
      ownedGroupLeftEmpty(
        { ...base, subscriptions: [...base.subscriptions, sub("s2", "gs")] },
        "s1",
      ),
    ).toBeUndefined();
  });

  it("counts only the provider configs still in the subscription's group", () => {
    const config = (id: string, groupId: string, origin: "provider" | "user"): Profile => {
      const p = emptyProfile("custom", groupId);
      return { ...p, origin, meta: { ...p.meta, id, subId: "s1" } } as Profile;
    };
    const profiles = [
      config("a", "gs", "provider"),
      config("moved", "g-main", "provider"),
      config("own", "gs", "user"),
      profile("gs", "s1"),
    ];
    const ids = (groupId: string | null) =>
      providerConfigsOf(profiles, { id: "s1", groupId }).map((p) => p.meta.id);
    expect(ids("gs")).toEqual(["a"]);
    expect(ids(null)).toEqual(["a", "moved"]);
    expect(providerConfigsOf(profiles, { id: "s2", groupId: "gs" })).toEqual([]);
  });
});
