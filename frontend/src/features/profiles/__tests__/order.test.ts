import { describe, expect, it } from "vitest";
import type { Profile } from "../../../generated/bindings";
import { orderProfiles } from "../order";

const p = (id: string, remarks: string, groupId: string) =>
  ({ meta: { id, remarks, groupId } }) as unknown as Profile;

describe("orderProfiles", () => {
  const groups = [{ id: "g-main" }, { id: "g2" }];
  // Stored newest first, groups mixed: the order a subscription refresh leaves.
  const stored = [p("c", "Charlie", "g2"), p("b", "Bravo", "g-main"), p("a", "Alpha", "g2")];

  it("groups in group order and sorts by name inside each, like the Profiles screen", () => {
    expect(orderProfiles(stored, groups, "name", {}).map((x) => x.meta.id)).toEqual([
      "b",
      "a",
      "c",
    ]);
  });

  it("by ping puts the fastest first inside a group and the untested last", () => {
    const pings = { a: { ping: 300 }, c: { ping: 40 } };
    expect(orderProfiles(stored, groups, "ping", pings).map((x) => x.meta.id)).toEqual([
      "b",
      "c",
      "a",
    ]);
  });
});
