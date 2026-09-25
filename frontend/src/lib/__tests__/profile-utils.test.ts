import { describe, expect, it } from "vitest";
import type { Profile } from "../../generated/bindings";
import { chainCandidates, emptyProfile } from "../profile-utils";

const profile = (
  id: string,
  via: string | null = null,
  protocol: "trojan" | "custom" = "trojan",
) => {
  const p = emptyProfile(protocol);
  p.meta = { ...p.meta, id, remarks: id, via };
  return p;
};
const ids = (ps: Profile[]) => ps.map((p) => p.meta.id);

describe("chainCandidates", () => {
  it("offers every other profile when nothing chains through self", () => {
    const all = [profile("a"), profile("b"), profile("c")];
    expect(ids(chainCandidates(all, all[0]))).toEqual(["b", "c"]);
  });

  it("drops profiles whose chain passes through self", () => {
    // c -> b -> a: a can't dial through b or c without a loop.
    const all = [profile("a"), profile("b", "a"), profile("c", "b"), profile("d")];
    expect(ids(chainCandidates(all, all[0]))).toEqual(["d"]);
    expect(ids(chainCandidates(all, all[2]))).toEqual(["a", "b", "d"]);
  });

  it("skips custom profiles and survives an existing loop", () => {
    const all = [
      profile("a"),
      profile("x", "y"),
      profile("y", "x"),
      profile("raw", null, "custom"),
    ];
    expect(ids(chainCandidates(all, all[0]))).toEqual(["x", "y"]);
  });
});
