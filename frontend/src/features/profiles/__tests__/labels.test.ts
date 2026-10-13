import { describe, expect, it } from "vitest";
import type { Profile, Protocol } from "../../../generated/bindings";
import { profileLabels, profileLabelText, profileRefText } from "../labels";

const p = (id: string, remarks: string, groupId: string, protocol: Protocol, host: string) =>
  ({
    protocol,
    meta: { id, remarks, groupId },
    endpoint: { address: host, port: 443 },
  }) as unknown as Profile;

const groups = [
  { id: "g1", name: "Gosha 1" },
  { id: "g2", name: "Gosha 2" },
];

const textOf = (profiles: Profile[]) => {
  const labels = profileLabels(profiles, groups);
  return profiles.map((x) => profileRefText(labels, x.meta.id, "deleted"));
};

describe("profileLabels", () => {
  it("leaves a unique name as it is", () => {
    expect(
      textOf([p("a", "Finland", "g1", "vless", "a.fi"), p("b", "Sweden", "g1", "vless", "b.se")]),
    ).toEqual(["Finland", "Sweden"]);
  });

  it("tells namesakes in different groups apart by the group", () => {
    expect(
      textOf([p("a", "Finland", "g1", "vless", "a.fi"), p("b", "Finland", "g2", "vless", "b.fi")]),
    ).toEqual(["Finland (Gosha 1)", "Finland (Gosha 2)"]);
  });

  it("adds the protocol when the group is shared", () => {
    expect(
      textOf([
        p("a", "Finland", "g2", "hysteria2", "a.fi"),
        p("b", "Finland", "g2", "vless", "a.fi"),
        p("c", "Finland", "g1", "vless", "c.fi"),
      ]),
    ).toEqual(["Finland (Gosha 2 · hysteria2)", "Finland (Gosha 2 · vless)", "Finland (Gosha 1)"]);
  });

  it("adds host:port when name, group and protocol are all shared", () => {
    expect(
      textOf([
        p("a", "Finland", "g1", "vless", "fi1.example"),
        p("b", "Finland", "g1", "vless", "fi2.example"),
      ]),
    ).toEqual(["Finland (fi1.example:443)", "Finland (fi2.example:443)"]);
  });

  it("names an id with no profile behind it as deleted", () => {
    const labels = profileLabels([p("a", "Finland", "g1", "vless", "a.fi")], groups);
    expect(profileRefText(labels, "gone", "Deleted profile")).toBe("Deleted profile");
    expect(profileLabelText({ name: "Finland", detail: [] })).toBe("Finland");
  });
});
