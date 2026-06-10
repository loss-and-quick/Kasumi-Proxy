import { describe, expect, it } from "vitest";
import { EMPTY_SETTINGS } from "../../store/defaults";
import { activeConfigChanged, buildCoreConfig } from "../core-config";
import { emptyProfile, type Profile } from "../schema";

function vless(overrides: Partial<Extract<Profile, { protocol: "vless" }>>): Profile {
  return { ...(emptyProfile("vless") as Extract<Profile, { protocol: "vless" }>), ...overrides };
}

describe("buildCoreConfig / activeConfigChanged", () => {
  it("reports no change when only volatile fields (id) differ", () => {
    const base = { remarks: "Node", address: "ex.com", port: 443, uuid: "u-1" } as const;
    const a = buildCoreConfig(vless({ id: "p1", ...base }), EMPTY_SETTINGS, [], []);
    const b = buildCoreConfig(vless({ id: "p2", ...base }), EMPTY_SETTINGS, [], []);
    expect(activeConfigChanged(a, b)).toBe(false);
  });

  it("reports a change when the port differs", () => {
    const base = { remarks: "Node", address: "ex.com", uuid: "u-1" } as const;
    const a = buildCoreConfig(vless({ id: "p1", port: 443, ...base }), EMPTY_SETTINGS, [], []);
    const b = buildCoreConfig(vless({ id: "p2", port: 8443, ...base }), EMPTY_SETTINGS, [], []);
    expect(activeConfigChanged(a, b)).toBe(true);
  });
});
