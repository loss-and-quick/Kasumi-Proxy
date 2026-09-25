import { describe, expect, it } from "vitest";
import { DEFAULT_CORE_BY_PROTOCOL, PROTOCOL_OPTS } from "../../../generated/defaults";
import { applyCoresPreset, coresPreset, LOCKED_CORE_PROTOCOLS } from "../helpers";

describe("coresPreset", () => {
  it("reads an empty or missing map as the default preset", () => {
    expect(coresPreset(undefined)).toBe("default");
    expect(coresPreset({})).toBe("default");
  });

  it("reads explicit overrides equal to the defaults as the default preset", () => {
    expect(coresPreset({ ...DEFAULT_CORE_BY_PROTOCOL })).toBe("default");
  });

  it("round-trips every non-custom preset", () => {
    for (const preset of ["default", "xray", "sing-box"] as const) {
      expect(coresPreset(applyCoresPreset(preset))).toBe(preset);
    }
  });

  it("reports a mixed map as custom", () => {
    const map = { ...applyCoresPreset("xray"), vless: "sing-box" as const };
    expect(coresPreset(map)).toBe("custom");
  });

  it("ignores overrides on locked protocols", () => {
    expect(coresPreset({ hysteria2: "xray", custom: "sing-box" })).toBe("default");
  });
});

describe("applyCoresPreset", () => {
  it("never touches locked protocols", () => {
    for (const preset of ["xray", "sing-box"] as const) {
      const map = applyCoresPreset(preset);
      for (const p of LOCKED_CORE_PROTOCOLS) expect(map[p]).toBeUndefined();
      const pinned = PROTOCOL_OPTS.filter((p) => !LOCKED_CORE_PROTOCOLS.includes(p));
      for (const p of pinned) expect(map[p]).toBe(preset);
    }
  });
});
