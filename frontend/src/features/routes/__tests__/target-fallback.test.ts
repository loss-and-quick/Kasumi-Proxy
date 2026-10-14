import { describe, expect, it } from "vitest";
import type { CoreResolution } from "../../../generated/bindings";
import { translate } from "../../../i18n";
import { targetFallback, targetFallbackText } from "../labels";

const resolutions: Record<string, CoreResolution> = {
  active: { resolved: "xray", forced: null },
  tuic: {
    resolved: "sing-box",
    forced: "sing-box",
    ruleTargetFallback: { xray: { kind: "singBoxOnly" } },
  },
  custom: {
    resolved: "xray",
    forced: "xray",
    ruleTargetFallback: { xray: { kind: "customConfig" }, "sing-box": { kind: "customConfig" } },
  },
  xhttp: {
    resolved: "xray",
    forced: "xray",
    conflict: { kind: "unpinnedInsecureTls" },
    ruleTargetFallback: {
      xray: { kind: "cantStart", conflict: { kind: "unpinnedInsecureTls" } },
    },
  },
};

const t: Parameters<typeof targetFallbackText>[0] = (key, vars) => translate("en", key, vars);

describe("targetFallback", () => {
  it("reads the fallback for the active profile's core", () => {
    expect(targetFallback("tuic", "active", resolutions)).toEqual({
      core: "xray",
      fallback: { kind: "singBoxOnly" },
    });
    const onSingBox = { ...resolutions, active: { resolved: "sing-box", forced: null } };
    expect(targetFallback("tuic", "active", onSingBox as typeof resolutions)).toBeNull();
  });

  it("stays quiet for built-ins, deleted profiles, the active profile and no active one", () => {
    for (const tag of ["proxy", "direct", "gone", "active"]) {
      expect(targetFallback(tag, "active", resolutions)).toBeNull();
    }
    expect(targetFallback("custom", null, resolutions)).toBeNull();
  });

  it("says where the traffic goes and why", () => {
    const text = (tag: string) => {
      const why = targetFallback(tag, "active", resolutions);
      return why && targetFallbackText(t, why);
    };
    expect(text("tuic")).toContain("on xray");
    expect(text("custom")).toContain("custom config");
    expect(text("xhttp")).toContain("“Allow insecure”");
    for (const tag of ["tuic", "custom", "xhttp"]) expect(text(tag)).toContain("active proxy");
  });
});
