import { describe, expect, it } from "vitest";
import type { CoreResolution } from "../../../generated/bindings";
import { translate } from "../../../i18n";
import { targetFallback, targetFallbackText, targetIgnored, targetIgnoredText } from "../labels";

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
const formatters = { formatList: (v: Iterable<string>) => [...v].join(", ") } as Parameters<
  typeof targetIgnoredText
>[1];

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

describe("targetIgnored", () => {
  const withIgnored: Record<string, CoreResolution> = {
    active: { resolved: "sing-box", forced: null },
    kcp: { resolved: "xray", forced: "xray", xrayOnlySettings: ["kcp", "vlessEncryption"] },
    plain: { resolved: "xray", forced: null },
  };

  it("lists what sing-box drops when it builds the target", () => {
    expect(targetIgnored("kcp", "active", withIgnored)).toEqual(["kcp", "vlessEncryption"]);
    expect(targetIgnored("plain", "active", withIgnored)).toEqual([]);
    const text = targetIgnoredText(t, formatters, ["kcp", "vlessEncryption"]);
    expect(text).toContain("sing-box these settings are ignored");
    expect(text).toContain("mKCP transport");
    expect(text).toContain("VLESS encryption");
  });

  it("stays quiet when xray builds the target or the target is the proxy", () => {
    const onXray = { ...withIgnored, active: { resolved: "xray", forced: null } };
    expect(targetIgnored("kcp", "active", onXray as typeof withIgnored)).toEqual([]);
    expect(targetIgnored("active", "active", withIgnored)).toEqual([]);
    expect(targetIgnored("kcp", null, withIgnored)).toEqual([]);
  });
});
