import { describe, expect, it } from "vitest";
import type { RoutingRule } from "../../../generated/bindings";
import { isRedundantCatchAll } from "../helpers";

const rule = (patch: Partial<RoutingRule>): RoutingRule => ({
  id: "r1",
  remarks: "",
  enabled: true,
  outboundTag: "proxy",
  ...patch,
});

describe("isRedundantCatchAll", () => {
  const catchAll = (patch: Partial<RoutingRule> = {}) => rule({ port: "0-65535", ...patch });

  it("flags a trailing catch-all that only repeats the final proxy fallback", () => {
    expect(isRedundantCatchAll([rule({ ip: ["geoip:ru"] }), catchAll()], 1)).toBe(true);
  });

  it("ignores one that still shadows an enabled rule below", () => {
    expect(isRedundantCatchAll([catchAll(), rule({ ip: ["geoip:ru"] })], 0)).toBe(false);
  });

  it("looks past disabled rules below", () => {
    expect(isRedundantCatchAll([catchAll(), rule({ ip: ["geoip:ru"], enabled: false })], 0)).toBe(
      true,
    );
  });

  it("ignores a catch-all routed anywhere but the proxy", () => {
    expect(isRedundantCatchAll([catchAll({ outboundTag: "direct" })], 0)).toBe(false);
    expect(isRedundantCatchAll([catchAll({ outboundTag: "block" })], 0)).toBe(false);
  });

  it("ignores an index that points at no rule", () => {
    expect(isRedundantCatchAll([catchAll()], -1)).toBe(false);
    expect(isRedundantCatchAll([], 0)).toBe(false);
  });
});
