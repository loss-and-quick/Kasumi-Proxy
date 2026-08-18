import { describe, expect, it } from "vitest";
import type { RoutingRule } from "../../../generated/bindings";
import { isCatchAllRule, isRedundantCatchAll } from "../helpers";

const rule = (patch: Partial<RoutingRule>): RoutingRule => ({
  id: "r1",
  remarks: "",
  enabled: true,
  outboundTag: "proxy",
  ...patch,
});

describe("isCatchAllRule", () => {
  it("flags a full port range with no other match field", () => {
    expect(isCatchAllRule(rule({ port: "0-65535" }))).toBe(true);
    expect(isCatchAllRule(rule({ port: "1-65535" }))).toBe(true);
  });

  it("flags a full range assembled from several parts", () => {
    expect(isCatchAllRule(rule({ port: "1-1000,1001-65535" }))).toBe(true);
  });

  it("ignores a range with a gap or a short tail", () => {
    expect(isCatchAllRule(rule({ port: "1-1000,1002-65535" }))).toBe(false);
    expect(isCatchAllRule(rule({ port: "0-65534" }))).toBe(false);
    expect(isCatchAllRule(rule({ port: "443" }))).toBe(false);
  });

  it("ignores rules that also match on domain, ip or protocol", () => {
    expect(isCatchAllRule(rule({ port: "0-65535", domain: ["geosite:private"] }))).toBe(false);
    expect(isCatchAllRule(rule({ port: "0-65535", ip: ["geoip:ru"] }))).toBe(false);
    expect(isCatchAllRule(rule({ port: "0-65535", protocol: ["bittorrent"] }))).toBe(false);
  });

  it("treats a single-network rule as narrower than catch-all", () => {
    expect(isCatchAllRule(rule({ port: "0-65535", network: "udp" }))).toBe(false);
    expect(isCatchAllRule(rule({ port: "0-65535", network: "tcp,udp" }))).toBe(true);
  });

  it("ignores disabled rules and rules the backend drops for having no match field", () => {
    expect(isCatchAllRule(rule({ port: "0-65535", enabled: false }))).toBe(false);
    expect(isCatchAllRule(rule({}))).toBe(false);
    expect(isCatchAllRule(rule({ port: "  " }))).toBe(false);
  });

  it("ignores a malformed port list", () => {
    expect(isCatchAllRule(rule({ port: "0-abc" }))).toBe(false);
  });
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
