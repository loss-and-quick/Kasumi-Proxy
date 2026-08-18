import { describe, expect, it } from "vitest";
import type { RoutingRule } from "../../../generated/bindings";
import { isCatchAllRule } from "../helpers";

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
