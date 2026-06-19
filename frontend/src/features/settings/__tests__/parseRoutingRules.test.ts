import { describe, expect, it } from "vitest";
import { parseRoutingRulesJson } from "../helpers";

const nativeRule = {
  id: "abc-123",
  remarks: "block ads",
  enabled: true,
  outboundTag: "block",
  domain: ["geosite:category-ads"],
};

const v2rayngRule = {
  remarks: "direct cn",
  enabled: true,
  outboundTag: "direct",
  ip: ["geoip:cn"],
};

describe("parseRoutingRulesJson", () => {
  it("accepts native format (with id)", () => {
    const { ok, rules } = parseRoutingRulesJson(JSON.stringify([nativeRule]));
    expect(ok).toBe(true);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("abc-123");
    expect(rules[0].remarks).toBe("block ads");
  });

  it("accepts v2rayNG format (no id) and generates id", () => {
    const { ok, rules } = parseRoutingRulesJson(JSON.stringify([v2rayngRule]));
    expect(ok).toBe(true);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBeTruthy();
    expect(rules[0].remarks).toBe("direct cn");
    expect(rules[0].outboundTag).toBe("direct");
    expect(rules[0].ip).toEqual(["geoip:cn"]);
  });

  it("defaults remarks to empty string when absent in v2rayNG format", () => {
    const { rules } = parseRoutingRulesJson(
      JSON.stringify([{ enabled: true, outboundTag: "proxy", domain: ["example.com"] }]),
    );
    expect(rules[0].remarks).toBe("");
  });

  it("each v2rayNG rule gets a unique id", () => {
    const { rules } = parseRoutingRulesJson(JSON.stringify([v2rayngRule, v2rayngRule]));
    expect(rules[0].id).not.toBe(rules[1].id);
  });

  it("returns ok=false for empty array", () => {
    const { ok, rules } = parseRoutingRulesJson("[]");
    expect(ok).toBe(false);
    expect(rules).toHaveLength(0);
  });

  it("returns ok=false for invalid JSON", () => {
    const { ok } = parseRoutingRulesJson("not json");
    expect(ok).toBe(false);
  });

  it("returns ok=false for invalid rule shape", () => {
    const { ok } = parseRoutingRulesJson(JSON.stringify([{ foo: "bar" }]));
    expect(ok).toBe(false);
  });
});
