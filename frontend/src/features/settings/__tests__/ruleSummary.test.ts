import { beforeAll, describe, expect, it } from "vitest";
import type { RoutingRule } from "../../../generated/bindings";
import { type I18nFormatters, loadLocale, type Translate, translate } from "../../../i18n";
import { ruleSummary } from "../helpers";

const mockFormatters: I18nFormatters = {
  formatDateTime: (val) => String(val),
  formatNumber: (val) => String(val),
  formatList: (items) => Array.from(items).join(", "),
};

const rule = (fields: Partial<RoutingRule>): RoutingRule => ({
  id: "r1",
  remarks: "test rule",
  enabled: true,
  outboundTag: "proxy",
  ...fields,
});

describe("ruleSummary", () => {
  const tEn: Translate = (key, params) => translate("en", key, params);

  beforeAll(async () => {
    await loadLocale("en");
  });

  it("shows processes when rule specifies only processes", () => {
    const summary = ruleSummary(rule({ process: ["firefox", "curl"] }), tEn, mockFormatters);
    expect(summary).toContain("2 processes");
    expect(summary).not.toContain("No match fields");
    expect(summary).toContain("→ proxy");
  });

  it("shows packages when rule specifies only package names", () => {
    const summary = ruleSummary(
      rule({ packageName: ["com.example.app"], outboundTag: "direct" }),
      tEn,
      mockFormatters,
    );
    expect(summary).toContain("1 package");
    expect(summary).not.toContain("No match fields");
    expect(summary).toContain("→ direct");
  });

  it("shows source IPs when rule specifies only source IP", () => {
    const summary = ruleSummary(
      rule({ sourceIp: ["192.168.1.0/24"], outboundTag: "block" }),
      tEn,
      mockFormatters,
    );
    expect(summary).toContain("1 source IP");
    expect(summary).not.toContain("No match fields");
    expect(summary).toContain("→ block");
  });

  it("shows no match fields when rule has no conditions", () => {
    const summary = ruleSummary(rule({}), tEn, mockFormatters);
    expect(summary).toContain("No match fields");
    expect(summary).toContain("→ proxy");
  });

  it("formats process rule correctly in Russian without reporting missing matchers", async () => {
    await loadLocale("ru");
    const tRu: Translate = (key, params) => translate("ru", key, params);
    const summary = ruleSummary(rule({ process: ["curl"] }), tRu, mockFormatters);
    expect(summary).toContain("1 процесс");
    expect(summary).not.toContain("Нет полей для сопоставления");
  });
});
