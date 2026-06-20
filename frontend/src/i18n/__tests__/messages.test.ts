import { describe, expect, it } from "vitest";
import { loadLocale, resolvePreferredLang, translate } from "../index";

describe("i18n message helpers", () => {
  it("handles plural messages", () => {
    expect(translate("en", "profiles.shareCopiedMany", { count: 1 })).toBe("Copied 1 link");
    expect(translate("en", "profiles.shareCopiedMany", { count: 3 })).toBe("Copied 3 links");
  });

  it("handles composed plural messages", () => {
    expect(translate("en", "profiles.subtitle", { servers: 1, groups: 2 })).toBe(
      "1 server · 2 groups",
    );
    expect(translate("en", "subs.subtitle", { active: 2, imported: 1 })).toBe(
      "2 active subscriptions · 1 imported profile",
    );
  });

  it("handles pluralized store notifications", () => {
    expect(translate("en", "store.profile.imported", { count: 1 })).toBe("Imported 1 profile");
    expect(translate("en", "store.sub.updatedProfiles", { name: "Demo", count: 4 })).toBe(
      "Demo: 4 profiles",
    );
  });

  it("handles select-style mode labels", () => {
    expect(translate("en", "store.asset.updated", { mode: "auto", name: "geoip.dat" })).toBe(
      "Updated geoip.dat via automatic",
    );
    expect(
      translate("en", "store.asset.downloadFailed", { mode: "proxy", name: "geoip.dat" }),
    ).toBe("Download failed (proxy): geoip.dat");
  });

  it("auto-detects base browser languages from regional variants", () => {
    expect(resolvePreferredLang(["pt-BR"])).toBe("pt");
    expect(resolvePreferredLang(["es-419"])).toBe("es");
    expect(resolvePreferredLang(["zh-CN"])).toBe("zh");
    expect(resolvePreferredLang(["ar-EG"])).toBe("ar");
    expect(resolvePreferredLang(["hi-IN"])).toBe("hi");
    expect(resolvePreferredLang(["vi-VN"])).toBe("vi");
    expect(resolvePreferredLang(["ru-RU"])).toBe("ru");
  });

  it("loads non-English locale dictionaries on demand", async () => {
    expect(translate("es", "nav.overview")).toBe("Overview");

    await loadLocale("es");

    expect(translate("es", "nav.overview")).not.toBe("Overview");
  });
});
