import { describe, expect, it } from "vitest";
import type { HwidSource, ResolvedIdentity } from "../../../generated/bindings";
import en from "../../../i18n/en";
import { HWID_SOURCE_KEY, hwidRejected, providerAsks, typed } from "../identity";

const view = (over: Partial<ResolvedIdentity> = {}): ResolvedIdentity => ({
  hwid: "0123456789abcdef",
  hwidSource: "happComputed",
  autoHwid: "0123456789abcdef",
  autoHwidSource: "happComputed",
  facts: { os: "Android", osVersion: "16", model: "Pixel 9", locale: "ru-RU" },
  headers: [],
  cookieJar: true,
  locks: { userAgent: false, sendHwid: false, hwidInCookie: false },
  providerHidesDevice: false,
  providerHwidCookie: false,
  ...over,
});

describe("request identity helpers", () => {
  it("names every HWID source", () => {
    const sources: HwidSource[] = [
      "subscription",
      "settings",
      "happStored",
      "happComputed",
      "machineId",
      "deviceId",
    ];
    for (const s of sources) expect(en[HWID_SOURCE_KEY[s]]).toBeTruthy();
  });

  it("a blank field inherits", () => {
    expect(typed("  ")).toBeUndefined();
    expect(typed("abc")).toBe("abc");
  });

  it("a typed HWID the backend did not take is rejected", () => {
    expect(hwidRejected("bad id", "subscription", view())).toBe(true);
    expect(hwidRejected("good", "subscription", view({ hwidSource: "subscription" }))).toBe(false);
    expect(hwidRejected(undefined, "subscription", view())).toBe(false);
    expect(hwidRejected("pending", "subscription", null)).toBe(false);
  });

  it("lists what the provider asked for", () => {
    expect(providerAsks(view())).toEqual([]);
    expect(providerAsks(view({ providerHidesDevice: true }))).toEqual([
      "subs.identity.providerNoDevice",
    ]);
    expect(
      providerAsks(
        view({
          providerHidesDevice: true,
          providerHwidCookie: true,
          locks: { userAgent: true, sendHwid: true, hwidInCookie: true },
        }),
      ),
    ).toEqual([
      "subs.identity.providerUa",
      "subs.identity.providerAlwaysHwid",
      "subs.identity.providerCookie",
    ]);
    expect(
      providerAsks(view({ locks: { userAgent: false, sendHwid: false, hwidInCookie: true } })),
    ).toEqual(["subs.identity.providerHeader"]);
  });
});
