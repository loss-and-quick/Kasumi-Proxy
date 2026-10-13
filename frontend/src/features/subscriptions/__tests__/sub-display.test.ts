import { describe, expect, it } from "vitest";
import type { SubErrorKind } from "../../../generated/bindings";
import en from "../../../i18n/en";
import type { Subscription } from "../../../lib/bridge";
import {
  daysLeft,
  displayTitle,
  EXPIRE_SOON_MS,
  errorKey,
  errorVars,
  expiryState,
  intervalLabel,
  trafficUsage,
} from "../sub-display";

const sub = (o: Partial<Subscription> = {}): Subscription => ({
  id: "s1",
  remarks: "",
  url: "https://sub.example.org/s/abc",
  enabled: true,
  groupId: null,
  autoUpdate: true,
  interval: 90,
  allowInsecure: false,
  userAgent: "",
  filter: "",
  updateMode: "auto",
  lastUpdated: "",
  count: 0,
  manualTitle: false,
  intervalOverride: false,
  bodyEncrypted: false,
  ...o,
});

const NOW = Date.UTC(2026, 9, 13, 12);
const nowSecs = NOW / 1000;

describe("expiryState", () => {
  it("is none without a date", () => {
    expect(expiryState(null, NOW)).toBe("none");
    expect(expiryState(undefined, NOW)).toBe("none");
    expect(expiryState(0, NOW)).toBe("none");
  });

  it("is soon at exactly three days and ok just after", () => {
    expect(expiryState(nowSecs + EXPIRE_SOON_MS / 1000, NOW)).toBe("soon");
    expect(expiryState(nowSecs + EXPIRE_SOON_MS / 1000 + 1, NOW)).toBe("ok");
  });

  it("is expired once the date has passed", () => {
    expect(expiryState(nowSecs, NOW)).toBe("expired");
    expect(expiryState(nowSecs - 60, NOW)).toBe("expired");
  });

  it("counts whole days left, rounded up", () => {
    expect(daysLeft(nowSecs + 3600, NOW)).toBe(1);
    expect(daysLeft(nowSecs + 2 * 86_400 + 1, NOW)).toBe(3);
  });
});

describe("trafficUsage", () => {
  it("has no ratio for an unmetered plan", () => {
    expect(trafficUsage({ upload: 1, download: 2, total: 0 })).toEqual({
      used: 3,
      total: 0,
      ratio: null,
    });
  });

  it("caps the ratio at the quota", () => {
    expect(trafficUsage({ upload: 60, download: 60, total: 100 }).ratio).toBe(1);
    expect(trafficUsage({ upload: 20, download: 30, total: 100 }).ratio).toBe(0.5);
  });
});

describe("displayTitle", () => {
  it("prefers the stored name, then the provider's, then the host", () => {
    expect(
      displayTitle(sub({ remarks: "Mine", provider: { title: "Theirs", expired: false } })),
    ).toBe("Mine");
    expect(displayTitle(sub({ provider: { title: "Theirs", expired: false } }))).toBe("Theirs");
    expect(displayTitle(sub())).toBe("sub.example.org");
  });
});

describe("intervalLabel", () => {
  it("shows the provider's hours unless the user overrides them", () => {
    expect(intervalLabel(sub({ providerIntervalHours: 12 }))).toEqual({
      kind: "provider",
      hours: 12,
    });
    expect(intervalLabel(sub({ providerIntervalHours: 12, intervalOverride: true }))).toEqual({
      kind: "own",
      minutes: 90,
    });
    expect(intervalLabel(sub())).toEqual({ kind: "own", minutes: 90 });
  });
});

describe("errorKey", () => {
  const kinds: SubErrorKind[] = [
    { kind: "network" },
    { kind: "http", status: 403 },
    { kind: "decrypt", keyId: "key02" },
    { kind: "emptyBody" },
    { kind: "unknownContent", hint: "yaml" },
    { kind: "unknownContent", hint: "html" },
    { kind: "unknownContent", hint: "unknown" },
    { kind: "unsupportedPayload", payload: "singBoxJson" },
    { kind: "noProfiles" },
    { kind: "limit" },
    { kind: "invalid" },
  ];

  it("has a distinct translated message for every kind", () => {
    const keys = kinds.map(errorKey);
    expect(new Set(keys).size).toBe(keys.length);
    for (const key of keys) expect(en[key]).toBeTruthy();
  });

  it("fills the message's variables", () => {
    expect(errorVars({ kind: "http", status: 502 }, "HTTP 502")).toEqual({ status: 502 });
    expect(errorVars({ kind: "decrypt", keyId: null }, "")).toEqual({ key: "" });
    expect(errorVars({ kind: "decrypt", keyId: "key02" }, "")).toEqual({ key: " (key02)" });
    expect(errorVars({ kind: "network" }, "operation timed out")).toEqual({
      detail: "operation timed out",
    });
  });
});
