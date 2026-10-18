import { describe, expect, it } from "vitest";
import { mockBridge } from "../mock-bridge";
import { clockToMinutes, minutesToClock } from "../utils";

describe("checkSubscriptionUrlSecurity", () => {
  it("treats localhost and *.local as private", async () => {
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://localhost:8080/sub")).isLocalOrPrivate,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("https://router.local/sub")).isLocalOrPrivate,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://box.localhost/sub")).isLocalOrPrivate,
    ).toBe(true);
  });

  it("treats private and loopback IPv4 ranges as private", async () => {
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://127.0.0.1/sub")).isLocalOrPrivate,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://10.1.2.3/sub")).isLocalOrPrivate,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://192.168.0.5/sub")).isLocalOrPrivate,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://172.16.0.1/sub")).isLocalOrPrivate,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://172.31.255.255/sub")).isLocalOrPrivate,
    ).toBe(true);
  });

  it("treats public hosts as not private", async () => {
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("https://example.com/sub")).isLocalOrPrivate,
    ).toBe(false);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://8.8.8.8/sub")).isLocalOrPrivate,
    ).toBe(false);
  });

  it("flags plain http only", async () => {
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("http://example.com")).isInsecureHttp,
    ).toBe(true);
    expect(
      (await mockBridge.checkSubscriptionUrlSecurity("https://example.com")).isInsecureHttp,
    ).toBe(false);
    expect((await mockBridge.checkSubscriptionUrlSecurity("garbage")).isInsecureHttp).toBe(false);
  });
});

describe("minutesToClock / clockToMinutes", () => {
  it("formats minutes as HH:MM", () => {
    expect(minutesToClock(0)).toBe("00:00");
    expect(minutesToClock(90)).toBe("01:30");
    expect(minutesToClock(360)).toBe("06:00");
    expect(minutesToClock(1439)).toBe("23:59");
  });

  it("parses HH:MM back to minutes", () => {
    expect(clockToMinutes("00:00")).toBe(0);
    expect(clockToMinutes("01:30")).toBe(90);
    expect(clockToMinutes("06:00")).toBe(360);
  });

  it("round-trips and tolerates malformed input", () => {
    expect(clockToMinutes(minutesToClock(725))).toBe(725);
    expect(clockToMinutes("")).toBe(0);
    expect(clockToMinutes("nope")).toBe(0);
  });
});
