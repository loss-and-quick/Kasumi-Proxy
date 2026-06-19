import { beforeEach, describe, expect, it, vi } from "vitest";
import { ActivityService } from "../activity";

describe("ActivityService", () => {
  let svc: ActivityService;

  beforeEach(() => {
    svc = new ActivityService();
  });

  it("starts empty", () => {
    expect(svc.snapshot()).toHaveLength(0);
  });

  it("add returns the updated feed with the new entry at index 0", () => {
    const feed = svc.add("play_circle", "Service started · Node A", "var(--running)");
    expect(feed).toHaveLength(1);
    expect(feed[0].icon).toBe("play_circle");
    expect(feed[0].text).toBe("Service started · Node A");
    expect(feed[0].color).toBe("var(--running)");
  });

  it("add timestamps entries with Date.now()", () => {
    const before = Date.now();
    svc.add("stop_circle", "Service stopped");
    const after = Date.now();
    const [entry] = svc.snapshot();
    expect(entry.at).toBeGreaterThanOrEqual(before);
    expect(entry.at).toBeLessThanOrEqual(after);
  });

  it("newest entry is always at index 0", () => {
    svc.add("A", "first");
    svc.add("B", "second");
    svc.add("C", "third");
    expect(svc.snapshot()[0].text).toBe("third");
    expect(svc.snapshot()[2].text).toBe("first");
  });

  it("caps the feed at MAX_EVENTS (10) entries", () => {
    for (let i = 0; i < 15; i++) svc.add("icon", `event ${i}`);
    expect(svc.snapshot()).toHaveLength(10);
    // newest entry still at front
    expect(svc.snapshot()[0].text).toBe("event 14");
  });

  it("color is optional — defaults to undefined when omitted", () => {
    svc.add("dns", "No color");
    expect(svc.snapshot()[0].color).toBeUndefined();
  });

  it("snapshot returns the same reference as the last add result", () => {
    const fromAdd = svc.add("icon", "text");
    expect(svc.snapshot()).toBe(fromAdd);
  });

  it("add with frozen time produces stable at values", () => {
    const FIXED = 1_700_000_000_000;
    vi.useFakeTimers();
    vi.setSystemTime(FIXED);
    svc.add("icon", "event");
    expect(svc.snapshot()[0].at).toBe(FIXED);
    vi.useRealTimers();
  });
});
