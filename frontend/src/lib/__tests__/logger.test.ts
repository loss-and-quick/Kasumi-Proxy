import { beforeEach, describe, expect, it } from "vitest";
import { clearLogs, errorStack, formatLogs, logEvent, notableCount, recentLogs } from "../logger";

describe("logger", () => {
  beforeEach(() => {
    clearLogs();
  });

  it("keeps the records in order with their level and fields", () => {
    logEvent("warn", "socket closed", { dropped: 2 });
    logEvent("error", "dispatch failed", { cmd: "status" });
    const entries = recentLogs();
    expect(entries.map((r) => r.message)).toEqual(["socket closed", "dispatch failed"]);
    expect(entries[0].level).toBe("warn");
    expect(entries[1].fields).toEqual({ cmd: "status" });
  });

  it("drops the oldest once full, so a long session cannot grow without bound", () => {
    for (let i = 0; i < 260; i++) logEvent("info", `line ${i}`);
    const entries = recentLogs();
    expect(entries).toHaveLength(200);
    expect(entries[0].message).toBe("line 60");
    expect(entries[199].message).toBe("line 259");
  });

  it("counts what is worth showing without the debug chatter", () => {
    logEvent("debug", "rendered");
    logEvent("info", "opened the logs sheet");
    logEvent("error", "boom");
    expect(notableCount()).toBe(2);
  });

  it("formats one line per record, fields included", () => {
    logEvent("error", "dispatch failed", { cmd: "realPing" });
    const [line] = formatLogs(recentLogs()).split("\n");
    expect(line).toContain("ERROR");
    expect(line).toContain("dispatch failed");
    expect(line).toContain('{"cmd":"realPing"}');
  });

  it("skips empty field objects rather than printing {}", () => {
    logEvent("error", "boom", {});
    expect(recentLogs()[0].fields).toBeUndefined();
    expect(formatLogs(recentLogs())).not.toContain("{}");
  });

  it("survives a field that cannot be serialised", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => logEvent("error", "boom", cyclic)).not.toThrow();
    expect(recentLogs()).toHaveLength(1);
    expect(formatLogs(recentLogs())).toContain("unserializable");
  });

  it("redacts query and credentials from URLs in free text", () => {
    logEvent("error", "fetch failed: https://user:pass@example.com/api?token=secret#hash");
    expect(formatLogs(recentLogs())).not.toContain("secret");
    expect(formatLogs(recentLogs())).not.toContain("user:pass");
    expect(formatLogs(recentLogs())).toContain("https://example.com/api");
  });

  it("includes indented stack in formatted logs when present", () => {
    logEvent("error", "failed", undefined, "Error: failed\n    at test.ts:1:1");
    const formatted = formatLogs(recentLogs());
    expect(formatted).toContain("ERROR failed");
    expect(formatted).toContain("    Error: failed\n        at test.ts:1:1");
  });

  it("reads a stack only off an Error", () => {
    expect(errorStack(new Error("x"))).toContain("x");
    expect(errorStack("x")).toBeUndefined();
  });
});
