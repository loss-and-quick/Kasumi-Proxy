import { describe, expect, it } from "vitest";
import { formatRate } from "../format";

describe("formatRate", () => {
  it("formats bytes per second", () => {
    expect(formatRate(0)).toBe("0 B/s");
    expect(formatRate(512)).toBe("512 B/s");
  });

  it("formats kilobytes per second", () => {
    expect(formatRate(1536)).toBe("1.5 KB/s");
  });

  it("formats megabytes per second", () => {
    expect(formatRate(2.5 * 1024 * 1024)).toBe("2.5 MB/s");
  });
});
