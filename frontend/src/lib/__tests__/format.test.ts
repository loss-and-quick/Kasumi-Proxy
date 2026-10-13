import { describe, expect, it } from "vitest";
import { formatBytes, formatRate } from "../format";

const numberIn =
  (locale: string) =>
  (value: number, options?: Intl.NumberFormatOptions): string =>
    new Intl.NumberFormat(locale, options).format(value);

describe("formatBytes", () => {
  it("steps through binary units", () => {
    const en = numberIn("en");
    expect(formatBytes(0, en)).toBe("0.0 MB");
    expect(formatBytes(1536, en)).toBe("1.5 kB");
    expect(formatBytes(5 * 1024 * 1024, en)).toBe("5.0 MB");
    expect(formatBytes(62.94 * 1024 ** 3, en)).toBe("62.94 GB");
  });

  it("writes the number and unit in the reader's locale", () => {
    expect(formatBytes(62.94 * 1024 ** 3, numberIn("ru"))).toMatch(/^62,94\sГБ$/);
  });
});

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
