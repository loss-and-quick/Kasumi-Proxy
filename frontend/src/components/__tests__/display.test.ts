import { describe, expect, it } from "vitest";
import { pingLabel, speedLabel } from "../display";

// null = untested ("—"); any negative = failed ("err").
describe("pingLabel", () => {
  it("renders untested vs failed distinctly", () => {
    expect(pingLabel(null)).toBe("—");
    expect(pingLabel(-1)).toBe("err");
    expect(pingLabel(-2)).toBe("err");
    expect(pingLabel(-99)).toBe("err");
  });
  it("renders a measured value in ms", () => {
    expect(pingLabel(0)).toBe("0 ms");
    expect(pingLabel(330)).toBe("330 ms");
  });
});

describe("speedLabel", () => {
  it("renders untested vs failed distinctly", () => {
    expect(speedLabel(null)).toBe("—");
    expect(speedLabel(undefined)).toBe("—");
    expect(speedLabel(-1)).toBe("err");
    expect(speedLabel(-2)).toBe("err");
  });
  it("renders a measured throughput", () => {
    expect(speedLabel(1_500_000)).toBe("1.5 MB/s");
    expect(speedLabel(2_000)).toBe("2 KB/s");
  });
});
