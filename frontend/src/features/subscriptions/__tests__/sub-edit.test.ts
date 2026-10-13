import { describe, expect, it } from "vitest";
import type { Subscription } from "../../../lib/bridge";
import { savedName } from "../sub-edit";

const opened = (remarks: string, manualTitle: boolean): Subscription => ({
  id: "s1",
  remarks,
  url: "https://sub.example.org/s/abc",
  enabled: true,
  groupId: null,
  autoUpdate: false,
  interval: 90,
  allowInsecure: false,
  userAgent: "",
  filter: "",
  updateMode: "auto",
  lastUpdated: "",
  count: 0,
  manualTitle,
  intervalOverride: false,
  bodyEncrypted: false,
  insecureByProvider: false,
  allowProviderConfigs: false,
});

describe("savedName", () => {
  it("sends an untouched name back as it was opened", () => {
    const sub = opened("Old Title ", false);
    expect(savedName("Old Title ", sub, "Old Title", "Old Title")).toEqual({
      remarks: "Old Title ",
      manualTitle: false,
    });
    const own = opened("Mine", true);
    expect(savedName("Mine", own, "Mine", "Mine")).toEqual({ remarks: "Mine", manualTitle: true });
  });

  it("marks a typed name as the user's and the default as not", () => {
    const sub = opened("Old Title", false);
    expect(savedName("Mine", sub, "Mine", "Old Title")).toEqual({
      remarks: "Mine",
      manualTitle: true,
    });
    expect(savedName("", sub, "Old Title", "Old Title")).toEqual({
      remarks: "Old Title",
      manualTitle: false,
    });
    expect(savedName("", null, "sub.example.org", "sub.example.org")).toEqual({
      remarks: "sub.example.org",
      manualTitle: false,
    });
  });
});
