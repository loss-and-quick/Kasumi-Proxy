import { describe, expect, it } from "vitest";
import en from "../../i18n/en";
import { UNSUPPORTED_TEXT } from "../add-input";
import { parseCapabilities } from "../bridge";

describe("parseCapabilities", () => {
  it("keeps the protocols the cores can't run, dropping unknown values", () => {
    const caps = parseCapabilities({
      bridge: "ksu-js",
      tun: true,
      unavailableProtocols: ["naive", "carrier-pigeon", 7],
    });
    expect(caps.unavailableProtocols).toEqual(["naive"]);
  });

  it("reads an older daemon without the field as none unavailable", () => {
    expect(parseCapabilities({ bridge: "ksu-js" }).unavailableProtocols).toEqual([]);
  });
});

describe("UNSUPPORTED_TEXT", () => {
  it("explains a link the device can't run", () => {
    expect(en[UNSUPPORTED_TEXT.unavailableProtocol]).toContain("Android");
  });
});
