import { describe, expect, it } from "vitest";
import { classifyAddInput } from "../add-input";

const defaults = { autoUpdate: false, interval: 360 };

describe("classifyAddInput", () => {
  it("takes subscription URLs whatever separates them", () => {
    const { subs, profileText } = classifyAddInput(
      "https://a.example.com/sub?token=1 https://b.example.com/s\n\nhttps://c.example.com",
      defaults,
    );
    expect(subs.map((s) => s.remarks)).toEqual(["a.example.com", "b.example.com", "c.example.com"]);
    expect(profileText).toBe("");
  });

  it("leaves share links, an HTTP proxy link and a subscription body as text", () => {
    const text = [
      "vless://uuid@host:443?type=tcp#My node with spaces",
      "http://user:pass@1.2.3.4:8080#proxy",
      "dm1lc3M6Ly9hYmM=",
    ].join("\n");
    const { subs, profileText } = classifyAddInput(text, defaults);
    expect(subs).toEqual([]);
    expect(profileText).toBe(text);
  });

  it("splits a mixed paste", () => {
    const { subs, profileText } = classifyAddInput(
      "https://sub.example.net/x\ntrojan://pw@h:443#T",
      defaults,
    );
    expect(subs).toHaveLength(1);
    expect(profileText).toBe("trojan://pw@h:443#T");
  });

  it("reads an exported subscription list", () => {
    const { subs } = classifyAddInput(
      JSON.stringify([
        { remarks: "P", url: "https://p.example/s", groupId: "g1", autoUpdate: true },
      ]),
      defaults,
    );
    expect(subs[0]).toMatchObject({ remarks: "P", groupId: "g1", autoUpdate: true, interval: 360 });
  });

  it("treats JSON without subscription URLs as text", () => {
    const { subs, profileText } = classifyAddInput('{"outbounds":[]}', defaults);
    expect(subs).toEqual([]);
    expect(profileText).toBe('{"outbounds":[]}');
  });
});
