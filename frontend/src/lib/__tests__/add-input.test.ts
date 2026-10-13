import { describe, expect, it } from "vitest";
import { addInputFrom, parseSubscriptionDump } from "../add-input";
import type { ResolvedImport } from "../bridge";

const defaults = { autoUpdate: false, interval: 360 };

const resolved = (o: Partial<ResolvedImport> = {}): ResolvedImport => ({
  subscriptions: [],
  routing: [],
  unsupported: [],
  shareText: "",
  ...o,
});

describe("addInputFrom", () => {
  it("names plain subscriptions after their host", () => {
    const { subs, profileText } = addInputFrom(
      resolved({
        subscriptions: [
          { url: "https://a.example.com/sub?token=1", encrypted: false },
          { url: "https://b.example.com/s", encrypted: false },
        ],
        shareText: "trojan://pw@h:443#T",
      }),
      defaults,
      "Encrypted",
    );
    expect(subs.map((s) => s.remarks)).toEqual(["a.example.com", "b.example.com"]);
    expect(subs.every((s) => !s.manualTitle)).toBe(true);
    expect(profileText).toBe("trojan://pw@h:443#T");
  });

  it("keeps an encrypted link as given, under a name the provider can replace", () => {
    const { subs } = addInputFrom(
      resolved({ subscriptions: [{ url: "happ://crypt5/abc", encrypted: true }] }),
      defaults,
      "Encrypted subscription",
    );
    expect(subs[0]).toMatchObject({
      url: "happ://crypt5/abc",
      remarks: "Encrypted subscription",
      manualTitle: false,
    });
  });

  it("passes routing profiles and unsupported links through", () => {
    const routing = {
      routing: {
        name: "R",
        directSites: [],
        directIp: [],
        proxySites: [],
        proxyIp: [],
        blockSites: ["geosite:ads"],
        blockIp: [],
        ignoredFields: [],
      },
      activate: true,
    };
    const unsupported = [{ text: "happ://toggle", kind: "control" as const }];
    const input = addInputFrom(resolved({ routing: [routing], unsupported }), defaults, "E");
    expect(input.routing).toEqual([routing]);
    expect(input.unsupported).toEqual(unsupported);
    expect(input.subs).toEqual([]);
  });
});

describe("parseSubscriptionDump", () => {
  it("reads an exported subscription list", () => {
    const subs = parseSubscriptionDump(
      JSON.stringify([
        { remarks: "P", url: "https://p.example/s", groupId: "g1", autoUpdate: true },
      ]),
      defaults,
    );
    expect(subs?.[0]).toMatchObject({
      remarks: "P",
      groupId: "g1",
      autoUpdate: true,
      interval: 360,
    });
  });

  it("marks only a typed name as manual", () => {
    const subs = parseSubscriptionDump(
      JSON.stringify([
        { remarks: "Mine", url: "https://a.example/s" },
        { remarks: "b.example", url: "https://b.example/s" },
        { remarks: "Kept", url: "https://c.example/s", manualTitle: false },
        { url: "https://d.example/s" },
      ]),
      defaults,
    );
    expect(subs?.map((s) => s.manualTitle)).toEqual([true, false, false, false]);
  });

  it("is null for JSON without subscription URLs and for plain text", () => {
    expect(parseSubscriptionDump('{"outbounds":[]}', defaults)).toBeNull();
    expect(parseSubscriptionDump("https://a.example/s", defaults)).toBeNull();
  });
});
