import { describe, expect, it } from "vitest";
import {
  type AddOptions,
  addInputFrom,
  makeSubscription,
  parseSubscriptionDump,
  profileDraft,
  profileDraftFrom,
  subDraft,
  subDraftFrom,
} from "../add-input";
import type { ResolvedImport } from "../bridge";
import { emptyProfile } from "../profile-utils";

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
          {
            url: "https://a.example.com/sub?token=1",
            encrypted: false,
            name: null,
            client: "happ",
          },
          { url: "https://b.example.com/s", encrypted: false, name: null, client: "happ" },
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
      resolved({
        subscriptions: [{ url: "happ://crypt5/abc", encrypted: true, name: null, client: "happ" }],
      }),
      defaults,
      "Encrypted subscription",
    );
    expect(subs[0]).toMatchObject({
      url: "happ://crypt5/abc",
      remarks: "Encrypted subscription",
      manualTitle: false,
    });
  });

  it("names an encrypted link after the provider it carries", () => {
    const url = "incy://crypt1/abc";
    const { subs } = addInputFrom(
      resolved({
        subscriptions: [{ url, encrypted: true, name: "Example VPN", client: "incy" }],
      }),
      defaults,
      "Encrypted subscription",
    );
    expect(subs[0]).toMatchObject({
      url,
      remarks: "Example VPN",
      manualTitle: false,
      client: "incy",
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
      package: { name: "R", finalOutbound: "proxy", blocks: [] },
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

describe("subDraftFrom", () => {
  const options: AddOptions = {
    autoUpdate: true,
    interval: 120,
    groupEach: false,
    group: { id: "g-work" },
  };
  const groups = [{ id: "g-main" }, { id: "g-work" }];

  it("carries the sheet's options and its picked group", () => {
    const first = makeSubscription({ url: "https://a.example.com/s" }, options);
    const { sub, group } = subDraftFrom(first, options, groups);
    expect(sub).toMatchObject({ url: "https://a.example.com/s", autoUpdate: true, interval: 120 });
    expect(group).toEqual({ id: "g-work" });
  });

  it("leaves a stand-in name for the editor to suggest, and keeps a given one", () => {
    const host = makeSubscription({ url: "https://a.example.com/s" }, options);
    expect(subDraftFrom(host, options, groups).sub.remarks).toBe("");
    const named = makeSubscription({ url: "https://a.example.com/s", remarks: "Work" }, options);
    expect(subDraftFrom(named, options, groups).sub.remarks).toBe("Work");
  });

  it("gives the subscription a group of its own unless a dump names one that exists", () => {
    const each = { ...options, groupEach: true };
    const plain = makeSubscription({ url: "https://a.example.com/s" }, each);
    expect(subDraftFrom(plain, each, groups).group).toEqual({ newName: "" });
    const kept = makeSubscription({ url: "https://a.example.com/s", groupId: "g-main" }, each);
    expect(subDraftFrom(kept, each, groups).group).toEqual({ id: "g-main" });
    const gone = makeSubscription({ url: "https://a.example.com/s", groupId: "g-gone" }, each);
    expect(subDraftFrom(gone, each, groups).group).toEqual({ newName: "" });
  });

  it("is a blank subscription with the options when the text holds none", () => {
    const { sub, group } = subDraftFrom(null, { ...options, group: { newName: "New" } }, groups);
    expect(sub).toMatchObject({ url: "", remarks: "", autoUpdate: true, interval: 120 });
    expect(group).toEqual({ newName: "New" });
  });
});

describe("subDraft", () => {
  const options: AddOptions = { ...defaults, groupEach: true, group: { id: "g-main" } };
  const bridgeOf = (value: ResolvedImport) => ({
    resolveImportInput: async () => value,
    parseShareLinks: async () => [],
  });

  it("opens on the first subscription the backend finds", async () => {
    const b = bridgeOf(
      resolved({
        subscriptions: [
          { url: "https://a.example.com/s", encrypted: false, name: null, client: "happ" },
          { url: "https://b.example.com/s", encrypted: false, name: null, client: "happ" },
        ],
      }),
    );
    const { sub } = await subDraft("https://a.example.com/s", options, [], "Encrypted", b);
    expect(sub.url).toBe("https://a.example.com/s");
  });

  it("reads an exported dump without the backend, keeping its name", async () => {
    const b = bridgeOf(resolved());
    const dump = JSON.stringify([{ url: "https://d.example.com/s", remarks: "D" }]);
    const { sub } = await subDraft(dump, options, [], "Encrypted", b);
    expect(sub).toMatchObject({ url: "https://d.example.com/s", remarks: "D" });
  });

  it("is blank for blank text and for text with no subscription", async () => {
    const b = bridgeOf(resolved({ shareText: "trojan://pw@h:443#T" }));
    expect((await subDraft("  ", options, [], "E", b)).sub.url).toBe("");
    expect((await subDraft("trojan://pw@h:443#T", options, [], "E", b)).sub.url).toBe("");
  });
});

describe("profileDraftFrom", () => {
  const link = emptyProfile("vless", "g-main");

  it("is the one parsed profile, filed under the picked group", () => {
    expect(profileDraftFrom([link], { id: "g-work" })?.meta.groupId).toBe("g-work");
    // A group still to be made is resolved when the editor saves.
    expect(profileDraftFrom([link], { newName: "New" })).toBe(link);
  });

  it("is null for none or several", () => {
    expect(profileDraftFrom([], { id: "g-main" })).toBeNull();
    expect(profileDraftFrom([link, link], { id: "g-main" })).toBeNull();
  });
});

describe("profileDraft", () => {
  const link = emptyProfile("vless", "g-main");
  const asked: string[] = [];
  const b = {
    resolveImportInput: async (text: string) =>
      resolved({ shareText: text.replace(/^https:\S+\s*/, "") }),
    parseShareLinks: async (text: string) => {
      asked.push(text);
      return text.trim() ? [link] : [];
    },
  };

  it("hands the backend only the share-link part of the text", async () => {
    asked.length = 0;
    const draft = await profileDraft("https://sub.example.com/s\nvless://x", { id: "g-work" }, b);
    expect(draft?.meta.groupId).toBe("g-work");
    expect(asked).toEqual(["vless://x"]);
  });

  it("is null for blank text, JSON and text with no share link", async () => {
    expect(await profileDraft(" ", { id: "g-main" }, b)).toBeNull();
    expect(await profileDraft('[{"url":"https://a"}]', { id: "g-main" }, b)).toBeNull();
    expect(await profileDraft("https://sub.example.com/s", { id: "g-main" }, b)).toBeNull();
  });
});
