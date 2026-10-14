// Every way text reaches the add flow (typed or pasted, the clipboard when the
// sheet opens, a QR code from the camera or a photo, the URL field of a new
// subscription) ends in the same backend sorting, so a `happ://` link means the
// same thing whatever brought it in.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SHARE_LINK_SCHEMES } from "../../generated/defaults";
import {
  addInputFrom,
  appendScanned,
  checkSubscriptionUrl,
  linkInputText,
  resolveAddText,
  resolveLinkInput,
  subscriptionNameFrom,
  withClipboard,
} from "../add-input";
import type { ResolvedImport } from "../bridge";
import { isShareLink, mockBridge } from "../mock-bridge";

const crypt5 = (
  JSON.parse(
    readFileSync(
      new URL(
        "../../../../crates/kasumi-core/tests/fixtures/happ/crypt5-samples.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as { encrypted_link: string }[]
)[0].encrypted_link;

const routingPayload = btoa(
  JSON.stringify({
    Name: "RU direct",
    DirectSites: ["geosite:category-ru"],
    BlockSites: ["geosite:category-ads"],
    GlobalProxy: true,
  }),
);

const SAMPLES = {
  crypt5,
  add: "happ://add/https://sub.provider.example/s/9f2c7e41",
  routing: `happ://routing/onadd/${routingPayload}`,
  control: "happ://connect",
  vless: "vless://4b8e9c1a-2f3d-4e5f-8a9b-0c1d2e3f4a5b@node.example.com:443?security=tls#Node",
};

/** What each way into the add sheet hands to the sorting step. */
const ENTRY_POINTS: Record<string, (link: string) => string> = {
  paste: (link) => link,
  clipboard: (link) => withClipboard("", `\n${link}\n`),
  // The camera and a chosen photo both hand the decoded text to the same callback.
  qrScan: (link) => appendScanned("", link),
};

const defaults = { autoUpdate: false, interval: 360 };

async function outcome(text: string) {
  const { value, profileCount } = await resolveAddText(text, mockBridge);
  return { value, profileCount, input: addInputFrom(value, defaults, "Encrypted subscription") };
}

const noSubs = (r: ResolvedImport) => ({ ...r, subscriptions: [] });

describe("import entry points", () => {
  for (const [entry, feed] of Object.entries(ENTRY_POINTS)) {
    describe(entry, () => {
      it("keeps a crypt5 link encrypted, as one subscription", async () => {
        const { value, input } = await outcome(feed(SAMPLES.crypt5));
        expect(value.subscriptions).toEqual([
          { url: SAMPLES.crypt5, encrypted: true, name: null, client: "happ" },
        ]);
        expect(input.subs[0]).toMatchObject({
          url: SAMPLES.crypt5,
          remarks: "Encrypted subscription",
        });
        expect(noSubs(value)).toEqual(noSubs((await outcome(SAMPLES.crypt5)).value));
      });

      it("unwraps happ://add into the plain subscription URL", async () => {
        const { value, input } = await outcome(feed(SAMPLES.add));
        expect(value.subscriptions).toEqual([
          {
            url: "https://sub.provider.example/s/9f2c7e41",
            encrypted: false,
            name: null,
            client: "happ",
          },
        ]);
        expect(input.subs[0].remarks).toBe("sub.provider.example");
      });

      it("reads happ://routing/onadd as a routing profile that turns on", async () => {
        const { value } = await outcome(feed(SAMPLES.routing));
        expect(value.routing).toHaveLength(1);
        expect(value.routing[0]).toMatchObject({
          activate: true,
          routing: {
            name: "RU direct",
            directSites: ["geosite:category-ru"],
            blockSites: ["geosite:category-ads"],
          },
        });
        expect(value.subscriptions).toEqual([]);
      });

      it("skips a Happ control link with its reason", async () => {
        const { value, profileCount } = await outcome(feed(SAMPLES.control));
        expect(value.unsupported).toEqual([{ text: SAMPLES.control, kind: "control" }]);
        expect(profileCount).toBe(0);
      });

      it("leaves a share link to the share-link parser", async () => {
        const { value, profileCount } = await outcome(feed(SAMPLES.vless));
        expect(value.shareText).toBe(SAMPLES.vless);
        expect(value.subscriptions).toEqual([]);
        expect(profileCount).toBe(1);
      });
    });
  }

  it("adds a scanned code on its own line after what was typed", async () => {
    const text = appendScanned(`${SAMPLES.vless}\n`, SAMPLES.crypt5);
    expect(text).toBe(`${SAMPLES.vless}\n${SAMPLES.crypt5}`);
    const { value, profileCount } = await outcome(text);
    expect(value.subscriptions).toEqual([
      { url: SAMPLES.crypt5, encrypted: true, name: null, client: "happ" },
    ]);
    expect(profileCount).toBe(1);
  });

  it("does not let the clipboard replace what is already in the field", () => {
    expect(withClipboard(SAMPLES.vless, SAMPLES.crypt5)).toBe(SAMPLES.vless);
    expect(withClipboard("", "   ")).toBe("");
    expect(withClipboard("", null)).toBe("");
  });

  it("falls back to share-link text when the backend can't answer", async () => {
    const failing = {
      resolveImportInput: () => Promise.reject(new Error("offline")),
      parseShareLinks: mockBridge.parseShareLinks,
    };
    const { value, profileCount } = await resolveAddText(SAMPLES.crypt5, failing);
    expect(value).toEqual({
      subscriptions: [],
      routing: [],
      unsupported: [],
      shareText: SAMPLES.crypt5,
    });
    expect(profileCount).toBe(0);
  });
});

describe("subscription URL field", () => {
  it("stores the same URL the add sheet would", async () => {
    for (const link of [SAMPLES.crypt5, SAMPLES.add]) {
      const [sub] = (await outcome(link)).value.subscriptions;
      expect(await checkSubscriptionUrl(link, mockBridge)).toEqual({ kind: "url", ...sub });
    }
  });

  it("refuses a routing profile", async () => {
    expect(await checkSubscriptionUrl(SAMPLES.routing, mockBridge)).toEqual({ kind: "routing" });
  });

  it("refuses a control link with the add sheet's reason", async () => {
    expect(await checkSubscriptionUrl(SAMPLES.control, mockBridge)).toEqual({
      kind: "unsupported",
      reason: "control",
    });
  });

  it("leaves a plain URL, a share link and several lines as typed", async () => {
    expect(await checkSubscriptionUrl("https://a.example/s", mockBridge)).toEqual({
      kind: "url",
      url: "https://a.example/s",
      encrypted: false,
      name: null,
      client: "happ",
    });
    expect(await checkSubscriptionUrl(SAMPLES.vless, mockBridge)).toEqual({ kind: "other" });
    expect(
      await checkSubscriptionUrl("https://a.example/s\nhttps://b.example/s", mockBridge),
    ).toEqual({ kind: "other" });
  });
});

describe("links pasted where JSON is expected", () => {
  const read = (text: string) => resolveLinkInput(text, mockBridge);

  for (const [entry, feed] of Object.entries(ENTRY_POINTS)) {
    it(`reads a happ://routing link as a route to import (${entry})`, async () => {
      const link = await read(feed(SAMPLES.routing));
      expect(link).toMatchObject({
        kind: "routing",
        links: [
          {
            routing: { name: "RU direct", directSites: ["geosite:category-ru"] },
            // GlobalProxy true keeps the proxy as the final outbound.
            package: {
              name: "RU direct",
              finalOutbound: "proxy",
              blocks: [
                {
                  name: "RU direct",
                  enabled: true,
                  rules: [
                    { outboundTag: "block", domain: ["geosite:category-ads"] },
                    { outboundTag: "direct", domain: ["geosite:category-ru"] },
                  ],
                },
              ],
            },
          },
        ],
      });
    });
  }

  it("sends subscriptions and share links to the Add button", async () => {
    for (const text of [SAMPLES.add, SAMPLES.crypt5, SAMPLES.vless, "https://a.example/s"]) {
      const link = await read(text);
      expect(link).toEqual({ kind: "add" });
      expect(link && linkInputText(link)).toBe("add.linkUseAdd");
    }
  });

  it("sends routing mixed with other links to the Add button", async () => {
    expect(await read(`${SAMPLES.routing}\n${SAMPLES.vless}`)).toEqual({ kind: "add" });
  });

  it("gives a skipped Happ link its own reason", async () => {
    const link = await read("happ://routing/off");
    expect(link).toEqual({ kind: "unsupported", reason: "routingOff" });
    expect(link && linkInputText(link)).toBe("add.unsupported.routingOff");
    expect(await read(SAMPLES.control)).toEqual({ kind: "unsupported", reason: "control" });
  });

  it("leaves JSON and empty text to the JSON parser without asking the backend", async () => {
    const asked = {
      resolveImportInput: () => Promise.reject(new Error("asked")),
      parseShareLinks: () => Promise.reject(new Error("asked")),
    };
    for (const text of ["", "  ", '{"kasumiRoute":1}', ' [{"outboundTag":"direct"}]', "{"]) {
      expect(await resolveLinkInput(text, asked)).toBeNull();
    }
  });

  it("finds nothing in text the backend sorts into no links", async () => {
    const none = {
      resolveImportInput: async (text: string) => ({
        subscriptions: [],
        routing: [],
        unsupported: [],
        shareText: text,
      }),
      parseShareLinks: async () => [],
    };
    expect(await resolveLinkInput("not a backup", none)).toBeNull();
  });
});

describe("name a typed subscription URL suggests", () => {
  const enc = "Encrypted subscription";
  const nameOf = async (url: string) =>
    subscriptionNameFrom(url, await checkSubscriptionUrl(url, mockBridge), enc);

  it("names a happ:// link after what it resolves to, never its scheme word", async () => {
    expect(await nameOf(SAMPLES.add)).toBe("sub.provider.example");
    expect(await nameOf(SAMPLES.crypt5)).toBe(enc);
    expect(await nameOf(SAMPLES.routing)).toBe("");
    expect(await nameOf(SAMPLES.control)).toBe("");
  });

  it("suggests nothing for a happ:// link the backend hasn't read yet", () => {
    expect(subscriptionNameFrom(SAMPLES.add, null, enc)).toBe("");
    expect(subscriptionNameFrom(` ${SAMPLES.routing}`, null, enc)).toBe("");
    expect(subscriptionNameFrom("incy://crypt1/abc", null, enc)).toBe("");
  });

  it("names an encrypted link after the provider it carries", () => {
    const check = {
      kind: "url",
      url: "incy://crypt1/abc",
      encrypted: true,
      client: "incy",
    } as const;
    expect(subscriptionNameFrom(check.url, { ...check, name: "Example VPN" }, enc)).toBe(
      "Example VPN",
    );
    expect(subscriptionNameFrom(check.url, { ...check, name: null }, enc)).toBe(enc);
  });

  it("names a plain URL after its host before and after the check", async () => {
    expect(subscriptionNameFrom("https://a.example/s", null, enc)).toBe("a.example");
    expect(await nameOf("https://a.example/s")).toBe("a.example");
  });
});

describe("mock bridge share-link sorting", () => {
  it("counts only links in the backend's share-link schemes", async () => {
    for (const scheme of SHARE_LINK_SCHEMES)
      expect(isShareLink(`${scheme}://u@h.example:443#n`)).toBe(true);
    expect(isShareLink("https://u:p@proxy.example:8080")).toBe(true);
    expect(isShareLink("https://sub.example/s")).toBe(false);
    expect(isShareLink("not a backup")).toBe(false);
    expect(isShareLink("ftp://u@h.example")).toBe(false);
    const parsed = await mockBridge.parseShareLinks(`${SAMPLES.vless}\nhello\n{"a":1}`);
    expect(parsed).toHaveLength(1);
  });

  it("leaves plain text in a JSON import as broken JSON, not a link", async () => {
    expect(await resolveLinkInput("not a backup", mockBridge)).toBeNull();
    expect(await resolveLinkInput("https://u:p@proxy.example:8080", mockBridge)).toEqual({
      kind: "add",
    });
  });
});
