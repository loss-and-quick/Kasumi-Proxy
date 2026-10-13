// Every way text reaches the add flow (typed or pasted, the clipboard when the
// sheet opens, a QR code from the camera or a photo) ends in the same backend
// sorting, so a `happ://` link means the same thing whatever brought it in.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { addInputFrom, appendScanned, resolveAddText, withClipboard } from "../add-input";
import type { ResolvedImport } from "../bridge";
import { mockBridge } from "../mock-bridge";

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
        expect(value.subscriptions).toEqual([{ url: SAMPLES.crypt5, encrypted: true }]);
        expect(input.subs[0]).toMatchObject({
          url: SAMPLES.crypt5,
          remarks: "Encrypted subscription",
        });
        expect(noSubs(value)).toEqual(noSubs((await outcome(SAMPLES.crypt5)).value));
      });

      it("unwraps happ://add into the plain subscription URL", async () => {
        const { value, input } = await outcome(feed(SAMPLES.add));
        expect(value.subscriptions).toEqual([
          { url: "https://sub.provider.example/s/9f2c7e41", encrypted: false },
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
    expect(value.subscriptions).toEqual([{ url: SAMPLES.crypt5, encrypted: true }]);
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
