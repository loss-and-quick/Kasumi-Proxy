import { describe, expect, it } from "vitest";
import type {
  AdvancedSettings,
  AssetFile,
  Profile,
  Route,
  RoutingRule,
} from "../../generated/bindings";
import { getMissingGeoAssets } from "../geo-assets";
import { DEFAULT_ROUTE_ID, newRoute, type RuleBlock } from "../routes";

const makeSettings = (fields: Partial<AdvancedSettings> = {}): AdvancedSettings =>
  ({
    routingMode: "rules",
    proxyMode: "tun",
    domainSniffing: true,
    routeOnly: false,
    domainStrategy: "ipIfNonMatch",
    domainStrategy4Singbox: "preferIpv4",
    strictRoute: false,
    proxyTethering: false,
    fakeDns: false,
    ...fields,
  }) as AdvancedSettings;

const makeRoute = (id: string, blocks: string[], fields: Partial<Route> = {}): Route => ({
  ...newRoute(id, id),
  blocks: blocks.map((blockId) => ({ blockId, enabled: true })),
  ...fields,
});

const makeBlock = (id: string, rules: RoutingRule[]): RuleBlock => ({
  id,
  name: id,
  rules,
});

const makeRule = (id: string, fields: Partial<RoutingRule> = {}): RoutingRule => ({
  id,
  remarks: id,
  enabled: true,
  outboundTag: "direct",
  ...fields,
});

const makeAsset = (remarks: string, lastUpdated: number | null = 1000): AssetFile => ({
  id: remarks.replace(/\.dat$/, ""),
  remarks,
  url: `https://example.com/${remarks}`,
  lastUpdated,
  locked: false,
});

const dummyProfile = { meta: { id: "p1", groupId: "g-main", remarks: "P1" } } as unknown as Profile;

describe("getMissingGeoAssets", () => {
  it("returns empty when routing mode is global", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings({ routingMode: "global" }),
      routes: [makeRoute(DEFAULT_ROUTE_ID, ["b1"])],
      ruleBlocks: [makeBlock("b1", [makeRule("r1", { domain: ["geosite:ru"] })])],
      activeProfile: dummyProfile,
      assetFiles: [],
    });
    expect(missing).toEqual([]);
  });

  it("returns empty when rules do not reference geo matchers", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings(),
      routes: [makeRoute(DEFAULT_ROUTE_ID, ["b1"])],
      ruleBlocks: [makeBlock("b1", [makeRule("r1", { domain: ["example.com"], ip: ["1.1.1.1"] })])],
      activeProfile: dummyProfile,
      assetFiles: [],
    });
    expect(missing).toEqual([]);
  });

  it("flags missing geosite.dat when geosite matcher is used and un-downloaded", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings(),
      routes: [makeRoute(DEFAULT_ROUTE_ID, ["b1"])],
      ruleBlocks: [makeBlock("b1", [makeRule("r1", { domain: ["geosite:ru"] })])],
      activeProfile: dummyProfile,
      assetFiles: [makeAsset("geoip.dat", 12345)], // geoip is present, but geosite is missing
    });
    expect(missing).toEqual(["geosite.dat"]);
  });

  it("flags missing geoip.dat when geoip matcher is used and un-downloaded", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings(),
      routes: [makeRoute(DEFAULT_ROUTE_ID, ["b1"])],
      ruleBlocks: [makeBlock("b1", [makeRule("r1", { ip: ["geoip:ru"] })])],
      activeProfile: dummyProfile,
      assetFiles: [makeAsset("geosite.dat", 12345)],
    });
    expect(missing).toEqual(["geoip.dat"]);
  });

  it("returns empty when all required geo assets are downloaded", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings(),
      routes: [makeRoute(DEFAULT_ROUTE_ID, ["b1"])],
      ruleBlocks: [makeBlock("b1", [makeRule("r1", { domain: ["geosite:ru"], ip: ["geoip:ru"] })])],
      activeProfile: dummyProfile,
      assetFiles: [makeAsset("geosite.dat", 1000), makeAsset("geoip.dat", 2000)],
    });
    expect(missing).toEqual([]);
  });

  it("ignores disabled rules and disabled blocks", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings(),
      routes: [
        {
          ...makeRoute(DEFAULT_ROUTE_ID, []),
          blocks: [
            { blockId: "b-disabled", enabled: false },
            { blockId: "b-enabled", enabled: true },
          ],
        },
      ],
      ruleBlocks: [
        makeBlock("b-disabled", [makeRule("r1", { domain: ["geosite:ru"] })]),
        makeBlock("b-enabled", [
          makeRule("r2", { enabled: false, domain: ["geosite:cn"] }),
          makeRule("r3", { enabled: true, domain: ["example.com"] }),
        ]),
      ],
      activeProfile: dummyProfile,
      assetFiles: [],
    });
    expect(missing).toEqual([]);
  });

  it("detects geo requirements in custom routing mode", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings({
        routingMode: "custom",
        customRouting: JSON.stringify([{ domain: ["geosite:category-ads"] }]),
      }),
      routes: [],
      ruleBlocks: [],
      activeProfile: dummyProfile,
      assetFiles: [],
    });
    expect(missing).toEqual(["geosite.dat"]);
  });

  it("does not treat literal domains containing geosite as geo assets", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings(),
      routes: [makeRoute(DEFAULT_ROUTE_ID, ["b1"])],
      ruleBlocks: [
        makeBlock("b1", [makeRule("r1", { domain: ["full:geosite.database.example.com"] })]),
      ],
      activeProfile: dummyProfile,
      assetFiles: [],
    });
    expect(missing).toEqual([]);
  });

  it("requires geoip.dat when fakeDns is enabled for Xray even in global mode", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings({ routingMode: "global", fakeDns: true }),
      routes: [],
      ruleBlocks: [],
      activeProfile: dummyProfile,
      assetFiles: [],
      resolvedCore: "xray",
    });
    expect(missing).toEqual(["geoip.dat"]);
  });

  it("ignores custom routing when resolved core is sing-box", () => {
    const missing = getMissingGeoAssets({
      settings: makeSettings({
        routingMode: "custom",
        customRouting: JSON.stringify([{ domain: ["geosite:cn"] }]),
      }),
      routes: [],
      ruleBlocks: [],
      activeProfile: dummyProfile,
      assetFiles: [],
      resolvedCore: "sing-box",
    });
    expect(missing).toEqual([]);
  });
});
