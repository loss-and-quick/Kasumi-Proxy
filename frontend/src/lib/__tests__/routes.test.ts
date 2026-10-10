import { describe, expect, it } from "vitest";
import { buildRouteGraph } from "../../features/routes/graph";
import type { Profile, Route, RoutingRule } from "../../generated/bindings";
import {
  catchAllBlockIndex,
  DEFAULT_ROUTE_ID,
  exportRoutePackage,
  flattenRoute,
  newRoute,
  normalizeRoutes,
  parseRoutePackage,
  type RuleBlock,
  routeFor,
} from "../routes";

const rule = (id: string, fields: Partial<RoutingRule> = {}): RoutingRule => ({
  id,
  remarks: id,
  enabled: true,
  outboundTag: "direct",
  domain: [`${id}.example`],
  ...fields,
});

const route = (id: string, blocks: string[], fields: Partial<Route> = {}): Route => ({
  ...newRoute(id, id),
  blocks: blocks.map((blockId) => ({ blockId, enabled: true })),
  ...fields,
});

const profile = (id: string, groupId: string) =>
  ({ meta: { id, groupId, remarks: id } }) as unknown as Profile;

describe("routes", () => {
  it("a profile's own route beats its group's, which beats the default", () => {
    const routes = [
      route(DEFAULT_ROUTE_ID, []),
      route("team", [], { groups: ["g2"] }),
      route("mine", [], { profiles: ["c"] }),
    ];
    expect(routeFor(routes, profile("a", "g-main"))?.id).toBe(DEFAULT_ROUTE_ID);
    expect(routeFor(routes, profile("b", "g2"))?.id).toBe("team");
    expect(routeFor(routes, profile("c", "g2"))?.id).toBe("mine");
    routes[2].enabled = false;
    expect(routeFor(routes, profile("c", "g2"))?.id).toBe("team");
  });

  it("finds the block after which nothing is reached", () => {
    const blocks: RuleBlock[] = [
      { id: "a", name: "A", rules: [rule("x")] },
      { id: "all", name: "All", rules: [rule("rest", { domain: undefined, port: "1-65535" })] },
    ];
    expect(catchAllBlockIndex(route("r", ["a", "all"]), blocks)).toBe(1);
    const off = route("r", ["a", "all"]);
    off.blocks = [
      { blockId: "a", enabled: true },
      { blockId: "all", enabled: false },
    ];
    expect(catchAllBlockIndex(off, blocks)).toBe(-1);
  });

  it("normalizing folds a flat rule list into the default route and drops what is gone", () => {
    const state = {
      routes: [route("work", ["gone", "b"], { profiles: ["p", "deleted"] })],
      ruleBlocks: [{ id: "b", name: "B", rules: [] }],
      routingRules: [rule("old")],
      profiles: [profile("p", "g-main")],
      groups: [{ id: "g-main" }],
    };
    const next = normalizeRoutes(state, () => "folded");
    expect(next.routes.map((r) => r.id)).toEqual([DEFAULT_ROUTE_ID, "work"]);
    expect(next.routes[0].blocks).toEqual([{ blockId: "folded", enabled: true }]);
    expect(next.routes[1].blocks).toEqual([{ blockId: "b", enabled: true }]);
    expect(next.routes[1].profiles).toEqual(["p"]);
    expect(next.routingRules).toBeUndefined();
  });

  it("a shared route keeps its blocks and loses its profiles", () => {
    const blocks: RuleBlock[] = [{ id: "b", name: "B", rules: [rule("x", { outboundTag: "p1" })] }];
    const text = exportRoutePackage(
      route("work", ["b"], { profiles: ["p1"], finalOutbound: "direct" }),
      blocks,
    );
    expect(text).not.toContain("p1");
    const pkg = parseRoutePackage(text);
    expect(pkg?.finalOutbound).toBe("direct");
    expect(pkg?.blocks[0].rules[0].outboundTag).toBe("proxy");
    expect(parseRoutePackage('[{"remarks":"x","outboundTag":"direct"}]')).toBeNull();
    expect(parseRoutePackage("not json")).toBeNull();
  });

  it("one list ends with the route's final outbound", () => {
    const blocks: RuleBlock[] = [{ id: "b", name: "B", rules: [rule("x")] }];
    const flat = JSON.parse(flattenRoute(route("r", ["b"], { finalOutbound: "direct" }), blocks));
    expect(flat.map((r: RoutingRule) => r.outboundTag)).toEqual(["direct", "direct"]);
    expect(flat[1].network).toBe("tcp,udp");
    const proxied = JSON.parse(flattenRoute(route("r", ["b"]), blocks));
    expect(proxied).toHaveLength(1);
  });

  it("a block shared by two routes is one node both routes pass through", () => {
    const blocks: RuleBlock[] = [
      { id: "ads", name: "Ads", rules: [rule("ad", { outboundTag: "block" })] },
      { id: "work", name: "Work", rules: [rule("corp")] },
    ];
    const graph = buildRouteGraph(
      [route(DEFAULT_ROUTE_ID, ["ads"]), route("w", ["work", "ads"], { finalOutbound: "direct" })],
      blocks,
    );
    expect(graph.nodes.filter((n) => n.id === "block:ads")).toHaveLength(1);
    const into = graph.edges.filter((e) => e.target === "block:ads" && !e.ruleOut);
    expect(into.map((e) => e.routeId).sort()).toEqual([DEFAULT_ROUTE_ID, "w"]);
    const finals = graph.edges.filter((e) => e.id.endsWith(":final")).map((e) => e.target);
    expect(finals.sort()).toEqual(["out:direct", "out:proxy"]);
  });
});
