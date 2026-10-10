// ============================================================
// features/routes/graph.ts
// Routes as a graph: each route enters on the left, runs through its blocks
// and ends at the outbound unmatched traffic takes. A block shared by several
// routes is one node that several routes pass through. Thin dashed edges show
// where a block's own rules send traffic.
// ============================================================

import dagre from "@dagrejs/dagre";
import type { Route } from "../../generated/bindings";
import {
  catchAllBlockIndex,
  PROXY_OUTBOUND,
  type RuleBlock,
  refEnabled,
  routeBlocks,
  routeFinal,
} from "../../lib/routes";

export type GraphNode =
  | { id: string; kind: "route"; routeId: string }
  | { id: string; kind: "block"; blockId: string }
  | { id: string; kind: "out"; tag: string };

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  /** The route this edge is part of; absent for a block's rule outbounds. */
  routeId?: string;
  /** The block at the end is switched off in that route, or never reached. */
  faint?: boolean;
  /** Where a block's rules send traffic (not the route's path). */
  ruleOut?: boolean;
};

export const routeNodeId = (id: string) => `route:${id}`;
export const blockNodeId = (id: string) => `block:${id}`;
export const outNodeId = (tag: string) => `out:${tag}`;

export function buildRouteGraph(
  routes: Route[],
  blocks: RuleBlock[],
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const addOut = (tag: string) => {
    const id = outNodeId(tag || PROXY_OUTBOUND);
    if (!nodes.has(id)) nodes.set(id, { id, kind: "out", tag: tag || PROXY_OUTBOUND });
    return id;
  };

  for (const route of routes) {
    const start = routeNodeId(route.id);
    nodes.set(start, { id: start, kind: "route", routeId: route.id });
    const deadFrom = catchAllBlockIndex(route, blocks);
    let prev = start;
    routeBlocks(route).forEach((ref, index) => {
      const block = blocks.find((b) => b.id === ref.blockId);
      if (!block) return;
      const id = blockNodeId(block.id);
      nodes.set(id, { id, kind: "block", blockId: block.id });
      edges.push({
        id: `${route.id}:${index}`,
        source: prev,
        target: id,
        routeId: route.id,
        faint: !refEnabled(ref) || (deadFrom >= 0 && index > deadFrom),
      });
      prev = id;
    });
    edges.push({
      id: `${route.id}:final`,
      source: prev,
      target: addOut(routeFinal(route)),
      routeId: route.id,
      faint: deadFrom >= 0,
    });
  }

  // Each block's rule outbounds, once per block and outbound.
  for (const node of [...nodes.values()]) {
    if (node.kind !== "block") continue;
    const block = blocks.find((b) => b.id === node.blockId);
    const tags = new Set(block?.rules.filter((r) => r.enabled).map((r) => r.outboundTag));
    for (const tag of tags) {
      edges.push({
        id: `${node.id}->${tag}`,
        source: node.id,
        target: addOut(tag),
        ruleOut: true,
      });
    }
  }
  return { nodes: [...nodes.values()], edges };
}

export const NODE_SIZE = {
  route: { width: 170, height: 56 },
  block: { width: 180, height: 56 },
  out: { width: 130, height: 40 },
} as const;

/**
 * Positions (top-left corners) for the nodes: left to right on a wide screen,
 * top to bottom on a phone, where a long row would shrink to unreadable.
 */
export function layoutRouteGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  vertical = false,
): Map<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph({ multigraph: true });
  g.setGraph({
    rankdir: vertical ? "TB" : "LR",
    nodesep: vertical ? 16 : 24,
    ranksep: vertical ? 44 : 70,
    marginx: 16,
    marginy: 16,
  });
  g.setDefaultEdgeLabel(() => ({}));
  for (const n of nodes) g.setNode(n.id, { ...NODE_SIZE[n.kind] });
  // Rule outbounds hang off the side; they shouldn't pull the route's path apart.
  for (const e of edges) g.setEdge(e.source, e.target, { weight: e.ruleOut ? 0 : 2 }, e.id);
  dagre.layout(g);
  const out = new Map<string, { x: number; y: number }>();
  for (const n of nodes) {
    const p = g.node(n.id);
    const size = NODE_SIZE[n.kind];
    out.set(n.id, { x: p.x - size.width / 2, y: p.y - size.height / 2 });
  }
  return out;
}

/** A distinct, readable color per route on the dark surface; the default route gets the primary. */
export function routeColor(index: number): string {
  if (index === 0) return "var(--primary)";
  const hue = (40 + index * 83) % 360;
  return `oklch(0.78 0.13 ${hue})`;
}
