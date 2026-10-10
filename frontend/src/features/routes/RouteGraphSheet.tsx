// ============================================================
// features/routes/RouteGraphSheet.tsx
// The graph view of every route at once. Tapping a route selects it; tapping
// a block opens it. On a wide screen the selected route can be rebuilt right
// here: draw a link from a node to a block to put that block next in the
// route, delete a link to take the block out, or append a block from the list.
// On a phone the graph is for looking (pan and pinch); the chain view edits.
// ============================================================

import "@xyflow/react/dist/style.css";
import {
  Background,
  type Connection,
  Controls,
  type Edge,
  Handle,
  MarkerType,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import { useEffect, useMemo } from "react";
import { Icon, ListRow, Sheet } from "../../components";
import { useFormatters, useT } from "../../i18n";
import { routeBlocks } from "../../lib/routes";
import { useIsWide } from "../../lib/useIsWide";
import { useAppStore } from "../../store/useAppStore";
import {
  blockNodeId,
  buildRouteGraph,
  type GraphNode,
  layoutRouteGraph,
  NODE_SIZE,
  routeColor,
  routeNodeId,
} from "./graph";
import { outboundLabel, routeName, scopeSummary } from "./labels";

type NodeData = {
  title: string;
  sub?: string;
  color?: string;
  icon: string;
  dim: boolean;
  kind: GraphNode["kind"];
  vertical: boolean;
};

function GraphCard({ data }: NodeProps<Node<NodeData>>) {
  return (
    <div
      className={`route-graph-node ${data.kind}${data.dim ? " dim" : ""}`}
      style={{ borderColor: data.color, ...NODE_SIZE[data.kind] }}
    >
      {data.kind !== "route" && (
        <Handle type="target" position={data.vertical ? Position.Top : Position.Left} />
      )}
      <Icon name={data.icon} style={{ color: data.color }} />
      <div style={{ minWidth: 0 }}>
        <div className="truncate route-graph-title">{data.title}</div>
        {data.sub && <div className="truncate route-graph-sub">{data.sub}</div>}
      </div>
      {data.kind !== "out" && (
        <Handle type="source" position={data.vertical ? Position.Bottom : Position.Right} />
      )}
    </div>
  );
}

const NODE_TYPES = { card: GraphCard };

export function RouteGraphSheet({
  selectedId,
  onSelect,
  onOpenBlock,
  onClose,
}: {
  selectedId: string;
  onSelect: (routeId: string) => void;
  onOpenBlock: (blockId: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const formatters = useFormatters();
  const isWide = useIsWide();
  const routes = useAppStore((s) => s.routes);
  const ruleBlocks = useAppStore((s) => s.ruleBlocks);
  const profiles = useAppStore((s) => s.profiles);
  const groups = useAppStore((s) => s.groups);
  const saveRoute = useAppStore((s) => s.saveRoute);
  const notify = useAppStore((s) => s.notify);

  const selected = routes.find((r) => r.id === selectedId);

  const graph = useMemo(() => {
    const colorOf = (routeId: string) => routeColor(routes.findIndex((r) => r.id === routeId));
    const graph = buildRouteGraph(routes, ruleBlocks);
    const vertical = !isWide;
    const at = layoutRouteGraph(graph.nodes, graph.edges, vertical);
    const onSelected = new Set(
      graph.edges.filter((e) => e.routeId === selectedId).flatMap((e) => [e.source, e.target]),
    );
    const nodes: Node<NodeData>[] = graph.nodes.map((n) => {
      const base = { id: n.id, type: "card", position: at.get(n.id) ?? { x: 0, y: 0 } };
      const dim = !onSelected.has(n.id);
      if (n.kind === "route") {
        const route = routes.find((r) => r.id === n.routeId);
        return {
          ...base,
          data: {
            kind: n.kind,
            vertical,
            icon: "route",
            title: route ? routeName(route, t) : "",
            sub: route ? scopeSummary(route, t, formatters, groups, profiles) : undefined,
            color: colorOf(n.routeId),
            dim,
          },
        };
      }
      if (n.kind === "block") {
        const block = ruleBlocks.find((b) => b.id === n.blockId);
        return {
          ...base,
          data: {
            kind: n.kind,
            vertical,
            icon: "layers",
            title: block?.name ?? "",
            sub: t("routes.block.rules", { count: block?.rules.length ?? 0 }),
            dim,
          },
        };
      }
      return {
        ...base,
        data: {
          kind: n.kind,
          vertical,
          icon: n.tag === "block" ? "block" : n.tag === "direct" ? "near_me" : "shield_moon",
          title: outboundLabel(n.tag, t, profiles),
          dim,
        },
      };
    });
    const edges: Edge[] = graph.edges.map((e) => {
      const color = e.routeId ? colorOf(e.routeId) : "var(--outline)";
      const mine = e.routeId === selectedId;
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        type: "smoothstep",
        deletable: isWide && mine && e.target.startsWith("block:"),
        animated: mine && !e.faint,
        style: {
          stroke: color,
          strokeWidth: e.ruleOut ? 1 : mine ? 2.5 : 1.5,
          strokeDasharray: e.ruleOut || e.faint ? "4 4" : undefined,
          opacity: e.ruleOut ? 0.45 : mine ? 1 : 0.3,
        },
        markerEnd: e.ruleOut ? undefined : { type: MarkerType.ArrowClosed, color },
      };
    });
    return { nodes, edges };
  }, [routes, ruleBlocks, profiles, groups, selectedId, isWide, t, formatters]);

  // The flow keeps its own copy (measured sizes, the selected link to delete);
  // it follows the store whenever routes change.
  const [nodes, setNodes, onNodesChange] = useNodesState(graph.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(graph.edges);
  useEffect(() => {
    setNodes(graph.nodes);
    setEdges(graph.edges);
  }, [graph, setNodes, setEdges]);

  const refs = selected ? routeBlocks(selected) : [];

  // A link from the selected route's start or one of its blocks to a block puts
  // that block right after it (moving it if it was further along).
  const onConnect = (c: Connection) => {
    if (!selected || !c.target.startsWith("block:")) return;
    const blockId = c.target.slice("block:".length);
    const rest = refs.filter((r) => r.blockId !== blockId);
    const moved = refs.find((r) => r.blockId === blockId) ?? { blockId, enabled: true };
    let at: number;
    if (c.source === routeNodeId(selected.id)) at = 0;
    else {
      const i = rest.findIndex((r) => blockNodeId(r.blockId) === c.source);
      if (i < 0) {
        notify(t("routes.graph.connectHint", { route: routeName(selected, t) }));
        return;
      }
      at = i + 1;
    }
    rest.splice(at, 0, moved);
    void saveRoute({ ...selected, blocks: rest });
  };

  const onEdgesDelete = (deleted: Edge[]) => {
    if (!selected) return;
    const gone = new Set(
      deleted.filter((e) => e.target.startsWith("block:")).map((e) => e.target.slice(6)),
    );
    if (gone.size)
      void saveRoute({ ...selected, blocks: refs.filter((r) => !gone.has(r.blockId)) });
  };

  const outside = ruleBlocks.filter((b) => !refs.some((r) => r.blockId === b.id));

  return (
    <Sheet open title={t("routes.graph.title")} onClose={onClose}>
      <div className="hint" style={{ marginBottom: 8 }}>
        {isWide
          ? t("routes.graph.editHint", { route: selected ? routeName(selected, t) : "" })
          : t("routes.graph.viewHint")}
      </div>
      <div className={`route-graph${isWide ? " wide" : ""}`}>
        <div className="route-graph-canvas">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={NODE_TYPES}
            colorMode="dark"
            fitView
            fitViewOptions={{ padding: 0.12 }}
            // Fit again once the sheet has slid in and the canvas has its size.
            onInit={(flow) => setTimeout(() => void flow.fitView({ padding: 0.12 }), 320)}
            minZoom={0.2}
            nodesDraggable={false}
            nodesConnectable={isWide}
            elementsSelectable={isWide}
            deleteKeyCode={isWide ? ["Backspace", "Delete"] : null}
            onConnect={onConnect}
            onEdgesDelete={onEdgesDelete}
            onNodeClick={(_, node) => {
              if (node.id.startsWith("route:")) onSelect(node.id.slice("route:".length));
              else if (node.id.startsWith("block:")) onOpenBlock(node.id.slice("block:".length));
            }}
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={24} size={1} color="var(--outline-variant)" />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
        {isWide && selected && outside.length > 0 && (
          <div className="route-graph-palette">
            <div className="hint" style={{ marginBottom: 4 }}>
              {t("routes.graph.palette", { route: routeName(selected, t) })}
            </div>
            {outside.map((b) => (
              <ListRow
                key={b.id}
                icon="layers"
                title={b.name}
                sub={t("routes.block.rules", { count: b.rules.length })}
                onClick={() =>
                  void saveRoute({
                    ...selected,
                    blocks: [...refs, { blockId: b.id, enabled: true }],
                  })
                }
              />
            ))}
          </div>
        )}
      </div>
    </Sheet>
  );
}
