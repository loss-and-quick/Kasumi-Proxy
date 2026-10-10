// ============================================================
// features/routes/RoutesCard.tsx
// The Rules mode of the Routing page: pick a route, see who it applies to and
// the blocks it runs top to bottom, then where everything else goes. Blocks
// are reordered by drag, switched off per route, and inserted at any point.
// ============================================================

import { closestCenter, DndContext, type DragEndEvent } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { lazy, Suspense, useState } from "react";
import {
  Btn,
  Card,
  Chip,
  Icon,
  IconBtn,
  ListRow,
  Select,
  Sortable,
  Switch,
  useSortableSensors,
} from "../../components";
import type { Route } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import {
  catchAllBlockIndex,
  isDefaultRoute,
  refEnabled,
  routeBlocks,
  routeEnabled,
  routeFinal,
  routeFor,
  routesUsing,
} from "../../lib/routes";
import { useAppStore } from "../../store/useAppStore";
import { useOrderedProfiles } from "../profiles/order";
import { routeName, scopeSummary } from "./labels";
import { useRoutesView } from "./viewState";

const RuleBlockSheet = lazy(() =>
  import("./RuleBlockSheet").then((module) => ({ default: module.RuleBlockSheet })),
);
const AddBlockSheet = lazy(() =>
  import("./AddBlockSheet").then((module) => ({ default: module.AddBlockSheet })),
);
const RouteSheet = lazy(() =>
  import("./RouteSheet").then((module) => ({ default: module.RouteSheet })),
);
const RouteShareSheet = lazy(() =>
  import("./RouteShareSheet").then((module) => ({ default: module.RouteShareSheet })),
);
const RouteGraphSheet = lazy(() =>
  import("./RouteGraphSheet").then((module) => ({ default: module.RouteGraphSheet })),
);

export function RoutesCard() {
  const t = useT();
  const formatters = useFormatters();
  const sensors = useSortableSensors();
  const routes = useAppStore((s) => s.routes);
  const ruleBlocks = useAppStore((s) => s.ruleBlocks);
  const profiles = useOrderedProfiles();
  const groups = useAppStore((s) => s.groups);
  const saveRoute = useAppStore((s) => s.saveRoute);
  const activeId = useAppStore((s) => s.activeId);
  const selectedId = useRoutesView((s) => s.routeId);
  const setRouteId = useRoutesView((s) => s.setRouteId);

  const [blockSheet, setBlockSheet] = useState<string | null>(null);
  const [addAt, setAddAt] = useState<number | null>(null);
  const [routeSheet, setRouteSheet] = useState<{ routeId: string | null } | null>(null);
  const [shareOpen, setShareOpen] = useState(false);
  const [graphOpen, setGraphOpen] = useState(false);

  const route = routes.find((r) => r.id === selectedId) ?? routes.find(isDefaultRoute);
  if (!route) return null;

  const active = profiles.find((p) => p.meta.id === activeId);
  const activeRoute = routeFor(routes, active);
  const refs = routeBlocks(route);
  const deadFrom = catchAllBlockIndex(route, ruleBlocks);
  const finalReachable = deadFrom < 0;

  const update = (patch: Partial<Route>) => void saveRoute({ ...route, ...patch });
  const onDragEnd = ({ active, over }: DragEndEvent) => {
    if (!over || active.id === over.id) return;
    const from = refs.findIndex((r) => r.blockId === active.id);
    const to = refs.findIndex((r) => r.blockId === over.id);
    if (from < 0 || to < 0) return;
    const next = [...refs];
    const [moved] = next.splice(from, 1);
    next.splice(to, 0, moved);
    update({ blocks: next });
  };

  const finalOptions = [
    { value: "proxy", label: t("routes.out.proxy") },
    { value: "direct", label: t("routes.out.direct") },
    { value: "block", label: t("routes.out.block") },
    // Under each group's name, as on the Profiles screen.
    ...groups.flatMap((g) => {
      const members = profiles.filter((p) => p.meta.groupId === g.id);
      return members.length
        ? [
            {
              group: g.name,
              options: members.map((p) => ({ value: p.meta.id, label: p.meta.remarks })),
            },
          ]
        : [];
    }),
  ];

  const insertButton = (index: number) => (
    <button
      type="button"
      className="route-insert"
      title={t("routes.block.insertHere")}
      aria-label={t("routes.block.insertHere")}
      onClick={() => setAddAt(index)}
    >
      <Icon name="add" />
    </button>
  );

  return (
    <Card style={{ padding: "4px 14px 14px", marginTop: 12 }}>
      <div className="routing-rules-head">
        <span className="sr-title">{t("routes.title")}</span>
        <span className="group-count">{formatters.formatNumber(routes.length)}</span>
        <IconBtn
          name="account_tree"
          sm
          title={t("routes.graph.open")}
          onClick={() => setGraphOpen(true)}
        />
        <IconBtn
          name="swap_vert"
          sm
          title={t("routes.share.title")}
          onClick={() => setShareOpen(true)}
        />
      </div>
      <div className="hint" style={{ margin: "0 0 10px" }}>
        {t("routes.hint")}
      </div>

      <div className="chip-scroller" role="tablist" aria-label={t("routes.title")}>
        {routes.map((r) => (
          <Chip key={r.id} active={r.id === route.id} onClick={() => setRouteId(r.id)}>
            {routeName(r, t)}
            {!routeEnabled(r) && <span className="route-chip-off">{t("routes.off")}</span>}
          </Chip>
        ))}
        <Chip icon="add" onClick={() => setRouteSheet({ routeId: null })}>
          {t("routes.new")}
        </Chip>
      </div>

      <div className="route-scope">
        <ListRow
          icon={isDefaultRoute(route) ? "public" : "folder"}
          title={t("routes.scope.title")}
          sub={
            <>
              {scopeSummary(route, t, formatters, groups, profiles)}
              {!isDefaultRoute(route) && !routeEnabled(route) && (
                <div style={{ color: "var(--warn)", marginTop: 2 }}>{t("routes.offHint")}</div>
              )}
              {active && activeRoute?.id === route.id && (
                <div style={{ color: "var(--primary)", marginTop: 2 }}>
                  {t("routes.activeHere", { name: active.meta.remarks })}
                </div>
              )}
            </>
          }
          onClick={() => setRouteSheet({ routeId: route.id })}
          right={<Icon name="chevron_right" style={{ color: "var(--on-surface-faint)" }} />}
        />
      </div>

      <div className="route-chain">
        <div className="route-cap">
          <Icon name="south" />
          {t("routes.chain.start")}
        </div>
        {refs.length === 0 && <div className="route-empty">{t("routes.chain.empty")}</div>}
        <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
          <SortableContext
            items={refs.map((r) => r.blockId)}
            strategy={verticalListSortingStrategy}
          >
            {refs.map((ref, index) => {
              const block = ruleBlocks.find((b) => b.id === ref.blockId);
              if (!block) return null;
              const shared = routesUsing(routes, block.id).filter((r) => r.id !== route.id);
              const dead = deadFrom >= 0 && index > deadFrom;
              const on = refEnabled(ref);
              return (
                <div key={ref.blockId} className={`route-step${on && !dead ? "" : " muted"}`}>
                  {index > 0 && insertButton(index)}
                  <Sortable id={ref.blockId}>
                    {(bindings) => (
                      <ListRow
                        drag={{ bindings, label: t("routes.block.reorder") }}
                        icon="layers"
                        title={block.name}
                        sub={
                          <>
                            {t("routes.block.rules", { count: block.rules.length })}
                            {shared.length > 0 &&
                              ` · ${t("routes.block.alsoIn", {
                                routes: formatters.formatList(shared.map((r) => routeName(r, t))),
                              })}`}
                            {dead && on && (
                              <div style={{ color: "var(--on-surface-faint)", marginTop: 2 }}>
                                {t("routes.block.unreachable")}
                              </div>
                            )}
                            {index === deadFrom && (
                              <div style={{ color: "var(--warn)", marginTop: 2 }}>
                                {t("routes.block.catchAll")}
                              </div>
                            )}
                          </>
                        }
                        onClick={() => setBlockSheet(block.id)}
                        right={
                          <Switch
                            on={on}
                            onChange={(enabled) =>
                              update({
                                blocks: refs.map((r) =>
                                  r.blockId === ref.blockId ? { ...r, enabled } : r,
                                ),
                              })
                            }
                            label={block.name}
                          />
                        }
                      />
                    )}
                  </Sortable>
                </div>
              );
            })}
          </SortableContext>
        </DndContext>
        {refs.length > 0 && insertButton(refs.length)}
        <div className={`route-final${finalReachable ? "" : " muted"}`}>
          <div className="route-final-label">
            <Icon name="alt_route" />
            <div>
              <div className="lr-title">{t("routes.final.title")}</div>
              {!finalReachable && <div className="lr-sub">{t("routes.final.unreachable")}</div>}
            </div>
          </div>
          <Select
            value={routeFinal(route)}
            onChange={(finalOutbound) => update({ finalOutbound })}
            options={finalOptions}
          />
        </div>
      </div>

      <Btn
        variant="tonal"
        sm
        icon="add"
        onClick={() => setAddAt(refs.length)}
        style={{ marginTop: 12 }}
      >
        {t("routes.block.add")}
      </Btn>

      <Suspense fallback={null}>
        {/* First: a block opened from the graph comes up over it. */}
        {graphOpen && (
          <RouteGraphSheet
            selectedId={route.id}
            onSelect={setRouteId}
            onOpenBlock={(id) => setBlockSheet(id)}
            onClose={() => setGraphOpen(false)}
          />
        )}
        {blockSheet && (
          <RuleBlockSheet
            blockId={blockSheet}
            routeId={route.id}
            onClose={() => setBlockSheet(null)}
            onForked={setBlockSheet}
          />
        )}
        {addAt !== null && (
          <AddBlockSheet
            routeId={route.id}
            index={addAt}
            onClose={() => setAddAt(null)}
            onCreated={(id) => {
              setAddAt(null);
              setBlockSheet(id);
            }}
          />
        )}
        {routeSheet && (
          <RouteSheet
            routeId={routeSheet.routeId}
            copyFrom={route}
            onClose={() => setRouteSheet(null)}
            onCreated={setRouteId}
          />
        )}
        {shareOpen && (
          <RouteShareSheet
            route={route}
            onClose={() => setShareOpen(false)}
            onImported={setRouteId}
          />
        )}
      </Suspense>
    </Card>
  );
}
