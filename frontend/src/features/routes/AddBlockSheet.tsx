// ============================================================
// features/routes/AddBlockSheet.tsx
// Put a block into a route at a given place: one already made (shared, not
// copied), a ready-made template, or a new empty one to fill right away.
// ============================================================

import { useState } from "react";
import { Icon, ListRow, SectionLabel, Sheet } from "../../components";
import { useFormatters, useT } from "../../i18n";
import { routeBlocks, routesUsing, sameBlock } from "../../lib/routes";
import { useAppStore } from "../../store/useAppStore";
import { routeName } from "./labels";
import { BLOCK_TEMPLATES, templateRules } from "./templates";

/** More blocks than this get a filter box. */
const SEARCH_FROM = 6;

export function AddBlockSheet({
  routeId,
  index,
  onClose,
  onCreated,
}: {
  routeId: string;
  /** Where in the route the block goes. */
  index: number;
  onClose: () => void;
  /** A new empty block was made: open it to add rules. */
  onCreated: (blockId: string) => void;
}) {
  const t = useT();
  const formatters = useFormatters();
  const routes = useAppStore((s) => s.routes);
  const ruleBlocks = useAppStore((s) => s.ruleBlocks);
  const saveRoute = useAppStore((s) => s.saveRoute);
  const addRuleBlock = useAppStore((s) => s.addRuleBlock);
  const [query, setQuery] = useState("");

  const route = routes.find((r) => r.id === routeId);
  if (!route) return null;
  const inRoute = new Set(routeBlocks(route).map((r) => r.blockId));
  const q = query.trim().toLowerCase();
  const available = ruleBlocks
    .filter((b) => !inRoute.has(b.id))
    .filter((b) => !q || b.name.toLowerCase().includes(q));

  const insertExisting = (blockId: string) => {
    const blocks = [...routeBlocks(route)];
    blocks.splice(index, 0, { blockId, enabled: true });
    void saveRoute({ ...route, blocks });
    onClose();
  };

  return (
    <Sheet open title={t("routes.block.add")} onClose={onClose}>
      <ListRow
        icon="add_circle"
        title={t("routes.block.newEmpty")}
        sub={t("routes.block.newEmptySub")}
        onClick={async () =>
          onCreated(await addRuleBlock(t("routes.block.newName"), [], { routeId, index }))
        }
      />

      {ruleBlocks.length > inRoute.size && (
        <>
          <SectionLabel>{t("routes.block.existing")}</SectionLabel>
          {ruleBlocks.length - inRoute.size > SEARCH_FROM && (
            <div className="route-search">
              <Icon name="search" />
              <input
                className="input"
                value={query}
                placeholder={t("routes.block.search")}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
          )}
          {available.map((block) => {
            const usedIn = routesUsing(routes, block.id);
            return (
              <ListRow
                key={block.id}
                icon="layers"
                title={block.name}
                sub={
                  usedIn.length
                    ? `${t("routes.block.rules", { count: block.rules.length })} · ${t(
                        "routes.block.usedIn",
                        { routes: formatters.formatList(usedIn.map((r) => routeName(r, t))) },
                      )}`
                    : `${t("routes.block.rules", { count: block.rules.length })} · ${t("routes.block.unused")}`
                }
                onClick={() => insertExisting(block.id)}
              />
            );
          })}
        </>
      )}

      <SectionLabel>{t("routes.template.title")}</SectionLabel>
      {BLOCK_TEMPLATES.map((template) => (
        <ListRow
          key={template.id}
          icon={template.icon}
          title={t(template.nameKey)}
          sub={t(template.hintKey)}
          onClick={async () => {
            const name = t(template.nameKey);
            const rules = templateRules(template, t);
            // Added before: put that block in rather than a second copy.
            const same = ruleBlocks.find((b) => sameBlock(b, { name, rules }));
            if (same && inRoute.has(same.id)) onClose();
            else if (same) insertExisting(same.id);
            else {
              await addRuleBlock(name, rules, { routeId, index });
              onClose();
            }
          }}
        />
      ))}
    </Sheet>
  );
}
