// ============================================================
// features/routes/RuleBlockSheet.tsx
// One block's editor: its name and rules. A block can sit in several routes,
// so the sheet says where else an edit lands and offers a copy for just the
// route it was opened from.
// ============================================================

import { lazy, Suspense, useState } from "react";
import { Btn, confirm, Field, Icon, IconBtn, Sheet } from "../../components";
import type { RoutingRule } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import { routeBlocks, routesUsing } from "../../lib/routes";
import { useAppStore } from "../../store/useAppStore";
import { useOrderedProfiles } from "../profiles/order";
import { routeName } from "./labels";
import { RuleList } from "./RuleList";

const RoutingRuleSheet = lazy(() =>
  import("../settings/RoutingRuleSheet").then((module) => ({ default: module.RoutingRuleSheet })),
);
const RoutingRulesIOSheet = lazy(() =>
  import("../settings/RoutingRulesIOSheet").then((module) => ({
    default: module.RoutingRulesIOSheet,
  })),
);

export function RuleBlockSheet({
  blockId,
  routeId,
  onClose,
  onForked,
}: {
  /** The block shown; `null` keeps the sheet closed. */
  blockId: string | null;
  /** The route the block was opened from, if any. */
  routeId: string | null;
  onClose: () => void;
  /** The route got its own copy; the sheet should show that one now. */
  onForked: (copyId: string) => void;
}) {
  const t = useT();
  const formatters = useFormatters();
  const block = useAppStore((s) => s.ruleBlocks.find((b) => b.id === blockId));
  const routes = useAppStore((s) => s.routes);
  const profiles = useOrderedProfiles();
  const renameRuleBlock = useAppStore((s) => s.renameRuleBlock);
  const removeRuleBlock = useAppStore((s) => s.removeRuleBlock);
  const forkRuleBlock = useAppStore((s) => s.forkRuleBlock);
  const saveRoute = useAppStore((s) => s.saveRoute);
  const addRoutingRule = useAppStore((s) => s.addRoutingRule);
  const updateRoutingRule = useAppStore((s) => s.updateRoutingRule);
  const removeRoutingRule = useAppStore((s) => s.removeRoutingRule);

  const [ruleSheet, setRuleSheet] = useState<{ rule: RoutingRule | null } | null>(null);
  const [ioOpen, setIoOpen] = useState(false);

  const profileOptions = profiles.map((p) => ({ id: p.meta.id, remarks: p.meta.remarks }));
  const route = routes.find((r) => r.id === routeId);
  const usedIn = block ? routesUsing(routes, block.id) : [];
  const elsewhere = usedIn.filter((r) => r.id !== routeId);

  if (!block) return null;

  const saveRule = (rule: RoutingRule) => {
    if (block.rules.some((r) => r.id === rule.id)) void updateRoutingRule(block.id, rule.id, rule);
    else void addRoutingRule(block.id, rule);
  };

  const takeOutOfRoute = () => {
    if (!route) return;
    void saveRoute({
      ...route,
      blocks: routeBlocks(route).filter((ref) => ref.blockId !== block.id),
    });
    onClose();
  };

  const deleteBlock = async () => {
    const ok = await confirm({
      title: t("routes.block.deleteTitle", { name: block.name }),
      body:
        usedIn.length > 0
          ? t("routes.block.deleteBodyUsed", {
              routes: formatters.formatList(usedIn.map((r) => routeName(r, t))),
            })
          : undefined,
      confirmLabel: t("routes.block.delete"),
    });
    if (!ok) return;
    void removeRuleBlock(block.id);
    onClose();
  };

  // The rule editor and import sheets sit beside this one, not inside it: a
  // sheet's transform would pin a nested fixed overlay to its own box.
  return (
    <>
      <Sheet
        open
        title={block.name}
        onClose={onClose}
        headRight={
          <IconBtn
            name="swap_vert"
            sm
            title={t("settings.routingImportExport")}
            onClick={() => setIoOpen(true)}
          />
        }
      >
        <Field
          commitOnBlur
          mono={false}
          label={t("routes.block.name")}
          value={block.name}
          onChange={(name) => name.trim() && void renameRuleBlock(block.id, name.trim())}
        />
        {elsewhere.length > 0 && (
          <div className="route-shared-note">
            <Icon name="layers" />
            <div style={{ flex: 1, minWidth: 0 }}>
              {t("routes.block.sharedNote", {
                routes: formatters.formatList(elsewhere.map((r) => routeName(r, t))),
              })}
              {route && (
                <Btn
                  variant="text"
                  sm
                  icon="content_copy"
                  style={{ marginTop: 4, marginLeft: -8 }}
                  onClick={async () => onForked(await forkRuleBlock(block.id, route.id))}
                >
                  {t("routes.block.fork", { route: routeName(route, t) })}
                </Btn>
              )}
            </div>
          </div>
        )}

        <RuleList
          block={block}
          profiles={profileOptions}
          onEditRule={(rule) => setRuleSheet({ rule })}
          onAddRule={() => setRuleSheet({ rule: null })}
        />

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 20 }}>
          {route && (
            <Btn variant="outline" icon="close" onClick={takeOutOfRoute}>
              {t("routes.block.removeFromRoute")}
            </Btn>
          )}
          <Btn variant="error" icon="delete" onClick={deleteBlock}>
            {t("routes.block.delete")}
          </Btn>
        </div>
      </Sheet>

      {ruleSheet && (
        <Suspense fallback={null}>
          <RoutingRuleSheet
            open
            rule={ruleSheet.rule}
            profiles={profileOptions}
            onClose={() => setRuleSheet(null)}
            onSave={saveRule}
            onDelete={(id) => void removeRoutingRule(block.id, id)}
          />
        </Suspense>
      )}
      {ioOpen && (
        <Suspense fallback={null}>
          <RoutingRulesIOSheet open blockId={block.id} onClose={() => setIoOpen(false)} />
        </Suspense>
      )}
    </>
  );
}
