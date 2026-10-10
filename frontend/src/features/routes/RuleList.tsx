// ============================================================
// features/routes/RuleList.tsx
// The rules of one block: drag to reorder, a switch per rule, tap to edit,
// and the quick-add chips for common rules.
// ============================================================

import { closestCenter, DndContext, type DragEndEvent } from "@dnd-kit/core";
import { SortableContext, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { Btn, Chip, ListRow, Sortable, Switch, useSortableSensors } from "../../components";
import type { RoutingRule } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import type { RuleBlock } from "../../lib/routes";
import { useAppStore } from "../../store/useAppStore";
import { isCatchAllRule, isRedundantCatchAll, ruleIcon, ruleSummary } from "../settings/helpers";
import { makeQuickRule, QUICK_RULES } from "../settings/rule-presets";

export function RuleList({
  block,
  profiles,
  onEditRule,
  onAddRule,
}: {
  block: RuleBlock;
  profiles: { id: string; remarks: string }[];
  onEditRule: (rule: RoutingRule) => void;
  onAddRule: () => void;
}) {
  const t = useT();
  const formatters = useFormatters();
  const sensors = useSortableSensors();
  const addRoutingRule = useAppStore((s) => s.addRoutingRule);
  const updateRoutingRule = useAppStore((s) => s.updateRoutingRule);
  const reorderRoutingRules = useAppStore((s) => s.reorderRoutingRules);
  const rules = block.rules;
  const profileName = (tag: string) => profiles.find((p) => p.id === tag)?.remarks;
  const onDragEnd = ({ active, over }: DragEndEvent) => {
    if (!over || active.id === over.id) return;
    const from = rules.findIndex((r) => r.id === active.id);
    const to = rules.findIndex((r) => r.id === over.id);
    if (from !== -1 && to !== -1) void reorderRoutingRules(block.id, from, to);
  };
  const catchAllIndex = rules.findIndex(isCatchAllRule);
  const catchAllRedundant = isRedundantCatchAll(rules, catchAllIndex);

  return (
    <>
      {rules.length === 0 ? (
        <div className="hint" style={{ padding: "4px 0 8px" }}>
          {t("routes.block.empty")}
        </div>
      ) : (
        // Delete lives in the rule sheet and reorder is a drag handle, so a
        // narrow phone row keeps room for the summary instead of four buttons.
        <div className="routing-rules">
          <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
            <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
              {rules.map((rule, index) => (
                <Sortable key={rule.id} id={rule.id}>
                  {(bindings) => (
                    <ListRow
                      drag={{ bindings, label: t("settings.routingReorder") }}
                      icon={ruleIcon(rule)}
                      title={rule.remarks || t("settings.routingRuleDefault", { n: index + 1 })}
                      sub={
                        <>
                          {ruleSummary(rule, t, formatters, profileName)}
                          {index === catchAllIndex && (
                            <div style={{ color: "var(--warn)", marginTop: 2 }}>
                              {t(
                                catchAllRedundant
                                  ? "settings.routingCatchAllRedundant"
                                  : "routes.block.catchAll",
                              )}
                            </div>
                          )}
                          {catchAllIndex >= 0 && index > catchAllIndex && rule.enabled && (
                            <div style={{ color: "var(--on-surface-faint)", marginTop: 2 }}>
                              {t("settings.routingUnreachable")}
                            </div>
                          )}
                        </>
                      }
                      onClick={() => onEditRule(rule)}
                      right={
                        <Switch
                          on={rule.enabled}
                          onChange={(value) =>
                            void updateRoutingRule(block.id, rule.id, { enabled: value })
                          }
                          label={rule.remarks}
                        />
                      }
                    />
                  )}
                </Sortable>
              ))}
            </SortableContext>
          </DndContext>
        </div>
      )}
      <Btn variant="tonal" sm icon="add" onClick={onAddRule} style={{ marginTop: 10 }}>
        {t("settings.routingAddRule")}
      </Btn>
      <div className="hint" style={{ margin: "14px 0 6px" }}>
        {t("settings.rulePresets")}
      </div>
      {/* One scrollable line: wrapped chips took three rows on a phone. */}
      <div className="chip-scroller">
        {QUICK_RULES.map((quick) => (
          <Chip
            key={quick.id}
            icon={quick.icon}
            onClick={() => void addRoutingRule(block.id, makeQuickRule(quick, t(quick.labelKey)))}
          >
            {t(quick.labelKey)}
          </Chip>
        ))}
      </div>
    </>
  );
}
