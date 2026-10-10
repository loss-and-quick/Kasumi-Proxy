// ============================================================
// features/settings/rule-presets.ts
// Quick-add templates for common single rules. Each one becomes a full
// RoutingRule (with a generated id) in the open block when the user taps it.
// ============================================================

import type { RoutingRule } from "../../generated/bindings";
import type { DictKey } from "../../i18n";
import { uid } from "../../lib/utils";

export type QuickRule = {
  id: string;
  labelKey: DictKey;
  icon: string;
  rule: Omit<RoutingRule, "id" | "remarks" | "enabled">;
};

export const QUICK_RULES: QuickRule[] = [
  {
    id: "ads",
    labelKey: "settings.rulePreset.ads",
    icon: "block",
    rule: { outboundTag: "block", domain: ["geosite:category-ads-all"] },
  },
  {
    id: "private",
    labelKey: "settings.rulePreset.private",
    icon: "near_me",
    rule: { outboundTag: "direct", ip: ["geoip:private"] },
  },
  {
    id: "cn",
    labelKey: "settings.rulePreset.cn",
    icon: "public",
    rule: { outboundTag: "direct", domain: ["geosite:cn"], ip: ["geoip:cn"] },
  },
  {
    id: "quic",
    labelKey: "settings.rulePreset.blockQuic",
    icon: "block",
    rule: { outboundTag: "block", network: "udp", port: "443" },
  },
];

export function makeQuickRule(quick: QuickRule, name: string): RoutingRule {
  return { id: uid(), remarks: name, enabled: true, ...quick.rule };
}
