// ============================================================
// features/settings/rule-presets.ts
// Quick-add templates for common routing rules. Each preset becomes a
// full RoutingRule (with a generated id) when the user taps it.
// ============================================================

import type { RoutingRule } from "../../generated/bindings";
import type { DictKey } from "../../i18n";
import { uid } from "../../lib/utils";

export type RulePreset = {
  id: string;
  labelKey: DictKey;
  icon: string;
  rule: Omit<RoutingRule, "id" | "remarks" | "enabled">;
};

export const RULE_PRESETS: RulePreset[] = [
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

export function makePresetRule(preset: RulePreset, name: string): RoutingRule {
  return { id: uid(), remarks: name, enabled: true, ...preset.rule };
}
