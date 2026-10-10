// ============================================================
// features/routes/templates.ts
// Ready-made rule blocks offered when adding a block to a route. A template
// becomes an ordinary block (named in the user's language) that can be
// edited like any other.
//
// Domain and IP matches sit in separate rules: in one xray rule they would
// both have to match, while "a Russian site or a Russian address" is meant.
// ============================================================

import type { RoutingRule } from "../../generated/bindings";
import type { DictKey } from "../../i18n";

type TemplateRule = Omit<RoutingRule, "id" | "enabled" | "remarks"> & { remarksKey: DictKey };

export type BlockTemplate = {
  id: string;
  nameKey: DictKey;
  hintKey: DictKey;
  icon: string;
  rules: TemplateRule[];
};

export const BLOCK_TEMPLATES: BlockTemplate[] = [
  {
    id: "ads",
    nameKey: "routes.template.ads",
    hintKey: "routes.template.adsHint",
    icon: "block",
    rules: [
      {
        remarksKey: "routes.template.ads",
        outboundTag: "block",
        domain: ["geosite:category-ads-all"],
      },
    ],
  },
  {
    id: "lan",
    nameKey: "routes.template.lan",
    hintKey: "routes.template.lanHint",
    icon: "lan",
    rules: [{ remarksKey: "routes.template.lan", outboundTag: "direct", ip: ["geoip:private"] }],
  },
  {
    id: "ru",
    nameKey: "routes.template.ru",
    hintKey: "routes.template.ruHint",
    icon: "public",
    rules: [
      {
        remarksKey: "routes.template.sites",
        outboundTag: "direct",
        domain: ["geosite:category-ru"],
      },
      { remarksKey: "routes.template.addresses", outboundTag: "direct", ip: ["geoip:ru"] },
    ],
  },
  {
    id: "cn",
    nameKey: "routes.template.cn",
    hintKey: "routes.template.cnHint",
    icon: "public",
    rules: [
      { remarksKey: "routes.template.sites", outboundTag: "direct", domain: ["geosite:cn"] },
      { remarksKey: "routes.template.addresses", outboundTag: "direct", ip: ["geoip:cn"] },
    ],
  },
  {
    id: "quic",
    nameKey: "routes.template.quic",
    hintKey: "routes.template.quicHint",
    icon: "block",
    rules: [
      {
        remarksKey: "routes.template.quic",
        outboundTag: "block",
        network: "udp",
        port: "443",
      },
    ],
  },
];

/** The template's rules with names in the user's language (ids are given on save). */
export function templateRules(template: BlockTemplate, t: (key: DictKey) => string): RoutingRule[] {
  return template.rules.map(({ remarksKey, ...rule }) => ({
    ...rule,
    id: "",
    enabled: true,
    remarks: t(remarksKey),
  }));
}
