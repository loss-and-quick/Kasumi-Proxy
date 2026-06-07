import { z } from "zod";
import type { DictKey, I18nFormatters, Translate } from "../../i18n";
import { type Protocol, type RoutingRule, RoutingRuleSchema } from "../../lib/schema";
import { uid } from "../../lib/utils";

const PROTOCOL_LABEL_KEYS: Record<Protocol, DictKey> = {
  anytls: "settings.protocol.anytls",
  custom: "settings.protocol.custom",
  http: "settings.protocol.http",
  hysteria2: "settings.protocol.hysteria2",
  naive: "settings.protocol.naive",
  shadowsocks: "settings.protocol.shadowsocks",
  shadowtls: "settings.protocol.shadowtls",
  socks: "settings.protocol.socks",
  trojan: "settings.protocol.trojan",
  tuic: "settings.protocol.tuic",
  vless: "settings.protocol.vless",
  vmess: "settings.protocol.vmess",
  wireguard: "settings.protocol.wireguard",
};

const OUTBOUND_LABEL_KEYS = {
  block: "routingSheet.outbound.block",
  direct: "routingSheet.outbound.direct",
  proxy: "routingSheet.outbound.proxy",
} as const satisfies Record<string, DictKey>;

export function protocolLabel(t: Translate, protocol: Protocol): string {
  return t(PROTOCOL_LABEL_KEYS[protocol]);
}

function outboundLabel(
  tag: string,
  t: Translate,
  resolveName?: (tag: string) => string | undefined,
): string {
  const key = OUTBOUND_LABEL_KEYS[tag as keyof typeof OUTBOUND_LABEL_KEYS];
  if (key) return t(key);
  return resolveName?.(tag) ?? tag;
}

export function ruleSummary(
  rule: RoutingRule,
  t: Translate,
  formatters: I18nFormatters,
  resolveOutboundName?: (tag: string) => string | undefined,
): string {
  const parts: string[] = [];
  if (rule.domain?.length)
    parts.push(t("settings.routingRuleDomains", { count: rule.domain.length }));
  if (rule.ip?.length) parts.push(t("settings.routingRuleIps", { count: rule.ip.length }));
  if (rule.port) parts.push(t("settings.routingRulePort", { value: rule.port }));
  if (rule.network) parts.push(t("settings.routingRuleNetwork", { value: rule.network }));
  if (rule.protocol?.length)
    parts.push(
      t("settings.routingRuleProtocols", {
        value: formatters.formatList(rule.protocol),
      }),
    );
  if (!parts.length) parts.push(t("settings.routingRuleNoMatch"));
  parts.push(`→ ${outboundLabel(rule.outboundTag, t, resolveOutboundName)}`);
  return parts.join(" · ");
}

export function ruleIcon(rule: RoutingRule): string {
  if (rule.outboundTag === "direct") return "near_me";
  if (rule.outboundTag === "block") return "block";
  return "alt_route";
}

export function formatUpdatedAt(
  value: number | null,
  t: Translate,
  formatters: I18nFormatters,
): string {
  return value ? formatters.formatDateTime(value) : t("settings.assetNotDownloaded");
}

const V2rayNGRulesetItemSchema = RoutingRuleSchema.omit({ id: true, remarks: true }).extend({
  remarks: z.string().optional(),
});
const RulesArraySchema = z.union([
  z.array(RoutingRuleSchema),
  z.array(V2rayNGRulesetItemSchema).transform((items) =>
    items.map((item) => ({
      ...item,
      id: uid(),
      remarks: item.remarks ?? "",
    })),
  ),
]);

export function parseRoutingRulesJson(text: string): { ok: boolean; rules: RoutingRule[] } {
  try {
    const result = RulesArraySchema.safeParse(JSON.parse(text));
    if (result.success) return { ok: result.data.length > 0, rules: result.data };
  } catch {
    // fall through
  }
  return { ok: false, rules: [] };
}
