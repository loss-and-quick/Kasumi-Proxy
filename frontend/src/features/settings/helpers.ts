import { z } from "zod";
import type { CoreEngine, Protocol, RoutingRule } from "../../generated/bindings";
import { DEFAULT_CORE_BY_PROTOCOL, PROTOCOL_OPTS } from "../../generated/defaults";
import { RoutingRule_DeserializeSchema, RoutingRuleSchema } from "../../generated/schemas";
import type { DictKey, I18nFormatters, Translate } from "../../i18n";
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

const MAX_PORT = 65535;

function portCoversEveryPort(port: string | null | undefined): boolean {
  if (!port?.trim()) return false;
  const ranges: [number, number][] = [];
  for (const item of port.split(",")) {
    const part = item.trim();
    if (!part) continue;
    const [lo, hi] = part.includes("-") ? part.split("-") : [part, part];
    const from = Number(lo);
    const to = Number(hi);
    if (!Number.isInteger(from) || !Number.isInteger(to)) return false;
    ranges.push([Math.min(from, to), Math.max(from, to)]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  let reached = 0;
  for (const [from, to] of ranges) {
    if (from > reached + 1) break;
    reached = Math.max(reached, to);
  }
  return reached >= MAX_PORT;
}

/** Whether the rule matches every connection, making the rules below it dead. */
export function isCatchAllRule(rule: RoutingRule): boolean {
  if (!rule.enabled) return false;
  if (rule.domain?.length || rule.ip?.length || rule.protocol?.length) return false;
  if (rule.network && rule.network !== "tcp,udp") return false;
  return portCoversEveryPort(rule.port);
}

/**
 * Whether the catch-all at `index` shadows nothing but the automatic tail, which
 * already ends in the proxy fallback — so the rule costs the IP check and buys nothing.
 */
export function isRedundantCatchAll(rules: RoutingRule[], index: number): boolean {
  if (index < 0 || rules[index]?.outboundTag !== "proxy") return false;
  return !rules.slice(index + 1).some((rule) => rule.enabled);
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

const V2rayNGRulesetItemSchema = RoutingRule_DeserializeSchema.omit({
  id: true,
  remarks: true,
}).extend({
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

// ------------------------------------------------------------
// Core-per-protocol presets
// ------------------------------------------------------------

/** Protocols only one core implements (hysteria2/tuic are sing-box-only; a custom
 *  config is written for its own core), so the user can't reassign them. */
export const LOCKED_CORE_PROTOCOLS: readonly Protocol[] = ["hysteria2", "tuic", "custom"];

export type CoresPreset = "default" | CoreEngine | "custom";
type CoreMap = Partial<Record<Protocol, CoreEngine>>;

const switchable = PROTOCOL_OPTS.filter((p) => !LOCKED_CORE_PROTOCOLS.includes(p));

const effectiveCore = (map: CoreMap | undefined, protocol: Protocol): CoreEngine =>
  map?.[protocol] ?? DEFAULT_CORE_BY_PROTOCOL[protocol];

/** Which preset the stored map amounts to. Only switchable protocols count, so a
 *  stale override on a locked protocol doesn't turn the map into "custom". */
export function coresPreset(map: CoreMap | undefined): CoresPreset {
  if (switchable.every((p) => effectiveCore(map, p) === DEFAULT_CORE_BY_PROTOCOL[p])) {
    return "default";
  }
  for (const core of ["xray", "sing-box"] as const) {
    if (switchable.every((p) => effectiveCore(map, p) === core)) return core;
  }
  return "custom";
}

/** The map a preset stands for: `{}` defers to the per-protocol defaults; a single
 *  core pins every switchable protocol to it and leaves the locked ones alone. */
export function applyCoresPreset(preset: Exclude<CoresPreset, "custom">): CoreMap {
  if (preset === "default") return {};
  return Object.fromEntries(switchable.map((p) => [p, preset]));
}
