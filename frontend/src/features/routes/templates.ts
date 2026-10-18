// ============================================================
// features/routes/templates.ts
// Ready-made rule blocks offered when adding a block to a route. A template
// becomes an ordinary block (named in the user's language) that can be
// edited like any other.
//
// The templates themselves are single-sourced from Rust (`builtin_block_templates`)
// and reach the frontend through `generated/defaults`; this module only types
// them for the UI and turns them into rules.
//
// Domain and IP matches sit in separate rules: in one xray rule they would
// both have to match, while "a Russian site or a Russian address" is meant.
// ============================================================

import type { RoutingRule } from "../../generated/bindings";
import { BLOCK_TEMPLATES as GENERATED_BLOCK_TEMPLATES } from "../../generated/defaults";
import type { DictKey } from "../../i18n";

export type BlockTemplate = (typeof GENERATED_BLOCK_TEMPLATES)[number];
export type TemplateRule = BlockTemplate["rules"][number];

/** The ready-made blocks, single-sourced from Rust (`builtin_block_templates`). */
export const BLOCK_TEMPLATES: readonly BlockTemplate[] = GENERATED_BLOCK_TEMPLATES;

/** Compile-time type check ensuring all Rust template keys match known i18n dictionary keys. */
export const TEMPLATE_I18N_KEYS = GENERATED_BLOCK_TEMPLATES.flatMap((t) => [
  t.nameKey,
  t.hintKey,
  ...t.rules.map((r) => r.remarksKey),
]) satisfies readonly DictKey[];

/** The template's rules with names in the user's language (ids are given on save). */
export function templateRules(template: BlockTemplate, t: (key: DictKey) => string): RoutingRule[] {
  return template.rules.map((rule) => ({
    id: "",
    enabled: true,
    remarks: t(rule.remarksKey as DictKey),
    outboundTag: rule.outboundTag,
    domain: "domain" in rule && rule.domain ? [...rule.domain] : undefined,
    ip: "ip" in rule && rule.ip ? [...rule.ip] : undefined,
    network: "network" in rule ? rule.network : undefined,
    port: "port" in rule ? rule.port : undefined,
  }));
}
