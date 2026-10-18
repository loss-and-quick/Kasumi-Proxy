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

type TemplateRule = Omit<RoutingRule, "id" | "enabled" | "remarks"> & { remarksKey: DictKey };

export type BlockTemplate = {
  id: string;
  nameKey: DictKey;
  hintKey: DictKey;
  icon: string;
  rules: TemplateRule[];
};

/** The ready-made blocks, single-sourced from Rust (`builtin_block_templates`). */
export const BLOCK_TEMPLATES = GENERATED_BLOCK_TEMPLATES as unknown as BlockTemplate[];

/** The template's rules with names in the user's language (ids are given on save). */
export function templateRules(template: BlockTemplate, t: (key: DictKey) => string): RoutingRule[] {
  return template.rules.map(({ remarksKey, ...rule }) => ({
    ...rule,
    id: "",
    enabled: true,
    remarks: t(remarksKey),
  }));
}
