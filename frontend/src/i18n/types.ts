// ============================================================
// i18n/types.ts
// Dictionary/message types — keys are derived from the English catalog,
// while values may be plain strings or locale-aware message functions.
// ============================================================
import type en from "./en";
import type { MessageValue } from "./runtime";

/** Union of every translation key, derived from the en dictionary. */
export type DictKey = keyof typeof en;

/** A complete dictionary: every key mapped to a string or a message function. */
export type Dict = Record<DictKey, MessageValue>;
