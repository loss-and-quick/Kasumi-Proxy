import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { LOCALES, loadLocale } from "../src/i18n";
import en from "../src/i18n/en";

const baseLang = "en";
const baseKeys = Object.keys(en).sort();
const baseKeySet = new Set(baseKeys);
let hasErrors = false;

// 1. Every locale must carry the exact same key set as the base.
for (const lang of Object.keys(LOCALES)) {
  const dict = await loadLocale(lang as keyof typeof LOCALES);
  const keys = Object.keys(dict).sort();
  const keySet = new Set(keys);
  const missing = baseKeys.filter((key) => !keySet.has(key));
  const extra = keys.filter((key) => !baseKeySet.has(key));

  if (missing.length === 0 && extra.length === 0) continue;

  hasErrors = true;
  console.error(`\n❌ ${lang} dictionary is out of sync with ${baseLang}:`);
  if (missing.length > 0) {
    console.error(`  missing (${missing.length}): ${missing.join(", ")}`);
  }
  if (extra.length > 0) {
    console.error(`  extra (${extra.length}): ${extra.join(", ")}`);
  }
}

// 2. No stale keys: every base key must be referenced somewhere in the app source.
// Keys are always used as quoted string literals (`t("…")`, `labelKey: "…"`), never
// built dynamically, so a quoted-substring scan over the source (minus the
// dictionaries + generated code) is exact. A key found only in its own dictionary
// is dead weight — fail so it gets removed.
const srcDir = join(dirname(fileURLToPath(import.meta.url)), "../src");
const SKIP_DIRS = new Set(["i18n", "generated"]);

function readSources(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(entry)) readSources(full, acc);
    } else if (/\.(ts|tsx)$/.test(entry)) {
      acc.push(readFileSync(full, "utf8"));
    }
  }
  return acc;
}

const haystack = readSources(srcDir).join("\n");
const referenced = (key: string) =>
  haystack.includes(`"${key}"`) || haystack.includes(`'${key}'`) || haystack.includes(`\`${key}\``);

const stale = baseKeys.filter((key) => !referenced(key));
if (stale.length > 0) {
  hasErrors = true;
  console.error(`\n❌ stale i18n keys (defined but never referenced) (${stale.length}):`);
  for (const key of stale) console.error(`  ${key}`);
}

if (hasErrors) process.exit(1);

console.log(
  `✅ i18n dictionaries valid (${Object.keys(LOCALES).length} locale(s), ${baseKeys.length} keys in sync, no stale keys)`,
);
