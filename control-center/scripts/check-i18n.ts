import en from "../src/i18n/en";
import { LOCALES, loadLocale } from "../src/i18n";

const baseLang = "en";
const baseKeys = Object.keys(en).sort();
const baseKeySet = new Set(baseKeys);
let hasErrors = false;

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

if (hasErrors) process.exit(1);

console.log(
  `✅ i18n dictionaries valid (${Object.keys(LOCALES).length} locale(s), ${baseKeys.length} keys in sync)`,
);
