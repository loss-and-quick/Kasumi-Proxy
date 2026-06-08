import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The release version from module.prop — the single source of truth shared by
 * the Vite build and Vitest, injected into the bundle as __MODULE_VERSION__ so
 * the UI never hardcodes the release number.
 */
export function readModuleVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const prop = readFileSync(resolve(here, "../../module/module.prop"), "utf8");
    return prop.match(/^version=(.+)$/m)?.[1]?.trim() ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}
