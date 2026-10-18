// ============================================================
// lib/geo-assets.ts
// Detect which geo asset files (geosite.dat, geoip.dat) the active
// routing configuration requires, and which are missing on disk.
// ============================================================

import type {
  AdvancedSettings,
  AssetFile,
  CoreEngine,
  Profile,
  Route,
} from "../generated/bindings";
import { type RuleBlock, refEnabled, routeBlocks, routeFor } from "./routes";

export type MissingGeoCheckParams = {
  settings: AdvancedSettings;
  routes: Route[];
  ruleBlocks: RuleBlock[];
  activeProfile?: Profile | null;
  assetFiles: AssetFile[];
  resolvedCore?: CoreEngine | null;
};

/**
 * Returns filenames of required geo assets (e.g. `["geosite.dat"]`, `["geoip.dat"]`)
 * that are missing (not downloaded / not updated).
 */
export function getMissingGeoAssets({
  settings,
  routes,
  ruleBlocks,
  activeProfile,
  assetFiles,
  resolvedCore,
}: MissingGeoCheckParams): string[] {
  if (settings.routingMode === "global") {
    return [];
  }

  const needed = new Set<string>();

  if (settings.routingMode === "custom") {
    const raw = settings.customRouting ?? "";
    if (raw.includes("geosite:") || raw.includes("geosite.dat")) {
      needed.add("geosite.dat");
    }
    if (raw.includes("geoip:") || raw.includes("geoip.dat")) {
      needed.add("geoip.dat");
    }
  } else if (settings.routingMode === "rules") {
    const activeRoute = routeFor(routes, activeProfile ?? undefined);
    if (activeRoute) {
      const blockMap = new Map(ruleBlocks.map((b) => [b.id, b]));
      for (const ref of routeBlocks(activeRoute)) {
        if (!refEnabled(ref)) continue;
        const block = blockMap.get(ref.blockId);
        if (!block) continue;
        for (const rule of block.rules) {
          if (!rule.enabled) continue;
          if (rule.domain?.some((d) => d.startsWith("geosite:") || d.includes("geosite.dat"))) {
            needed.add("geosite.dat");
          }
          if (
            rule.ip?.some((ip) => {
              if (ip.includes("geoip.dat")) return true;
              if (ip.startsWith("geoip:")) {
                // On sing-box, geoip:private and geoip:!private are converted
                // to built-in ip_is_private without requiring geoip.dat.
                if (
                  resolvedCore === "sing-box" &&
                  (ip === "geoip:private" || ip === "geoip:!private")
                ) {
                  return false;
                }
                return true;
              }
              return false;
            })
          ) {
            needed.add("geoip.dat");
          }
        }
      }
    }
    // Xray fake-dns generates expectIPs: ["geoip:!private"]
    if (resolvedCore === "xray" && settings.fakeDns) {
      needed.add("geoip.dat");
    }
  }

  if (needed.size === 0) {
    return [];
  }

  const missing: string[] = [];
  for (const file of needed) {
    const hasAsset = assetFiles.some(
      (a) => (a.remarks === file || a.id === file.replace(/\.dat$/, "")) && a.lastUpdated != null,
    );
    if (!hasAsset) {
      missing.push(file);
    }
  }

  return missing.sort();
}
