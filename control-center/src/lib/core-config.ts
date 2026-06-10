// ============================================================
// src/lib/core-config.ts
// Resolve the core engine for a profile and build the exact config
// JSON that `kasumi-proxyctl start` would receive. Shared by the
// bridge (to launch the core) and the store (to decide whether an
// active profile actually needs a restart after a subscription
// update — see activeConfigChanged).
// ============================================================

import {
  type AdvancedSettings,
  type CoreEngineT,
  type Profile,
  type RoutingRule,
  resolveCore,
} from "./schema";
import { buildSingboxConfigJSON } from "./singbox-config";
import { buildXrayConfigJSON } from "./xray-config";

export interface CoreConfig {
  engine: CoreEngineT;
  config: string;
}

/** Engine + config JSON for a profile, mirroring what the core is launched with. */
export function buildCoreConfig(
  profile: Profile,
  settings: AdvancedSettings,
  routingRules: RoutingRule[],
  profiles: Profile[],
): CoreConfig {
  const engine = resolveCore(profile, settings);
  const config =
    engine === "sing-box"
      ? buildSingboxConfigJSON(profile, settings, routingRules, profiles)
      : buildXrayConfigJSON(profile, settings, routingRules, profiles);
  return { engine, config };
}

/** True when two resolved core configs differ — i.e. the core must be restarted. */
export function activeConfigChanged(prev: CoreConfig, next: CoreConfig): boolean {
  return prev.engine !== next.engine || prev.config !== next.config;
}
