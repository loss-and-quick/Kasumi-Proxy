import {
  DEFAULT_ADVANCED_SETTINGS,
  DEFAULT_DELAY_TEST_URL,
  DEFAULT_SPEED_TEST_URL,
} from "../generated/defaults";
import type { AdvancedSettings } from "../lib/bridge";

// The app's runtime default settings: the Rust serde defaults (generated, the single
// source) plus the few optional fields the UI surfaces with a concrete value where
// Rust leaves them unset (`None`).
export const EMPTY_SETTINGS: AdvancedSettings = {
  ...DEFAULT_ADVANCED_SETTINGS,
  muxXudpConcurrency: 8,
  muxXudp443: "reject",
  ipv6Enabled: false,
  delayTestUrl: DEFAULT_DELAY_TEST_URL,
  speedTestUrl: DEFAULT_SPEED_TEST_URL,
};

export function mergeSettings(settings?: Partial<AdvancedSettings>): AdvancedSettings {
  const merged: AdvancedSettings = {
    ...EMPTY_SETTINGS,
    ...Object.fromEntries(
      Object.entries(settings ?? {}).filter(([, value]) => value !== undefined),
    ),
  };
  // Legacy: the "bypass-lan" mode was removed; LAN bypass is now unconditional.
  if ((merged.routingMode as string) === "bypass-lan") merged.routingMode = "global";
  // Migration: drop old pkg-only appFilter keys (new format is pkg:uid).
  merged.appFilter = Object.fromEntries(
    Object.entries(merged.appFilter).filter(([k]) => k.includes(":")),
  ) as AdvancedSettings["appFilter"];
  return merged;
}
