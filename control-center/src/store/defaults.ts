import type { AdvancedSettings } from "../lib/bridge";

export const EMPTY_SETTINGS: AdvancedSettings = {
  routingMode: "global",
  domainSniffing: true,
  routeOnly: false,
  domainStrategy: "IPIfNonMatch",
  domainStrategy4Singbox: "prefer_ipv4",
  dnsViaProxy: true,
  fakeDns: false,
  preferIpv6: false,
  mux: false,
  muxConcurrency: 8,
  pingConcurrency: 3,
  speedConcurrency: 1,
  autoStart: true,
  muxXudpConcurrency: 8,
  muxXudp443: "reject",
  fragment: false,
  fragmentPackets: "tlshello",
  mtu: 1350,
  ipv6Enabled: false,
  delayTestUrl: "https://www.gstatic.com/generate_204",
  speedTestUrl: "http://speed.cloudflare.com/__down?bytes=10000000",
  coreByProtocol: {},
  appCaptureMode: "all",
  appFilter: {},
  logRotateMaxKb: 512,
  dedupOnUpdate: false,
  allowNonLocalhost: false,
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
