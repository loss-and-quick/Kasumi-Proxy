// ============================================================
// src/lib/schema/settings.ts
// Groups, subscriptions, global advanced settings and the top-level
// app state. All inferred from Zod (single source of truth).
// ============================================================
import { z } from "zod";
import { CoreEngine } from "./enums";
import { PROTOCOLS, ProfileSchema } from "./profile";

export const GroupSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  subId: z.string().optional(),
});

export const SubscriptionSchema = z.object({
  id: z.string().min(1),
  remarks: z.string().min(1, "Remarks required"),
  url: z.string().min(1, "Subscription URL required"),
  enabled: z.boolean(),
  groupId: z.string().optional(),
  autoUpdate: z.boolean(),
  interval: z.coerce.number().int().positive(),
  allowInsecure: z.boolean(),
  userAgent: z.string(),
  filter: z.string(),
  updateMode: z.enum(["auto", "proxy", "direct"]).default("auto"),
  lastUpdated: z.string(),
  count: z.coerce.number().int().min(0),
  lastError: z.string().nullable().optional(),
  prevProfile: z.string().nullable().optional(),
  nextProfile: z.string().nullable().optional(),
});

export const RoutingRuleSchema = z.object({
  id: z.string().min(1),
  remarks: z.string(),
  enabled: z.boolean(),
  outboundTag: z.string().min(1),
  domain: z.array(z.string()).optional(),
  ip: z.array(z.string()).optional(),
  port: z.string().optional(),
  network: z.enum(["tcp", "udp", "tcp,udp"]).optional(),
  protocol: z.array(z.string()).optional(),
});

export const AssetFileSchema = z.object({
  id: z.string().min(1),
  remarks: z.string().min(1),
  url: z.string(),
  lastUpdated: z.number().nullable(),
  locked: z.boolean(),
});

export const AdvancedSettingsSchema = z.object({
  routingMode: z.preprocess(
    (v) => (v === "bypass-lan" ? "global" : v),
    z.enum(["global", "custom", "rules"]).default("global"),
  ),
  domainSniffing: z.boolean().default(true),
  routeOnly: z.boolean().default(false),
  domainStrategy: z.enum(["AsIs", "IPIfNonMatch", "IPOnDemand"]).default("IPIfNonMatch"),
  domainStrategy4Singbox: z
    .enum(["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"])
    .default("prefer_ipv4"),
  dnsViaProxy: z.boolean().default(true),
  fakeDns: z.boolean().default(false),
  preferIpv6: z.boolean().default(false),
  mux: z.boolean().default(false),
  muxConcurrency: z.coerce.number().int().min(1).default(8),
  pingConcurrency: z.coerce.number().int().min(1).max(20).default(3),
  speedConcurrency: z.coerce.number().int().min(1).max(5).default(1),
  autoStart: z.boolean().default(true),
  muxXudpConcurrency: z.coerce.number().int().optional(),
  muxXudp443: z.enum(["reject", "proxy"]).optional(),
  fragment: z.boolean().default(false),
  fragmentPackets: z.string().default("tlshello"),
  mtu: z.coerce.number().int().min(1).default(1350),
  fragmentLength: z.string().optional(),
  fragmentDelay: z.string().optional(),
  logLevel: z.enum(["debug", "info", "warning", "error", "none"]).optional(),
  logRotateMaxKb: z.coerce.number().int().min(64).default(512),
  localSocksPort: z.coerce.number().int().min(1).max(65535).optional(),
  localHttpPort: z.coerce.number().int().min(1).max(65535).optional(),
  // DNS / routing (v2rayNG parity)
  remoteDns: z.string().optional(), // DNS used through the proxy
  domesticDns: z.string().optional(), // DNS used for direct/bypass
  dnsHosts: z.string().optional(), // static host overrides (raw JSON or "host=ip" lines)
  ipv6Enabled: z.boolean().optional(),
  socksUsername: z.string().optional(),
  socksPassword: z.string().optional(),
  delayTestUrl: z.string().optional(),
  speedTestUrl: z.string().optional(),
  customRouting: z.string().optional(), // raw JSON routing rules (routingMode "custom")
  // per-protocol default core (v2rayN CoreTypeItem). Partial; missing = fallback.
  coreByProtocol: z.partialRecord(z.enum(PROTOCOLS), CoreEngine).default({}),
  appCaptureMode: z.enum(["all", "none"]).default("all"),
  appFilter: z.record(z.string(), z.enum(["force-proxy", "bypass"])).default({}),
});

export const AppStateSchema = z.object({
  // Invalid profiles are dropped (not fatal) so one bad entry from a public
  // subscription can't brick the whole app. Each drop is logged with its reason
  // for debugging; the import flow surfaces a skipped-count to the user.
  profiles: z
    .array(z.unknown())
    .default([])
    .transform((arr) =>
      arr.flatMap((p) => {
        const r = ProfileSchema.safeParse(p);
        if (r.success) return [r.data];
        const label =
          (p && typeof p === "object" && "remarks" in p && (p as { remarks?: unknown }).remarks) ||
          (p && typeof p === "object" && "id" in p && (p as { id?: unknown }).id) ||
          "?";
        console.warn(`[KP] skipped invalid profile "${String(label)}":`, r.error.issues);
        return [];
      }),
    ),
  groups: z.array(GroupSchema),
  subscriptions: z.array(SubscriptionSchema),
  routingRules: z.array(RoutingRuleSchema).default([]),
  assetFiles: z.array(AssetFileSchema).default([]),
  settings: AdvancedSettingsSchema,
  activeId: z.string().nullable(),
  // Module version (module.prop) that last wrote this state. Absent on legacy
  // pre-versioning state, which is the trigger for one-time migrations in
  // hydrate() (e.g. subscription `interval` hours→minutes). Newer migrations
  // can semver-compare this against the current build's __MODULE_VERSION__.
  version: z.string().optional(),
});

/* ---------- inferred domain types ---------- */
export type Group = z.infer<typeof GroupSchema>;
export type Subscription = z.infer<typeof SubscriptionSchema>;
export type RoutingRule = z.infer<typeof RoutingRuleSchema>;
export type AssetFile = z.infer<typeof AssetFileSchema>;
export type AdvancedSettings = z.infer<typeof AdvancedSettingsSchema>;
export type AppState = z.infer<typeof AppStateSchema>;
