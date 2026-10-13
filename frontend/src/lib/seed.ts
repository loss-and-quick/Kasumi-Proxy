// ============================================================
// src/lib/seed.ts
// Seed data for development with the mock bridge.
// Based on Kasumi Proxy/data.jsx
// ============================================================

import type {
  AssetFile,
  Endpoint,
  Meta,
  Profile,
  Protocol,
  Route,
  RoutingRule,
  Tls,
  Transport,
} from "../generated/bindings";
import { EMPTY_SETTINGS } from "../store/defaults";
import type { AdvancedSettings, AppState, AuditEntry, PendingChange, Subscription } from "./bridge";
import { emptyProfile, type ProfileOf } from "./profile-utils";
import { DEFAULT_ROUTE_ID, newRoute, type RuleBlock } from "./routes";

const uid = () => Math.random().toString(36).slice(2, 9);

/** Build a nested seed profile with sub-object + root-field overrides. */
function mk<P extends Protocol>(
  protocol: P,
  o: {
    meta?: Partial<Meta>;
    endpoint?: Partial<Endpoint>;
    tls?: Partial<Tls>;
    transport?: Transport;
    root?: Record<string, unknown>;
  } = {},
): ProfileOf<P> {
  const base = emptyProfile(protocol) as ProfileOf<P>;
  base.meta = { ...base.meta, id: uid(), ...o.meta };
  if (o.endpoint && "endpoint" in base) base.endpoint = { ...base.endpoint, ...o.endpoint };
  if (o.tls && "tls" in base) base.tls = { ...base.tls, ...o.tls };
  if (o.transport && "transport" in base) base.transport = o.transport;
  if (o.root) Object.assign(base, o.root);
  return base;
}

export const GROUPS_SEED = [
  { id: "g-main", name: "Main" },
  { id: "g-de", name: "🇩🇪 Frankfurt" },
  { id: "g-nl", name: "🇳🇱 Amsterdam" },
  { id: "g-priv", name: "Private" },
];

// Expiry dates relative to now, so the dev seed shows each expiry state.
const inDays = (days: number) => Math.floor(Date.now() / 1000) + days * 86_400;
const GB = 1024 ** 3;

// What a provider proposes in the dev seed: one change of each kind the review shows.
const daysAgo = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
const AURORA_PENDING: PendingChange[] = [
  {
    key: "new-domain",
    value: "aurora-vpn.example.com",
    previous:
      "https://aurora.example.net/api/v1/client/subscribe?token=9f2c1ab7d4e8&flow=xtls-rprx-vision",
    risk: "trustBoundary",
    action: {
      kind: "replaceDomain",
      url: "https://aurora-vpn.example.com/api/v1/client/subscribe?token=9f2c1ab7d4e8&flow=xtls-rprx-vision",
      fromHost: "aurora.example.net",
      toHost: "aurora-vpn.example.com",
      otherDomain: true,
    },
    digest: "seed-new-domain",
    seenAt: daysAgo(1),
  },
  {
    key: "fallback-url",
    value: "https://mirror.aurora.example.net/api/v1/client/subscribe?token=9f2c1ab7d4e8",
    previous: null,
    risk: "trustBoundary",
    action: {
      kind: "setFallbackUrl",
      url: "https://mirror.aurora.example.net/api/v1/client/subscribe?token=9f2c1ab7d4e8",
      host: "mirror.aurora.example.net",
    },
    digest: "seed-fallback",
    seenAt: daysAgo(1),
  },
  {
    key: "routing",
    value: "Aurora RU direct",
    risk: "trustBoundary",
    action: {
      kind: "importRouting",
      activate: true,
      routing: {
        name: "Aurora RU direct",
        directSites: ["geosite:category-ru", "domain:gosuslugi.ru", "domain:yandex.ru"],
        directIp: ["geoip:ru", "geoip:private"],
        proxySites: [],
        proxyIp: [],
        blockSites: ["geosite:category-ads-all"],
        blockIp: [],
        globalProxy: null,
        ignoredFields: ["DomainStrategy", "RemoteDnsType", "RemoteDnsDomain", "Geoipurl"],
      },
    },
    digest: "seed-routing",
    seenAt: daysAgo(2),
  },
  {
    key: "mux-enable",
    value: "true",
    previous: "false",
    risk: "tunnelBehaviour",
    action: { kind: "tunnelSetting", setting: { kind: "mux", on: true } },
    digest: "seed-mux",
    seenAt: daysAgo(2),
  },
  {
    key: "fragmentation-length",
    value: "100-200",
    risk: "tunnelBehaviour",
    action: { kind: "tunnelSetting", setting: { kind: "fragmentLength", value: "100-200" } },
    digest: "seed-fragment-length",
    seenAt: daysAgo(2),
  },
  {
    key: "noises-enable",
    value: "true",
    risk: "tunnelBehaviour",
    action: { kind: "unsupported" },
    digest: "seed-noises",
    seenAt: daysAgo(2),
  },
  {
    key: "per-app-proxy-list",
    value: "com.android.chrome,org.telegram.messenger",
    risk: "trustBoundary",
    action: { kind: "unsupported" },
    digest: "seed-per-app",
    seenAt: daysAgo(2),
  },
];

const AURORA_AUDIT: AuditEntry[] = [
  { at: daysAgo(1), key: "new-domain", outcome: "offered", summary: "aurora-vpn.example.com" },
  {
    at: daysAgo(1),
    key: "fallback-url",
    outcome: "offered",
    summary: "https://mirror.aurora.example.net/api/v1/client/subscribe?token=9f2c1ab7d4e8",
  },
  { at: daysAgo(2), key: "routing", outcome: "offered", summary: "Aurora RU direct" },
  { at: daysAgo(2), key: "mux-enable", outcome: "offered", summary: "true" },
  { at: daysAgo(4), key: "change-user-agent", outcome: "rejected", summary: "AuroraClient/2.1" },
  {
    at: daysAgo(6),
    key: "new-url",
    outcome: "ignored",
    summary: "private, loopback or reserved IPv4 targets are rejected",
  },
  { at: daysAgo(9), key: "fragmentation-enable", outcome: "accepted", summary: "true" },
  { at: daysAgo(12), key: "routing", outcome: "autoApplied", summary: "happ://routing/off" },
];

export const SUBS_SEED: Subscription[] = [
  {
    id: "s-aurora",
    remarks: "Aurora Net",
    url: "https://aurora.example.net/api/v1/client/subscribe?token=9f2c1ab7d4e8&flow=xtls-rprx-vision",
    groupId: "g-de",
    enabled: true,
    autoUpdate: true,
    interval: 360,
    lastUpdated: "2026-06-05 09:14",
    count: 14,
    userAgent: "v2rayNG/1.10.7",
    // What the upgrade gives a subscription with its own User-Agent.
    request: { sendHwid: false },
    filter: "",
    allowInsecure: false,
    updateMode: "auto",
    manualTitle: false,
    providerIntervalHours: 1,
    intervalOverride: false,
    bodyEncrypted: true,
    insecureByProvider: false,
    allowProviderConfigs: false,
    pendingChanges: AURORA_PENDING,
    audit: AURORA_AUDIT,
    provider: {
      title: "Aurora Net",
      announce:
        "🎉 New Frankfurt and Amsterdam nodes are live.\nIf a node is slow, refresh the subscription: addresses rotate every night.\nSupport answers within an hour, 09:00–23:00 UTC.\nPayments by card and crypto are accepted on the website.\nThank you for staying with us!",
      supportUrl: "https://t.me/aurora_support_bot",
      webPageUrl: "https://aurora.example.net/account",
      traffic: { upload: 3.1 * GB, download: 39.6 * GB, total: 200 * GB, expire: inDays(25) },
      expired: false,
    },
  },
  {
    id: "s-nodes",
    remarks: "NodeHub Pro",
    url: "https://nodehub.example.io/sub/3a91f0e7c2b5d6489a/auto",
    groupId: "g-main",
    enabled: true,
    autoUpdate: false,
    interval: 720,
    lastUpdated: "2026-06-03 22:40",
    count: 9,
    userAgent: "",
    filter: "(?i)premium",
    allowInsecure: false,
    updateMode: "proxy",
    manualTitle: true,
    intervalOverride: false,
    bodyEncrypted: false,
    insecureByProvider: false,
    allowProviderConfigs: false,
    warnings: [
      { kind: "skippedLines", count: 3, sample: "Remaining traffic: unlimited | Next reset: 1st" },
      { kind: "unsupportedLinks", count: 2 },
    ],
    provider: {
      title: "NodeHub",
      notice: {
        text: "Maintenance tonight 02:00–04:00 UTC. Expect short disconnects.",
        color: "blue",
        buttonText: "Status page",
        buttonUrl: "https://status.nodehub.example.io",
      },
      traffic: { upload: 0.4 * GB, download: 12.3 * GB, total: 0, expire: inDays(2) },
      expired: false,
    },
  },
  {
    id: "s-relay",
    remarks: "Relay Backup",
    url: "https://relay.example.org/u/backup.txt",
    groupId: "g-priv",
    enabled: true,
    autoUpdate: false,
    interval: 180,
    lastUpdated: "2026-05-28 11:02",
    count: 6,
    userAgent: "",
    filter: "",
    allowInsecure: true,
    updateMode: "direct",
    manualTitle: true,
    intervalOverride: false,
    bodyEncrypted: true,
    insecureByProvider: false,
    allowProviderConfigs: false,
    lastError: "subscription body could not be decrypted with key02",
    lastErrorKind: { kind: "decrypt", keyId: "key02" },
    provider: {
      traffic: { upload: 9 * GB, download: 87 * GB, total: 100 * GB, expire: inDays(-3) },
      expired: true,
      renewUrl: "https://relay.example.org/renew",
    },
  },
  {
    id: "s-orbit",
    remarks: "Orbit VPN",
    url: "https://panel.orbit.example.com/sub/7c1e94d2",
    groupId: "g-main",
    enabled: true,
    autoUpdate: true,
    interval: 360,
    lastUpdated: "2026-06-05 08:30",
    count: 2,
    userAgent: "",
    filter: "",
    allowInsecure: false,
    updateMode: "auto",
    manualTitle: false,
    intervalOverride: false,
    bodyEncrypted: false,
    insecureByProvider: false,
    // Full Xray configs, allowed: each became a sanitised Custom profile.
    allowProviderConfigs: true,
    warnings: [{ kind: "rejectedConfigs", count: 1 }],
  },
  {
    id: "s-polar",
    remarks: "Polar Link",
    url: "https://polar.example.net/api/sub?token=4be0c7",
    groupId: "g-main",
    enabled: true,
    autoUpdate: true,
    interval: 720,
    lastUpdated: "2026-06-01 19:12",
    count: 3,
    userAgent: "",
    filter: "",
    allowInsecure: false,
    updateMode: "auto",
    manualTitle: false,
    intervalOverride: false,
    bodyEncrypted: false,
    insecureByProvider: false,
    allowProviderConfigs: false,
    // Left by the last sing-box body; the provider now sends Xray configs.
    warnings: [{ kind: "skippedOutbounds", count: 3 }],
    lastError: "JSON array configs are not allowed for this subscription",
    lastErrorKind: { kind: "unsupportedPayload", payload: "jsonArray" },
    pendingChanges: [
      {
        key: "provider-configs",
        value: "Xray JSON",
        risk: "trustBoundary",
        action: { kind: "allowProviderConfigs" },
        digest: "seed-provider-configs",
        seenAt: daysAgo(0),
      },
    ],
    audit: [{ at: daysAgo(0), key: "provider-configs", outcome: "offered", summary: "Xray JSON" }],
  },
  {
    id: "s-veil",
    remarks: "Veil",
    // An encrypted happ://crypt5 link, kept as added and decrypted on each fetch.
    url: "happ://crypt5/fzvd3yxN4D1czBH9VMsYU9US92O71xw1QspMpXf3a9PkZfJ9aJynfWtHwlg94qZEycNqqYapciRebqs0hZyxJTJF3fezsc8jMtCB7E0e6OH/FQRnMcxgkcEP/d=nek5FSQ384dOxZuK+f23OxuD1q8ettHs5hAIyw1aIbQ",
    groupId: "g-main",
    enabled: true,
    autoUpdate: true,
    interval: 360,
    lastUpdated: "2026-06-06 11:02",
    count: 0,
    userAgent: "",
    filter: "",
    allowInsecure: false,
    updateMode: "auto",
    manualTitle: false,
    intervalOverride: false,
    bodyEncrypted: false,
    insecureByProvider: false,
    allowProviderConfigs: false,
    warnings: [],
  },
];

// What the sanitiser keeps of a provider's Xray config: outbounds and routing.
const orbitConfig = (cc: string) =>
  JSON.stringify({
    outbounds: [
      {
        tag: "proxy",
        protocol: "vless",
        settings: {
          vnext: [
            {
              address: `${cc}.orbit.example.com`,
              port: 443,
              users: [{ id: "5e1b7c2a-8d3f-4a6b-9c0d-1e2f3a4b5c6d", encryption: "none" }],
            },
          ],
        },
        streamSettings: { network: "tcp", security: "tls" },
      },
      { tag: "direct", protocol: "freedom" },
    ],
    routing: { rules: [{ type: "field", ip: ["geoip:private"], outboundTag: "direct" }] },
  });

export const PROFILES_SEED: Profile[] = [
  mk("vless", {
    meta: { remarks: "DE · Vision Reality", groupId: "g-de", subId: "s-aurora" },
    endpoint: { address: "de1.aurora.example.net", port: 443 },
    transport: { kind: "tcp" },
    tls: {
      security: "reality",
      sni: "www.microsoft.com",
      fingerprint: "chrome",
      publicKey: "qg7v3...n9Xc",
      shortId: "a1b2c3d4",
    },
    root: { uuid: "b8f1e2a4-9c3d-4e5f-a6b7-c8d9e0f1a2b3", flow: "xtls-rprx-vision" },
  }),
  mk("vless", {
    meta: { remarks: "DE · WS TLS CDN", groupId: "g-de", subId: "s-aurora" },
    endpoint: { address: "cdn.aurora.example.net", port: 443 },
    transport: { kind: "ws", host: "cdn.aurora.example.net", path: "/ray" },
    tls: { security: "tls", sni: "cdn.aurora.example.net", fingerprint: "chrome" },
    root: { uuid: "c9f2e3a5-0d4e-5f6a-b7c8-d9e0f1a2b3c4" },
  }),
  mk("vless", {
    meta: { remarks: "NL · gRPC Reality", groupId: "g-nl", subId: "s-aurora" },
    endpoint: { address: "nl1.aurora.example.net", port: 8443 },
    transport: {
      kind: "grpc",
      mode: "multi",
      serviceName: "grpc-svc",
      authority: "nl1.aurora.example.net",
    },
    tls: {
      security: "reality",
      sni: "www.cloudflare.com",
      fingerprint: "firefox",
      publicKey: "tk4m9...p2Lq",
      shortId: "ff00ab",
    },
    root: { uuid: "d0f3e4a6-1e5f-6a7b-c8d9-e0f1a2b3c4d5" },
  }),
  mk("vmess", {
    meta: { remarks: "NL · VMess Legacy", groupId: "g-nl", subId: "s-aurora" },
    endpoint: { address: "nl2.aurora.example.net", port: 443 },
    transport: { kind: "ws", host: "nl2.aurora.example.net", path: "/vm" },
    tls: { security: "tls", sni: "nl2.aurora.example.net" },
    root: { uuid: "e1f4e5a7-2f6a-7b8c-d9e0-f1a2b3c4d5e6", encryption: "auto" },
  }),
  mk("trojan", {
    meta: { remarks: "US · Trojan Direct", groupId: "g-main", subId: "s-nodes" },
    endpoint: { address: "us1.nodehub.example.io", port: 443 },
    transport: { kind: "tcp" },
    tls: { security: "tls", sni: "us1.nodehub.example.io", fingerprint: "chrome" },
    root: { password: "Tr0jan$ecret_Pwd_2026" },
  }),
  mk("shadowsocks", {
    meta: { remarks: "SG · Shadowsocks 2022", groupId: "g-main", subId: "s-nodes" },
    endpoint: { address: "sg.nodehub.example.io", port: 8388 },
    root: { password: "rdJ8x2k9PqL=", method: "2022-blake3-aes-128-gcm" },
  }),
  mk("vless", {
    meta: { remarks: "Home Lab", groupId: "g-priv" },
    endpoint: { address: "192.0.2.44", port: 51820 },
    transport: { kind: "tcp" },
    tls: {
      security: "reality",
      sni: "www.apple.com",
      fingerprint: "safari",
      publicKey: "ux5n0...q3Mr",
      shortId: "deadbeef",
    },
    root: { uuid: "f2f5e6a8-3a7b-8c9d-e0f1-a2b3c4d5e6f7", flow: "xtls-rprx-vision" },
  }),
  mk("wireguard", {
    meta: { remarks: "WG · Mullvad", groupId: "g-priv" },
    endpoint: { address: "193.32.127.66", port: 51820 },
    root: {
      secretKey: "wFakeSecretKey0000000000000000000000000000=",
      peerPublicKey: "wFakePeerPublicKey00000000000000000000000=",
      localAddress: "10.64.0.2/32",
    },
  }),
  mk("hysteria2", {
    meta: { remarks: "FI · Hysteria2", groupId: "g-main", subId: "s-nodes" },
    endpoint: { address: "hy2.nodehub.example.io", port: 443 },
    tls: { sni: "hy2.nodehub.example.io" },
    root: {
      password: "hy2Pass_2026!",
      obfsType: "salamander",
      obfsPassword: "obfsSecret",
      upMbps: 100,
      downMbps: 200,
    },
  }),
  mk("tuic", {
    meta: { remarks: "JP · TUIC v5", groupId: "g-main", subId: "s-nodes" },
    endpoint: { address: "tuic.nodehub.example.io", port: 8443 },
    tls: { sni: "tuic.nodehub.example.io" },
    root: {
      uuid: "a3b6c7d8-4b8c-9d0e-f1a2-b3c4d5e6f7a8",
      password: "tuicPass_2026",
      congestionControl: "bbr",
    },
  }),
  ...["🇩🇪 Orbit Frankfurt", "🇫🇮 Orbit Helsinki"].map((remarks, i) =>
    mk("custom", {
      meta: { remarks, groupId: "g-main", subId: "s-orbit" },
      root: { origin: "provider", raw: orbitConfig(i === 0 ? "de" : "fi") },
    }),
  ),
];

const rule = (id: string, remarks: string, fields: Partial<RoutingRule>): RoutingRule => ({
  id,
  remarks,
  enabled: true,
  outboundTag: "direct",
  ...fields,
});

// Demo routes: two shared blocks on the default route, and a route for the
// Amsterdam group that adds work domains in front and sends the rest direct.
export const RULE_BLOCKS_SEED: RuleBlock[] = [
  {
    id: "b-ads",
    name: "Block ads",
    rules: [rule("r-ads", "Ads", { outboundTag: "block", domain: ["geosite:category-ads-all"] })],
  },
  {
    id: "b-lan",
    name: "Local network direct",
    rules: [rule("r-lan", "Private IPs", { ip: ["geoip:private"] })],
  },
  {
    id: "b-work",
    name: "Work",
    rules: [
      rule("r-corp", "Corporate", { domain: ["domain:corp.example", "domain:intra.example"] }),
      rule("r-git", "Git over SSH", { port: "22" }),
    ],
  },
];

export const ROUTES_SEED: Route[] = [
  {
    ...newRoute(DEFAULT_ROUTE_ID, "Default"),
    blocks: [
      { blockId: "b-ads", enabled: true },
      { blockId: "b-lan", enabled: true },
    ],
  },
  {
    ...newRoute("route-work", "Work"),
    groups: ["g-nl"],
    blocks: [
      { blockId: "b-work", enabled: true },
      { blockId: "b-ads", enabled: true },
    ],
    finalOutbound: "direct",
  },
];

export const ASSET_FILES_SEED: AssetFile[] = [];

// Demo settings: the runtime defaults with a couple of tweaks to exercise the UI.
export const SETTINGS_SEED: AdvancedSettings = {
  ...EMPTY_SETTINGS,
  fragment: true,
  tunMtu: 1500,
};

export function seedAppState(): AppState {
  return {
    profiles: PROFILES_SEED,
    groups: GROUPS_SEED,
    subscriptions: SUBS_SEED,
    ruleBlocks: RULE_BLOCKS_SEED,
    routes: ROUTES_SEED,
    assetFiles: [],
    settings: SETTINGS_SEED,
    activeId: PROFILES_SEED[0].meta.id,
    version: __MODULE_VERSION__,
  };
}
