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
  RoutingRule,
  Tls,
  Transport,
} from "../generated/bindings";
import type { AppState, Subscription } from "./bridge";
import { emptyProfile, type ProfileOf } from "./profile-utils";

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
  const base = emptyProfile(protocol) as unknown as Record<string, unknown>;
  base.meta = { ...(base.meta as object), id: uid(), ...o.meta };
  if (o.endpoint && "endpoint" in base)
    base.endpoint = { ...(base.endpoint as object), ...o.endpoint };
  if (o.tls && "tls" in base) base.tls = { ...(base.tls as object), ...o.tls };
  if (o.transport) base.transport = o.transport;
  if (o.root) Object.assign(base, o.root);
  return base as unknown as ProfileOf<P>;
}

export const GROUPS_SEED = [
  { id: "g-main", name: "Main" },
  { id: "g-de", name: "🇩🇪 Frankfurt" },
  { id: "g-nl", name: "🇳🇱 Amsterdam" },
  { id: "g-priv", name: "Private" },
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
    filter: "",
    allowInsecure: false,
    updateMode: "auto",
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
  },
  {
    id: "s-relay",
    remarks: "Relay Backup",
    url: "https://relay.example.org/u/backup.txt",
    groupId: "g-priv",
    enabled: false,
    autoUpdate: false,
    interval: 180,
    lastUpdated: "2026-05-28 11:02",
    count: 6,
    userAgent: "",
    filter: "",
    allowInsecure: true,
    updateMode: "direct",
  },
];

export const PROFILES_SEED: Profile[] = [
  mk("vless", {
    meta: { remarks: "DE · Vision Reality", groupId: "g-de", subId: "s-aurora", ping: 86 },
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
    meta: { remarks: "DE · WS TLS CDN", groupId: "g-de", subId: "s-aurora", ping: 142 },
    endpoint: { address: "cdn.aurora.example.net", port: 443 },
    transport: { kind: "ws", host: "cdn.aurora.example.net", path: "/ray" },
    tls: { security: "tls", sni: "cdn.aurora.example.net", fingerprint: "chrome" },
    root: { uuid: "c9f2e3a5-0d4e-5f6a-b7c8-d9e0f1a2b3c4" },
  }),
  mk("vless", {
    meta: { remarks: "NL · gRPC Reality", groupId: "g-nl", subId: "s-aurora", ping: 121 },
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
    meta: { remarks: "NL · VMess Legacy", groupId: "g-nl", subId: "s-aurora", ping: 168 },
    endpoint: { address: "nl2.aurora.example.net", port: 443 },
    transport: { kind: "ws", host: "nl2.aurora.example.net", path: "/vm" },
    tls: { security: "tls", sni: "nl2.aurora.example.net" },
    root: { uuid: "e1f4e5a7-2f6a-7b8c-d9e0-f1a2b3c4d5e6", encryption: "auto" },
  }),
  mk("trojan", {
    meta: { remarks: "US · Trojan Direct", groupId: "g-main", subId: "s-nodes", ping: 233 },
    endpoint: { address: "us1.nodehub.example.io", port: 443 },
    transport: { kind: "tcp" },
    tls: { security: "tls", sni: "us1.nodehub.example.io", fingerprint: "chrome" },
    root: { password: "Tr0jan$ecret_Pwd_2026" },
  }),
  mk("shadowsocks", {
    meta: { remarks: "SG · Shadowsocks 2022", groupId: "g-main", subId: "s-nodes", ping: 64 },
    endpoint: { address: "sg.nodehub.example.io", port: 8388 },
    root: { password: "rdJ8x2k9PqL=", method: "2022-blake3-aes-128-gcm" },
  }),
  mk("vless", {
    meta: { remarks: "Home Lab", groupId: "g-priv", ping: 12 },
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
    meta: { remarks: "WG · Mullvad", groupId: "g-priv", ping: 38 },
    endpoint: { address: "193.32.127.66", port: 51820 },
    root: {
      secretKey: "wFakeSecretKey0000000000000000000000000000=",
      peerPublicKey: "wFakePeerPublicKey00000000000000000000000=",
      localAddress: "10.64.0.2/32",
    },
  }),
  mk("hysteria2", {
    meta: { remarks: "FI · Hysteria2", groupId: "g-main", subId: "s-nodes", ping: 54 },
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
    meta: { remarks: "JP · TUIC v5", groupId: "g-main", subId: "s-nodes", ping: 97 },
    endpoint: { address: "tuic.nodehub.example.io", port: 8443 },
    tls: { sni: "tuic.nodehub.example.io" },
    root: {
      uuid: "a3b6c7d8-4b8c-9d0e-f1a2-b3c4d5e6f7a8",
      password: "tuicPass_2026",
      congestionControl: "bbr",
    },
  }),
];

export const ROUTING_RULES_SEED: RoutingRule[] = [];

export const ASSET_FILES_SEED: AssetFile[] = [];

export const SETTINGS_SEED = {
  routingMode: "global" as const,
  domainSniffing: true,
  routeOnly: false,
  domainStrategy: "IPIfNonMatch",
  domainStrategy4Singbox: "prefer_ipv4",
  strictRoute: false,
  singboxStack: "gvisor",
  dnsViaProxy: true,
  fakeDns: false,
  preferIpv6: false,
  mux: false,
  muxConcurrency: 8,
  muxXudpConcurrency: 8,
  muxXudp443: "reject" as "reject" | "proxy" | undefined,
  fragment: true,
  fragmentPackets: "tlshello",
  mtu: 1500,
  pingConcurrency: 3,
  speedConcurrency: 1,
  autoStart: true,
  coreByProtocol: {},
  appCaptureMode: "all" as "all" | "none",
  appFilter: {} as Record<string, "force-proxy" | "bypass">,
  logRotateMaxKb: 512,
  dedupOnUpdate: false,
  allowNonLocalhost: false,
} as const;

export function seedAppState(): AppState {
  return {
    profiles: PROFILES_SEED,
    groups: GROUPS_SEED,
    subscriptions: SUBS_SEED,
    routingRules: ROUTING_RULES_SEED,
    assetFiles: [],
    settings: SETTINGS_SEED,
    activeId: PROFILES_SEED[0].meta.id,
    version: __MODULE_VERSION__,
  };
}
