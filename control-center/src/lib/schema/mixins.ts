// ============================================================
// src/lib/schema/mixins.ts
// Shared field groups composed into per-protocol objects, plus the
// matching default factories used by each protocol's empty() helper.
// Keeping shapes + defaults together avoids drift between schema and
// the factory.
// ============================================================
import { z } from "zod";
import { CoreSel, Fingerprint, HeaderType, Network, Security } from "./enums";

export const metaShape = {
  id: z.string(),
  remarks: z.string().min(1, "Remarks required"),
  groupId: z.string(),
  subId: z.string().nullable().default(null),
  ping: z.number().nullable().default(null),
  speed: z.number().nullable().default(null), // bytes/sec, -1 = failed
  coreType: CoreSel.default("global"), // per-profile core override; "global" = resolve by protocol/settings
};

export const endpointShape = {
  address: z.string().min(1, "Address required"),
  port: z.coerce.number().int().min(1).max(65535),
};

export const transportShape = {
  network: Network.default("tcp"),
  headerType: HeaderType.default("none"),
  host: z.string().default(""), // ws/httpupgrade/xhttp/h2/tcp-http Host
  path: z.string().default(""), // ws/httpupgrade/xhttp/h2/tcp-http path
  wsEarlyData: z.coerce.number().int().min(0).default(0),
  wsEarlyDataHeader: z.string().default(""),
  wsHeartbeatPeriod: z.coerce.number().int().min(0).default(0), // xray WS keepalive ping (s)
  serviceName: z.string().default(""), // gRPC serviceName
  authority: z.string().default(""), // gRPC authority
  grpcMode: z.string().default(""), // "multi" | ""
  grpcIdleTimeout: z.coerce.number().int().min(0).default(0),
  grpcHealthCheckTimeout: z.coerce.number().int().min(0).default(0),
  grpcPingTimeout: z.coerce.number().int().min(0).default(0),
  grpcPermitWithoutStream: z.boolean().default(false),
  grpcInitialWindowsSize: z.coerce.number().int().min(0).default(0),
  userAgent: z.string().default(""),
  xhttpMode: z.string().default(""), // auto | packet-up | stream-up | stream-one
  xhttpExtra: z.string().default(""), // xHTTP extra (raw JSON)
  kcpSeed: z.string().default(""), // mKCP seed
  kcpMtu: z.coerce.number().int().min(0).default(0),
  kcpTti: z.coerce.number().int().min(0).default(0),
  kcpUplink: z.coerce.number().int().min(0).default(0),
  kcpDownlink: z.coerce.number().int().min(0).default(0),
  muxEnabled: z.boolean().default(false),
};

export const tlsShape = {
  security: Security.default("tls"),
  sni: z.string().default(""),
  disableSni: z.boolean().default(false),
  fingerprint: Fingerprint.default("chrome"),
  alpn: z.string().default(""),
  allowInsecure: z.boolean().default(false),
  tlsMinVersion: z.string().default(""),
  tlsMaxVersion: z.string().default(""),
  tlsCipherSuites: z.string().default(""),
  tlsCurvePreferences: z.string().default(""),
  cert: z.string().default(""),
  disableSystemRoot: z.boolean().default(false),
  rejectUnknownSni: z.boolean().default(false), // xray TLS
  enableSessionResumption: z.boolean().default(false), // xray TLS
  publicKey: z.string().default(""), // reality
  shortId: z.string().default(""), // reality
  spiderX: z.string().default(""), // reality
  ech: z.string().default(""), // ECH config list
  vcn: z.string().default(""), // verifyPeerCertByName
  pcs: z.string().default(""), // pinnedPeerCertSha256 (profile-level)
  pqv: z.string().default(""), // mldsa65Verify (Reality post-quantum)
};

/* ---------- default factories (one per shape) ---------- */
export function newId(): string {
  return globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);
}

export const metaDefault = (groupId: string) =>
  ({
    id: newId(),
    remarks: "New profile",
    groupId,
    subId: null,
    ping: null,
    speed: null,
    coreType: "global",
  }) as const;

export const endpointDefault = () => ({ address: "", port: 443 }) as const;

export const transportDefault = () =>
  ({
    network: "tcp",
    headerType: "none",
    host: "",
    path: "",
    wsEarlyData: 0,
    wsEarlyDataHeader: "",
    wsHeartbeatPeriod: 0,
    serviceName: "",
    authority: "",
    grpcMode: "",
    grpcIdleTimeout: 0,
    grpcHealthCheckTimeout: 0,
    grpcPingTimeout: 0,
    grpcPermitWithoutStream: false,
    grpcInitialWindowsSize: 0,
    userAgent: "",
    xhttpMode: "",
    xhttpExtra: "",
    kcpSeed: "",
    kcpMtu: 0,
    kcpTti: 0,
    kcpUplink: 0,
    kcpDownlink: 0,
    muxEnabled: false,
  }) as const;

export const tlsDefault = () =>
  ({
    security: "tls",
    sni: "",
    disableSni: false,
    fingerprint: "chrome",
    alpn: "",
    allowInsecure: false,
    tlsMinVersion: "",
    tlsMaxVersion: "",
    tlsCipherSuites: "",
    tlsCurvePreferences: "",
    cert: "",
    disableSystemRoot: false,
    rejectUnknownSni: false,
    enableSessionResumption: false,
    publicKey: "",
    shortId: "",
    spiderX: "",
    ech: "",
    vcn: "",
    pcs: "",
    pqv: "",
  }) as const;
