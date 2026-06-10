// ============================================================
// src/lib/bridge.ts
// The bridge contract the UI talks to: domain types, the `Bridge`
// interface, and the response parsers shared by implementations.
// Concrete impls live in ksu-bridge.ts (device) / mock-bridge.ts
// (dev); bridge-provider.ts picks one. Swapping the impl never
// touches a screen.
// ============================================================
import type { Profile } from "./schema";

// Domain types are inferred from the Zod schemas (single source of truth).
export type {
  AdvancedSettings,
  AppState,
  AssetFile,
  Group,
  RoutingRule,
  Subscription,
} from "./schema";

import type { AppState } from "./schema";

export type ServiceState = "stopped" | "connecting" | "running";

export interface AppEntry {
  pkg: string;
  uid: number;
  system: boolean;
  label?: string;
  iconUrl?: string;
}

/** A subscription body the backend daemon downloaded on its schedule, awaiting parse. */
export interface SubCacheEntry {
  id: string; // subscription id
  fetchedAt: number; // epoch seconds the daemon wrote it
}

export interface ServiceStatus {
  state: ServiceState;
  activeId: string | null;
  uploadBytes: number;
  downloadBytes: number;
  uptimeSec: number;
  core: string; // e.g. "Xray 25.5.16"
  /** Engine actually running (PID truth), not the marker/intent. */
  engine: "xray" | "sing-box" | null;
}

export interface Capabilities {
  bridge: string; // "ksu" | "cgi" | "mock"
  core: string; // Xray version
  singboxVersion: string; // sing-box version
  curl: boolean;
  tun: boolean;
}

export type ResourceUpdateMode = "auto" | "proxy" | "direct";

export type BatchProgress = (profileId: string, value: number) => void;

export interface Bridge {
  // service control
  start(profileId: string): Promise<ServiceStatus>;
  stop(): Promise<ServiceStatus>;
  restart(): Promise<ServiceStatus>;
  status(): Promise<ServiceStatus>;
  onStatus(cb: (s: ServiceStatus) => void): () => void; // live stream → unsubscribe
  capabilities(): Promise<Capabilities>;

  // diagnostics
  ping(profileId: string): Promise<number>;
  // Batch runs own concurrency *and* port allocation here (not in the store) so
  // the on-demand test cores never share a SOCKS port / job file (see
  // realPingAll). `onResult` streams each profile's result as it resolves so the
  // UI updates progressively instead of waiting for the whole batch.
  pingAll(onResult?: BatchProgress): Promise<Record<string, number>>;
  // `port` lets batch runs hand each concurrent worker its own pre-allocated
  // free port so the on-demand test cores never share a SOCKS port / job file
  // (see realPingAll). When omitted, the impl allocates one itself.
  realPing(profileId: string, port?: number): Promise<number>;
  realPingAll(onResult?: BatchProgress): Promise<Record<string, number>>;
  speedTest(profileId: string, port?: number): Promise<number>; // bytes/sec, -1 = failed
  speedTestAll(onResult?: BatchProgress): Promise<Record<string, number>>;
  log(input?: {
    target?: "xray" | "singbox" | "tun2socks" | "service" | "proxy_control";
    lines?: number;
  }): Promise<string>;
  clearLogs(): Promise<{ ok: boolean; error?: string }>;

  // persistence (source of truth lives in module files, not localStorage)
  readState(): Promise<AppState>;
  writeState(state: AppState): Promise<void>;

  // subscriptions
  fetchSubscription(
    url: string,
    opts?: { userAgent?: string; allowInsecure?: boolean; mode?: ResourceUpdateMode },
  ): Promise<Profile[]>;

  // subscription auto-update cache: a backend daemon downloads raw subscription
  // bodies on a schedule; the UI parses & applies them on launch, then clears.
  listSubCache(): Promise<SubCacheEntry[]>;
  readSubCache(id: string): Promise<string>;
  clearSubCache(id: string): Promise<void>;
  subWakeup(): Promise<void>;

  // asset files
  downloadAsset(
    filename: string,
    url: string,
    mode?: ResourceUpdateMode,
  ): Promise<{ ok: boolean; error?: string }>;
  listAssets(): Promise<string[]>;
  listApps(): Promise<AppEntry[]>;
  reloadAppFilter(): Promise<{ ok: boolean; error?: string }>;

  // import / export / backup
  parseShareLinks(text: string): Promise<Profile[]>; // vless:// vmess:// trojan://
  buildShareLink(p: Profile): Promise<string>;
  exportBackup(): Promise<Blob>;
  importBackup(file: Blob, mode: "merge" | "replace"): Promise<void>;
}

/** Parse a raw service-status payload into a typed `ServiceStatus`. */
export function parseServiceStatus(value: unknown): ServiceStatus {
  if (!value || typeof value !== "object") throw new Error("Invalid service status payload");
  const s = value as Record<string, unknown>;
  const state = s.state;
  if (state !== "stopped" && state !== "connecting" && state !== "running") {
    throw new Error("Invalid service state");
  }
  return {
    state,
    activeId: typeof s.activeId === "string" ? s.activeId : null,
    uploadBytes: typeof s.uploadBytes === "number" ? s.uploadBytes : 0,
    downloadBytes: typeof s.downloadBytes === "number" ? s.downloadBytes : 0,
    uptimeSec: typeof s.uptimeSec === "number" ? s.uptimeSec : 0,
    core: typeof s.core === "string" ? s.core : "",
    engine: s.engine === "xray" || s.engine === "sing-box" ? s.engine : null,
  };
}

/** Parse a raw capabilities payload into a typed `Capabilities`. */
export function parseCapabilities(value: unknown): Capabilities {
  const s = (value && typeof value === "object" ? value : {}) as Record<string, unknown>;
  return {
    bridge: typeof s.bridge === "string" ? s.bridge : "",
    core: typeof s.core === "string" ? s.core : "",
    singboxVersion: typeof s.singboxVersion === "string" ? s.singboxVersion : "",
    curl: s.curl === true || s.curl === 1 || s.curl === "1",
    tun: s.tun === true || s.tun === 1 || s.tun === "1",
  };
}
