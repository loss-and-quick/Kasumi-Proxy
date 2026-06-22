// ============================================================
// src/lib/bridge.ts
// The bridge contract the UI talks to: domain types, the `Bridge`
// interface, and the response parsers shared by implementations.
// Concrete impls live in ws-bridge.ts (device, WebSocket RPC) /
// mock-bridge.ts (dev); bridge-provider.ts picks one. Swapping the
// impl never touches a screen.
// ============================================================
import type {
  Capabilities,
  FetchMode,
  LogTarget,
  Profile,
  RunState,
  SubAppliedEvent,
  ServiceStatus as WireServiceStatus,
} from "../generated/bindings";

// Domain and wire-contract types come from the Rust-generated bindings (single
// source of truth shared with the daemon). The `_Serialize` variants are the
// concrete all-fields-present shapes the UI holds in memory.
export type {
  AdvancedSettings_Serialize as AdvancedSettings,
  AssetFile,
  Capabilities,
  Group,
  LogTarget,
  RoutingRule,
  SubAppliedEvent,
  Subscription_Serialize as Subscription,
} from "../generated/bindings";

import type { AppState_Serialize } from "../generated/bindings";

// The persisted app state as the UI holds it. `schemaVersion` is an on-disk
// migration detail owned by the Rust read path, so the frontend neither tracks
// nor writes it (the backend stamps it).
export type AppState = Omit<AppState_Serialize, "schemaVersion">;

/** The five truthful run states the UI renders (see Rust `RunState`):
 *  stopped · connecting · connected · noInternet · failed. */
export type ServiceState = RunState;

/** Whether the data-path is up (a live core / SOCKS exists): any state except the
 *  two terminal ones. Use for "stop if running" / "fetch through the core" guards —
 *  distinct from `=== "connected"`, which is "actually reaching the internet". */
export const isServiceUp = (s: ServiceState): boolean => s !== "stopped" && s !== "failed";

export interface AppEntry {
  pkg: string;
  uid: number;
  system: boolean;
  label?: string;
  iconUrl?: string;
}

/** ServiceStatus as screens consume it — keeps `error`, the reason carried by
 *  `failed` (couldn't start) and `noInternet` (up but no connectivity). */
export interface ServiceStatus extends Omit<WireServiceStatus, "state"> {
  state: ServiceState;
}

export type ResourceUpdateMode = FetchMode;

export type BatchProgress = (profileId: string, value: number) => void;

export interface Bridge {
  // service control
  start(profileId: string): Promise<ServiceStatus>;
  stop(): Promise<ServiceStatus>;
  restart(): Promise<ServiceStatus>;
  status(): Promise<ServiceStatus>;
  onStatus(cb: (s: ServiceStatus) => void): () => void; // live stream → unsubscribe
  capabilities(): Promise<Capabilities>;

  // diagnostics. The daemon owns ports AND concurrency: each call just names a
  // profile, the daemon leases its own port and bounds how many probe cores run at
  // once (the pingConcurrency/speedConcurrency setting). A batch is simply many
  // per-profile calls fired together; `*All` is a thin helper that does that and
  // streams each result via `onResult` as it resolves.
  ping(profileId: string): Promise<number>;
  pingAll(ids: string[], onResult?: BatchProgress): Promise<Record<string, number>>;
  realPing(profileId: string): Promise<number>;
  realPingAll(ids: string[], onResult?: BatchProgress): Promise<Record<string, number>>;
  speedTest(profileId: string): Promise<number>; // bytes/sec, -1 = unreachable
  speedTestAll(ids: string[], onResult?: BatchProgress): Promise<Record<string, number>>;
  log(input?: { target?: LogTarget; lines?: number }): Promise<string>;
  clearLogs(): Promise<{ ok: boolean; error?: string }>;

  // persistence (source of truth lives in module files, not localStorage)
  readState(): Promise<AppState>;
  writeState(state: AppState): Promise<void>;

  // subscriptions
  fetchSubscription(
    url: string,
    opts?: { userAgent?: string; allowInsecure?: boolean; mode?: ResourceUpdateMode },
  ): Promise<Profile[]>;

  // Fetch one subscription and apply it server-side (fetch + map + dedup + apply,
  // restarting the active data-path when affected), returning the new persisted
  // state. Soft failures are recorded as the subscription's `lastError` in the
  // returned state; the UI reloads from it instead of running the apply locally.
  applySubscription(subId: string): Promise<AppState>;

  // Run kasumi-core's canonical profile-list transforms server-side and return
  // the surviving profiles (the caller persists them) — so the dedup / sub-removal
  // logic is never reimplemented on the frontend.
  deduplicateProfiles(
    profiles: Profile[],
    activeId: string | null,
    groupId?: string,
  ): Promise<Profile[]>;
  removeProfilesBySubId(
    profiles: Profile[],
    subId: string,
    subGroupId?: string | null,
  ): Promise<Profile[]>;

  // The daemon fetches & applies auto-update subscriptions itself; this stream
  // tells the UI to reload the persisted state. Returns an unsubscribe.
  onSubApplied(cb: (info: SubAppliedEvent) => void): () => void;

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
  if (
    state !== "stopped" &&
    state !== "connecting" &&
    state !== "connected" &&
    state !== "noInternet" &&
    state !== "failed"
  ) {
    throw new Error("Invalid service state");
  }
  return {
    state,
    error: typeof s.error === "string" ? s.error : undefined,
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
    tun: s.tun === true || s.tun === 1 || s.tun === "1",
  };
}
