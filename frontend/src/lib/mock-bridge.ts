// ============================================================
// src/lib/mock-bridge.ts
// Mock implementation of the Bridge interface for dev.
// Swaps in at import time when VITE_BRIDGE_MODE=mock (default).
// Dev-only: share parse/build and sub-apply are light stand-ins for the Rust
// backend (deleted with this file in Phase 6); they only need to emit nested
// profiles so the UI renders.
// ============================================================

import type { Endpoint, Meta, Profile, Protocol, Tls, Transport } from "../generated/bindings";
import { AppStateSchema } from "../generated/schemas";
import type { AppState, Bridge, ResourceUpdateMode, ServiceStatus } from "./bridge";
import { emptyProfile, type ProfileOf, profileAddress, profilePort } from "./profile-utils";
import { seedAppState } from "./seed";
import { uid } from "./utils";

/** Build a nested mock profile with sub-object + root-field overrides. */
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

const safeRegex = (source: string): RegExp | null => {
  try {
    return new RegExp(source);
  } catch {
    return null;
  }
};

/** Simulated state (in-memory, lost on reload) */
let state: AppState = seedAppState();
let serviceState: ServiceStatus = {
  state: "stopped",
  activeId: null,
  uploadBytes: 0,
  downloadBytes: 0,
  uptimeSec: 0,
  core: "Xray 25.5.16",
  engine: "xray",
};

function cloneServiceStatus(): ServiceStatus {
  return { ...serviceState };
}

/** Simulated ping latencies by profile ID (randomized each call) */
function simPing(): number {
  return Math.floor(Math.random() * 200) + 10 + Math.floor(Math.random() * 150);
}

/** Stamp a profile's ping/speed without touching the nested structure. */
const withPing = (p: Profile, ping: number): Profile => ({ ...p, meta: { ...p.meta, ping } });

/** Simulate a subscription fetch: return a few nested profiles */
function simFetchSub(url: string): Profile[] {
  const tag = url.slice(0, 20);
  return [
    mk("vless", {
      meta: { remarks: `Fetched #1 (${tag})` },
      endpoint: { address: "node1.fetched.example.com", port: 443 },
      transport: { kind: "tcp" },
      tls: { security: "reality", sni: "www.apple.com", publicKey: "pbk-mock" },
      root: { uuid: uid() },
    }),
    mk("vmess", {
      meta: { remarks: `Fetched #2 (${tag})` },
      endpoint: { address: "node2.fetched.example.com", port: 443 },
      transport: { kind: "ws", path: "/vm" },
      tls: { security: "tls" },
      root: { uuid: uid() },
    }),
    mk("shadowsocks", {
      meta: { remarks: `Fetched #3 (${tag})` },
      endpoint: { address: "node3.fetched.example.com", port: 8388 },
      root: { password: uid(), method: "aes-256-gcm" },
    }),
  ];
}

export const mockBridge: Bridge = {
  async start(profileId: string) {
    state.activeId = profileId;
    serviceState = {
      ...serviceState,
      state: "connecting",
      activeId: profileId,
    };
    // Simulate async service start
    await new Promise((r) => setTimeout(r, 600));
    serviceState = {
      ...serviceState,
      state: "connected",
      uploadBytes: Math.floor(Math.random() * 500000),
      downloadBytes: Math.floor(Math.random() * 2000000),
      uptimeSec: 0,
    };
    // Start uptime counter
    setInterval(() => {
      serviceState.uptimeSec++;
      serviceState.uploadBytes += Math.floor(Math.random() * 100);
      serviceState.downloadBytes += Math.floor(Math.random() * 500);
    }, 1000);
    return cloneServiceStatus();
  },

  async stop() {
    serviceState = {
      ...serviceState,
      state: "stopped",
      activeId: null,
      uploadBytes: 0,
      downloadBytes: 0,
      uptimeSec: 0,
    };
    return cloneServiceStatus();
  },

  async restart() {
    await this.stop();
    if (state.activeId) {
      return this.start(state.activeId);
    }
    return cloneServiceStatus();
  },

  async status(): Promise<ServiceStatus> {
    return cloneServiceStatus();
  },

  onStatus(cb: (s: ServiceStatus) => void): () => void {
    const interval = setInterval(async () => {
      cb(await this.status());
    }, 2000);
    return () => clearInterval(interval);
  },

  async capabilities() {
    return {
      bridge: "mock",
      core: "Xray (mock)",
      singboxVersion: "sing-box (mock)",
      curl: true,
      tun: false,
    };
  },

  async ping(profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 300 + Math.random() * 700));
    const ms = simPing();
    state.profiles = state.profiles.map((p) => (p.meta.id === profileId ? withPing(p, ms) : p));
    return ms;
  },

  async pingAll(
    ids: string[],
    onResult?: (id: string, value: number) => void,
  ): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    const want = new Set(ids);
    const profiles = state.profiles.filter((p) => want.has(p.meta.id));
    const CONCURRENCY = 10;
    let i = 0;
    const worker = async () => {
      while (i < profiles.length) {
        const p = profiles[i++];
        await new Promise((r) => setTimeout(r, 300 + Math.random() * 700));
        const ms = simPing();
        results[p.meta.id] = ms;
        state.profiles = state.profiles.map((x) => (x.meta.id === p.meta.id ? withPing(x, ms) : x));
        onResult?.(p.meta.id, ms);
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return results;
  },

  async realPing(profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 800 + Math.random() * 1200));
    const ms = Math.random() < 0.15 ? -1 : simPing();
    state.profiles = state.profiles.map((p) => (p.meta.id === profileId ? withPing(p, ms) : p));
    return ms;
  },

  async realPingAll(
    ids: string[],
    onResult?: (id: string, value: number) => void,
  ): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    const CONCURRENCY = 3;
    const want = new Set(ids);
    const profiles = state.profiles.filter((p) => want.has(p.meta.id));
    let i = 0;
    const worker = async () => {
      while (i < profiles.length) {
        const p = profiles[i++];
        await new Promise((r) => setTimeout(r, 400 + Math.random() * 600));
        const ms = Math.random() < 0.15 ? -1 : simPing();
        results[p.meta.id] = ms;
        state.profiles = state.profiles.map((x) => (x.meta.id === p.meta.id ? withPing(x, ms) : x));
        onResult?.(p.meta.id, ms);
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return results;
  },

  async speedTest(_profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 3000 + Math.random() * 5000));
    const bps = Math.random() < 0.15 ? -1 : Math.floor(500_000 + Math.random() * 9_500_000);
    return bps;
  },

  async speedTestAll(
    ids: string[],
    onResult?: (id: string, value: number) => void,
  ): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    const want = new Set(ids);
    for (const p of state.profiles.filter((x) => want.has(x.meta.id))) {
      const bps = await this.speedTest(p.meta.id);
      results[p.meta.id] = bps;
      onResult?.(p.meta.id, bps);
    }
    return results;
  },

  log(input): Promise<string> {
    const target = input?.target ?? "daemon";
    const lines = input?.lines ?? 200;
    return Promise.resolve(`[${new Date().toISOString()}] [MOCK:${target}] Service status: ${serviceState.state}
[${new Date().toISOString()}] [MOCK:${target}] Active profile: ${state.activeId ?? "none"}
[${new Date().toISOString()}] [MOCK:${target}] Xray 25.5.16 running (pid: ${Math.floor(Math.random() * 99999)})
[${new Date().toISOString()}] [MOCK:${target}] tun2socks running (pid: ${Math.floor(Math.random() * 99999)})
[${new Date().toISOString()}] [MOCK:${target}] Traffic: ↑ ${serviceState.uploadBytes} B · ↓ ${serviceState.downloadBytes} B
-- Mock log lines above (${lines}) --`);
  },

  async clearLogs() {
    return { ok: true };
  },

  readState(): Promise<AppState> {
    return Promise.resolve({
      ...state,
      profiles: [...state.profiles],
      groups: [...state.groups],
      subscriptions: [...state.subscriptions],
      routingRules: [...state.routingRules],
      assetFiles: [...state.assetFiles],
    });
  },

  async writeState(s: AppState) {
    state = {
      ...s,
      profiles: [...s.profiles],
      groups: [...s.groups],
      subscriptions: [...s.subscriptions],
      routingRules: [...s.routingRules],
      assetFiles: [...s.assetFiles],
    };
  },

  async fetchSubscription(url: string): Promise<Profile[]> {
    // Simulate network delay
    await new Promise((r) => setTimeout(r, 800));
    return simFetchSub(url);
  },

  // Dev stand-in for the backend's server-side apply: fetch + filter + stamp +
  // replace this subscription's profiles in the in-memory state.
  async applySubscription(subId: string): Promise<AppState> {
    const sub = state.subscriptions.find((x) => x.id === subId);
    if (!sub) throw new Error(`subscription not found: ${subId}`);
    await new Promise((r) => setTimeout(r, 800));
    const re = sub.filter ? safeRegex(sub.filter) : null;
    const mapped = simFetchSub(sub.url)
      .filter((p) => !re || re.test(p.meta.remarks))
      .map((p) => ({
        ...p,
        meta: { ...p.meta, subId: sub.id, groupId: sub.groupId ?? p.meta.groupId },
      }));
    const others = state.profiles.filter((p) => p.meta.subId !== sub.id);
    state = { ...state, profiles: [...others, ...mapped] };
    return this.readState();
  },

  async deduplicateProfiles(profiles, activeId, groupId) {
    const inScope = (p: Profile) => !groupId || groupId === "all" || p.meta.groupId === groupId;
    const keyOf = (p: Profile) => `${p.protocol}|${profileAddress(p)}|${profilePort(p) ?? ""}`;
    const keep = new Map<string, string>();
    for (const p of profiles) {
      if (!inScope(p)) continue;
      const k = keyOf(p);
      if (!keep.has(k) || p.meta.id === activeId) keep.set(k, p.meta.id);
    }
    return profiles.filter((p) => !inScope(p) || keep.get(keyOf(p)) === p.meta.id);
  },

  async removeProfilesBySubId(profiles, subId, subGroupId) {
    return profiles.filter((p) => {
      if (p.meta.subId !== subId) return true;
      if (subGroupId != null && p.meta.groupId !== subGroupId) return true;
      return false;
    });
  },

  // No backend daemon in dev, so headless sub-applies never happen.
  onSubApplied() {
    return () => {};
  },

  async downloadAsset(
    filename: string,
    _url: string,
    _mode: ResourceUpdateMode = "auto",
  ): Promise<{ ok: boolean; error?: string }> {
    await new Promise((r) => setTimeout(r, 1500));
    if (!state.assetFiles.some((asset) => asset.remarks === filename)) {
      return { ok: false, error: "Asset not tracked" };
    }
    return { ok: true };
  },

  async listAssets(): Promise<string[]> {
    return state.assetFiles.map((asset) => asset.remarks);
  },

  async listApps() {
    return [
      { pkg: "com.google.android.youtube", uid: 10001, system: false },
      { pkg: "org.telegram.messenger", uid: 10002, system: false },
      { pkg: "com.android.chrome", uid: 10003, system: false },
      { pkg: "com.google.android.gms", uid: 10004, system: true },
      { pkg: "com.netflix.mediaclient", uid: 10005, system: false },
    ];
  },

  async reloadAppFilter() {
    return { ok: true };
  },

  // Dev stub: emit one nested placeholder profile per non-empty line.
  async parseShareLinks(text: string): Promise<Profile[]> {
    await new Promise((r) => setTimeout(r, 150));
    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((_line, i) =>
        mk("vless", {
          meta: { remarks: `Imported #${i + 1}` },
          endpoint: { address: "imported.example.com", port: 443 },
          root: { uuid: uid() },
        }),
      );
  },

  // Dev stub: best-effort share string from the nested profile.
  async buildShareLink(p: Profile): Promise<string> {
    const at = profileAddress(p) ? `${profileAddress(p)}:${profilePort(p) ?? ""}` : p.protocol;
    return `${p.protocol}://${at}#${encodeURIComponent(p.meta.remarks)}`;
  },

  async exportBackup(): Promise<Blob> {
    const json = JSON.stringify(await this.readState(), null, 2);
    return new Blob([json], { type: "application/json" });
  },

  async importBackup(file: Blob, mode: "merge" | "replace") {
    const text = await file.text();
    const incoming = AppStateSchema.parse(JSON.parse(text)) as unknown as AppState;
    if (mode === "replace") {
      // Keep current profiles — backups no longer include them
      state = { ...incoming, profiles: state.profiles };
    } else {
      // merge: add profiles/groups/subs, then overwrite settings
      state = {
        ...state,
        profiles: [...state.profiles, ...incoming.profiles],
        groups: [...state.groups, ...incoming.groups],
        subscriptions: [...state.subscriptions, ...incoming.subscriptions],
        routingRules: [...state.routingRules, ...incoming.routingRules],
        assetFiles: [...state.assetFiles, ...incoming.assetFiles],
        settings: incoming.settings,
      };
    }
  },
};
