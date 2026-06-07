// ============================================================
// src/lib/mock-bridge.ts
// Mock implementation of the Bridge interface for dev.
// Swaps in at import time when VITE_BRIDGE_MODE=mock (default).
// ============================================================
import type { AppState, Bridge, ResourceUpdateMode, ServiceStatus } from "./bridge";
import { emptyProfile, type Profile, type ProfileOf, type Protocol } from "./schema";
import { seedAppState } from "./seed";
import { buildShareLink as realBuild, parseShareLinks as realParse } from "./share";
import { uid } from "./utils";

/** Build a mock profile of a given protocol with field overrides. */
function mk<P extends Protocol>(protocol: P, o: Partial<ProfileOf<P>> = {}): ProfileOf<P> {
  const base = emptyProfile(protocol) as ProfileOf<P>;
  return { ...base, ...o, id: o.id ?? uid(), protocol };
}

/** Simulated state (in-memory, lost on reload) */
let state: AppState = seedAppState();
let serviceState: ServiceStatus = {
  state: "stopped",
  activeId: null,
  uploadBytes: 0,
  downloadBytes: 0,
  uptimeSec: 0,
  core: "Xray 25.5.16",
};

function cloneServiceStatus(): ServiceStatus {
  return { ...serviceState };
}

/** Simulated ping latencies by profile ID (randomized each call) */
function simPing(): number {
  return Math.floor(Math.random() * 200) + 10 + Math.floor(Math.random() * 150);
}

/** Simulate a subscription fetch: return a few profiles */
function simFetchSub(
  url: string,
  _opts?: { userAgent?: string; allowInsecure?: boolean },
): Profile[] {
  const tag = url.slice(0, 20);
  return [
    mk("vless", {
      remarks: `Fetched #1 (${tag})`,
      address: "node1.fetched.example.com",
      uuid: uid(),
      security: "reality",
      sni: "www.apple.com",
      publicKey: "pbk-mock",
    }),
    mk("vmess", {
      remarks: `Fetched #2 (${tag})`,
      address: "node2.fetched.example.com",
      uuid: uid(),
      network: "ws",
      path: "/vm",
      security: "tls",
    }),
    mk("shadowsocks", {
      remarks: `Fetched #3 (${tag})`,
      address: "node3.fetched.example.com",
      password: uid(),
      method: "aes-256-gcm",
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
      state: "running",
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
    // Update profile ping in state
    state.profiles = state.profiles.map((p) => (p.id === profileId ? { ...p, ping: ms } : p));
    return ms;
  },

  async pingAll(): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    const promises = state.profiles.map(async (p) => {
      const ms = simPing();
      results[p.id] = ms;
      return { id: p.id, ms };
    });
    await Promise.all(promises);
    state.profiles = state.profiles.map((p) => ({
      ...p,
      ping: results[p.id] ?? p.ping,
    }));
    return results;
  },

  async realPing(profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 800 + Math.random() * 1200));
    const ms = Math.random() < 0.15 ? -1 : simPing();
    state.profiles = state.profiles.map((p) => (p.id === profileId ? { ...p, ping: ms } : p));
    return ms;
  },

  async realPingAll(): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    const CONCURRENCY = 3;
    const profiles = [...state.profiles];
    let i = 0;
    const worker = async () => {
      while (i < profiles.length) {
        const p = profiles[i++];
        await new Promise((r) => setTimeout(r, 400 + Math.random() * 600));
        results[p.id] = Math.random() < 0.15 ? -1 : simPing();
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    state.profiles = state.profiles.map((p) => ({ ...p, ping: results[p.id] ?? p.ping }));
    return results;
  },

  async speedTest(_profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 3000 + Math.random() * 5000));
    const bps = Math.random() < 0.15 ? -1 : Math.floor(500_000 + Math.random() * 9_500_000);
    return bps;
  },

  async speedTestAll(): Promise<Record<string, number>> {
    const results: Record<string, number> = {};
    for (const p of state.profiles) {
      results[p.id] = await this.speedTest(p.id);
    }
    return results;
  },

  log(input): Promise<string> {
    const target = input?.target ?? "service";
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

  async fetchSubscription(
    url: string,
    opts?: { userAgent?: string; allowInsecure?: boolean },
  ): Promise<Profile[]> {
    // Simulate network delay
    await new Promise((r) => setTimeout(r, 800));
    return simFetchSub(url, opts);
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

  async parseShareLinks(text: string): Promise<Profile[]> {
    await new Promise((r) => setTimeout(r, 150));
    return realParse(text);
  },

  async buildShareLink(p: Profile): Promise<string> {
    return realBuild(p);
  },

  async exportBackup(): Promise<Blob> {
    const json = JSON.stringify(await this.readState(), null, 2);
    return new Blob([json], { type: "application/json" });
  },

  async importBackup(file: Blob, mode: "merge" | "replace") {
    const text = await file.text();
    const incoming: AppState = JSON.parse(text);
    if (mode === "replace") {
      state = incoming;
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
