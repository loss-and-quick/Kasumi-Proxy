// ============================================================
// src/lib/mock-bridge.ts
// Mock implementation of the Bridge interface for dev.
// Swaps in at import time when VITE_BRIDGE_MODE=mock (default).
// Dev-only: share parse/build and sub-apply are light stand-ins for the Rust
// backend (deleted with this file in Phase 6); they only need to emit nested
// profiles so the UI renders.
// ============================================================

import type {
  Endpoint,
  Meta,
  Profile,
  ProfileFieldIssue,
  Protocol,
  ResolvedImport_Serialize as ResolvedImport,
  Tls,
  Transport,
} from "../generated/bindings";
import {
  DEFAULT_CORE_BY_PROTOCOL,
  HAPP_VERSION,
  INCY_VERSION,
  SCHEMA_VERSION,
  SHARE_LINK_SCHEMES,
} from "../generated/defaults";
import { ProfileSchema } from "../generated/schemas";
import { applyMutation, routingPackage } from "./apply-mutation";
import type {
  AppState,
  Bridge,
  ConnectionProbe,
  ReadinessReport,
  ResourceUpdateMode,
  Route,
  RoutePackage,
  RouteSharePayload,
  RuleBlock,
  ServiceStatus,
} from "./bridge";
import { emptyProfile, type ProfileOf, profileAddress, profilePort } from "./profile-utils";
import { exportRoutePackage, flattenRoute, parseRoutePackage, routeNamesProfiles } from "./routes";
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
  const base = emptyProfile(protocol) as ProfileOf<P>;
  base.meta = { ...base.meta, id: uid(), ...o.meta };
  if (o.endpoint && "endpoint" in base) base.endpoint = { ...base.endpoint, ...o.endpoint };
  if (o.tls && "tls" in base) base.tls = { ...base.tls, ...o.tls };
  if (o.transport && "transport" in base) base.transport = o.transport;
  if (o.root) Object.assign(base, o.root);
  return base;
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
  pendingRestart: false,
  latencyMs: null,
  tetherOffloadBypass: false,
};

function cloneServiceStatus(): ServiceStatus {
  return { ...serviceState };
}

/** Simulated ping latencies by profile ID (randomized each call) */
function simPing(): number {
  return Math.floor(Math.random() * 200) + 10 + Math.floor(Math.random() * 150);
}

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

const isEncryptedLink = (s: string) => /^(happ:\/\/crypt[2-5]?|incy:\/\/crypt1)\//i.test(s);

/** Dev stand-in for the backend's `import_input`: the same sorting, roughly, without
 *  decrypting (any `happ://crypt` or `incy://crypt1` link passes) and with a lenient routing decode. */
function simResolveToken(token: string): MockInput {
  const lower = token.toLowerCase();
  const plainUrl = (s: string) => /^https?:\/\/[^@/]+(\/|$)/i.test(s);
  if (isEncryptedLink(token)) return { sub: token, encrypted: true };
  if (!lower.startsWith("happ://"))
    return plainUrl(token) ? { sub: token, encrypted: false } : null;
  const rest = token.slice("happ://".length);
  if (/^add\//i.test(rest)) {
    const inner = decodeURIComponent(rest.slice(4));
    if (isEncryptedLink(inner)) return { sub: inner, encrypted: true };
    return plainUrl(inner) ? { sub: inner, encrypted: false } : { unsupported: "invalid" };
  }
  if (/^routing\/off\/?$/i.test(rest)) return { unsupported: "routingOff" };
  const routing = /^routing\/(on)?add\/(.+)$/i.exec(rest);
  if (routing) {
    try {
      const p = JSON.parse(atob(routing[2])) as Record<string, unknown>;
      const list = (k: string) => (Array.isArray(p[k]) ? (p[k] as string[]) : []);
      return {
        routing: {
          name: typeof p.Name === "string" && p.Name ? p.Name : "Routing",
          directSites: list("DirectSites"),
          directIp: list("DirectIp"),
          proxySites: list("ProxySites"),
          proxyIp: list("ProxyIp"),
          blockSites: list("BlockSites"),
          blockIp: list("BlockIp"),
          globalProxy: typeof p.GlobalProxy === "boolean" ? p.GlobalProxy : null,
          ignoredFields: Object.keys(p).filter((k) => /Dns|geo|DomainStrategy/i.test(k)),
        },
        activate: !!routing[1],
      };
    } catch {
      return { unsupported: "invalid" };
    }
  }
  if (/^send_to_device\//i.test(rest)) return { unsupported: "sendToDevice" };
  if (/^(toggle|connect|disconnect|open|close)(_without_ui)?\/?$/i.test(rest))
    return { unsupported: "control" };
  return { unsupported: "invalid" };
}

/** Dev stand-in for the backend's `extract_uris`: a link in one of its share-link
 *  schemes, or `http`/`https` with userinfo (an HTTP proxy, not a subscription). */
export function isShareLink(line: string): boolean {
  const m = /^([a-z0-9+]+):\/\/(\S*)/i.exec(line.trim());
  if (!m) return false;
  const scheme = m[1].toLowerCase();
  if (scheme === "http" || scheme === "https") return /^[^/@]*@/.test(m[2]);
  return SHARE_LINK_SCHEMES.includes(scheme);
}

type MockInput =
  | { sub: string; encrypted: boolean }
  | { routing: ResolvedImport["routing"][number]["routing"]; activate: boolean }
  | { unsupported: ResolvedImport["unsupported"][number]["kind"] }
  | null;

function simResolveImport(text: string): ResolvedImport {
  const out: ResolvedImport = { subscriptions: [], routing: [], unsupported: [], shareText: "" };
  const rest: string[] = [];
  for (const line of text.trim().split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const inputs = tokens.map(simResolveToken);
    if (inputs.some((x) => x === null)) {
      rest.push(line);
      continue;
    }
    inputs.forEach((x, i) => {
      if (!x) return;
      if ("sub" in x)
        out.subscriptions.push({
          url: x.sub,
          encrypted: x.encrypted,
          name: null,
          client: /^incy:/i.test(x.sub) ? "incy" : "happ",
        });
      else if ("routing" in x)
        out.routing.push({
          routing: x.routing,
          package: routingPackage(x.routing),
          activate: x.activate,
        });
      else out.unsupported.push({ text: tokens[i], kind: x.unsupported });
    });
  }
  out.shareText = rest.join("\n");
  return out;
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
      pendingRestart: false,
      uploadBytes: Math.floor(Math.random() * 500000),
      downloadBytes: Math.floor(Math.random() * 2000000),
      uptimeSec: 0,
      latencyMs: simPing(),
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
      latencyMs: null,
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
      xrayVersion: "Xray (mock)",
      singboxVersion: "sing-box (mock)",
      tun: false,
    };
  },

  async ping(_profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 300 + Math.random() * 700));
    const ms = simPing();
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
        onResult?.(p.meta.id, ms);
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return results;
  },

  async realPing(_profileId: string): Promise<number> {
    await new Promise((r) => setTimeout(r, 800 + Math.random() * 1200));
    const ms = Math.random() < 0.15 ? -1 : simPing();
    return ms;
  },

  async probeConnection(): Promise<ConnectionProbe> {
    await new Promise((r) => setTimeout(r, 300 + Math.random() * 500));
    return {
      profileId: serviceState.activeId,
      latencyMs: serviceState.state === "connected" ? simPing() : null,
    };
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
[${new Date().toISOString()}] [MOCK:${target}] TUN engine helper running (pid: ${Math.floor(Math.random() * 99999)})
[${new Date().toISOString()}] [MOCK:${target}] Traffic: ↑ ${serviceState.uploadBytes} B · ↓ ${serviceState.downloadBytes} B
-- Mock log lines above (${lines}) --`);
  },

  testLog(_profileId, kind): Promise<string> {
    // The UI only opens this from a failed (`err`) check, so emit a sample core log.
    const stamp = new Date().toISOString();
    return Promise.resolve(`${stamp} [MOCK:${kind}] starting test core on 127.0.0.1:24600
${stamp} [MOCK:${kind}] [Warning] failed to dial to upstream: dial tcp: i/o timeout
${stamp} [MOCK:${kind}] transport/internet: connection ends, reading error`);
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
      ruleBlocks: [...state.ruleBlocks],
      routes: [...state.routes],
      assetFiles: [...state.assetFiles],
    });
  },

  async mutate(intent) {
    // The schema migrations live only in Rust, so the mock restores just a
    // backup that already has the current shape.
    if (intent.kind === "importBackup") ProfileSchema.array().parse(intent.incoming.profiles ?? []);
    // No backend in dev: apply the intent locally with the same logic the Rust
    // backend runs, then return the canonical state.
    state = applyMutation(state, intent);
    // Like the backend: a settings change while running waits for a restart.
    if (intent.kind === "setSettings" && serviceState.state === "connected")
      serviceState = { ...serviceState, pendingRestart: true };
    return this.readState();
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

  async openUrl(url: string): Promise<void> {
    window.open(url, "_blank", "noopener,noreferrer");
  },

  // A rough stand-in for happ-sub's request builder, enough for the identity UI.
  async resolveRequestIdentity({ subId, input }) {
    const sub = subId ? state.subscriptions.find((x) => x.id === subId) : undefined;
    const defaults = input?.defaults ?? state.settings.requestIdentity;
    const request = input?.request ?? sub?.request ?? {};
    const ownUa = input ? input.userAgent : (sub?.userAgent ?? "");
    const facts = { os: "Android", osVersion: "16", model: "Pixel 9", locale: "ru-RU" };
    const pick = (...v: (string | null | undefined)[]) => v.find((x) => x?.trim()) ?? "";
    if ((input?.client ?? sub?.client) === "incy") {
      const auto = "6B1F0C2E-94D3-4A7B-8C15-2E9F0A7D4B31";
      const own = request.hwid?.trim();
      const hwid = own || auto;
      const tag = pick(request.locale, defaults.locale, facts.locale).replace(/_/g, "-");
      const headers = [
        { name: "User-Agent", value: ownUa.trim() || `INCY/${INCY_VERSION}/android Dalvik/2.1.0` },
        { name: "Accept", value: "*/*" },
        { name: "Accept-Language", value: tag },
      ];
      if (request.sendHwid ?? defaults.sendHwid)
        headers.push(
          { name: "x-hwid", value: hwid },
          { name: "x-device-os", value: "Android" },
          { name: "x-ver-os", value: pick(request.osVersion, defaults.osVersion, facts.osVersion) },
          {
            name: "x-device-model",
            value: `Google ${pick(request.deviceModel, defaults.deviceModel, facts.model)}`,
          },
        );
      headers.push(
        { name: "x-app-version", value: INCY_VERSION },
        { name: "x-device-locale", value: tag.replace(/-/g, "_") },
        { name: "x-client", value: "INCY" },
      );
      return {
        hwid,
        hwidSource: own ? "subscription" : "incyDerived",
        autoHwid: auto,
        autoHwidSource: "incyDerived",
        facts,
        headers,
        cookieJar: false,
        locks: { userAgent: false, sendHwid: false, hwidInCookie: false },
        providerHidesDevice: false,
        providerHwidCookie: false,
      };
    }
    const autoHwid = "3f9c2a7be1d04c58";
    const hwid = pick(request.hwid, defaults.hwid, autoHwid);
    const hwidSource = request.hwid?.trim()
      ? "subscription"
      : defaults.hwid?.trim()
        ? "settings"
        : "happComputed";
    // NodeHub pretends its provider sent `subscription-always-hwid-enable`.
    const always = sub?.id === "s-nodes";
    const send = always || (request.sendHwid ?? defaults.sendHwid);
    const cookie = request.hwidInCookie ?? defaults.hwidInCookie;
    const os = pick(request.deviceOs, defaults.deviceOs, facts.os);
    const ua = pick(ownUa, defaults.userAgent) || `Happ/${HAPP_VERSION}/${os}/mock`;
    const headers = [
      { name: "Connection", value: "close" },
      { name: "User-agent", value: ua },
      {
        name: "X-Device-Locale",
        value: pick(request.locale, defaults.locale, facts.locale)
          .split(/[-_.@]/)[0]
          .toLowerCase(),
      },
    ];
    if (send) {
      if (!cookie) headers.push({ name: "X-HWID", value: hwid });
      headers.push(
        { name: "X-Device-OS", value: os },
        { name: "X-Ver-OS", value: pick(request.osVersion, defaults.osVersion, facts.osVersion) },
        {
          name: "X-Device-model",
          value: pick(request.deviceModel, defaults.deviceModel, facts.model),
        },
      );
      if (cookie) headers.push({ name: "Cookie", value: hwid });
    }
    return {
      hwid,
      hwidSource,
      autoHwid,
      autoHwidSource: "happComputed",
      facts,
      headers,
      cookieJar: defaults.cookieJar,
      locks: { userAgent: false, sendHwid: always, hwidInCookie: false },
      providerHidesDevice: false,
      providerHwidCookie: false,
    };
  },

  // No backend daemon in dev, so headless sub-applies / asset refreshes never happen.
  onSubApplied() {
    return () => {};
  },

  onAssetsUpdated() {
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

  // Dev stub: the generated per-protocol default table (no capability matrix — the
  // real answer lives behind the backend's `resolveCores`).
  async resolveCores(profiles: Profile[]) {
    return profiles.map((p) => ({
      resolved: p.meta.coreType ?? DEFAULT_CORE_BY_PROTOCOL[p.protocol],
      forced: null,
    }));
  },

  // Dev stub: every other stored profile (no loop check — the real answer lives
  // behind the backend's `chainCandidates`).
  async chainCandidates(profile: Profile) {
    return state.profiles.filter((p) => p.meta.id !== profile.meta.id).map((p) => p.meta.id);
  },

  // Dev stub: no core matrix (the real answer lives behind the backend's
  // `chainConflicts`).
  async chainConflicts(_profile: Profile) {
    return [];
  },

  async checkReadiness(_profileId?: string): Promise<ReadinessReport> {
    return { profileId: _profileId ?? null, engine: null, ok: true, issues: [] };
  },

  // Dev stub: no clash check (the real answer lives behind the backend's
  // `checkLocalPorts`).
  async checkLocalPorts() {
    return null;
  },

  // Dev stub: flags nothing (the real answer lives behind the backend's
  // `catchAllRules`).
  async catchAllRules(rules) {
    return rules.map(() => false);
  },

  async validateProfile(profile: Profile): Promise<ProfileFieldIssue[]> {
    const issues: ProfileFieldIssue[] = [];
    if (!profile.meta.remarks.trim()) issues.push({ field: "remarks", issue: "remarksRequired" });
    if ("endpoint" in profile && profile.endpoint) {
      if (!profile.endpoint.address.trim())
        issues.push({ field: "address", issue: "addressRequired" });
      if (profile.endpoint.port < 1 || profile.endpoint.port > 65535)
        issues.push({ field: "port", issue: "portOutOfRange" });
    }
    if ("uuid" in profile && typeof profile.uuid === "string" && !profile.uuid.trim()) {
      issues.push({ field: "uuid", issue: "uuidRequired" });
    }
    const passwordNeeded =
      ["trojan", "shadowsocks", "hysteria2", "tuic", "anytls"].includes(profile.protocol) ||
      (profile.protocol === "shadowtls" && "version" in profile && profile.version !== 1);
    if (
      passwordNeeded &&
      "password" in profile &&
      typeof profile.password === "string" &&
      !profile.password.trim()
    ) {
      issues.push({ field: "password", issue: "passwordRequired" });
    }
    if (profile.protocol === "wireguard") {
      if (!profile.secretKey.trim())
        issues.push({ field: "secretKey", issue: "secretKeyRequired" });
      if (!profile.peerPublicKey.trim())
        issues.push({ field: "peerPublicKey", issue: "peerPublicKeyRequired" });
    }
    if (
      "transport" in profile &&
      profile.transport &&
      ["ws", "httpupgrade", "xhttp"].includes(profile.transport.kind)
    ) {
      const path = "path" in profile.transport ? profile.transport.path : "";
      if (!path?.trim()) issues.push({ field: "path", issue: "pathRequired" });
    }
    if ("tls" in profile && profile.tls && profile.tls.security === "reality") {
      if (!profile.tls.sni?.trim()) issues.push({ field: "sni", issue: "realitySniRequired" });
      if (!profile.tls.publicKey?.trim())
        issues.push({ field: "publicKey", issue: "publicKeyRequired" });
    }
    if (profile.protocol === "custom" && !profile.raw?.trim()) {
      issues.push({ field: "raw", issue: "rawConfigRequired" });
    }
    return issues;
  },

  async switchProfileProtocol(cur: Profile, proto: Protocol): Promise<Profile> {
    const next = emptyProfile(proto, cur.meta.groupId);
    next.meta = {
      ...next.meta,
      id: cur.meta.id,
      remarks: cur.meta.remarks,
      subId: cur.meta.subId,
      coreType: cur.meta.coreType,
      via: cur.meta.via,
    };
    if ("endpoint" in next && "endpoint" in cur) next.endpoint = { ...cur.endpoint };
    if ("tls" in next && next.tls && "tls" in cur && cur.tls) {
      const security =
        proto === "shadowsocks"
          ? "none"
          : cur.tls.security === "none"
            ? next.tls.security
            : cur.tls.security;
      next.tls = { ...cur.tls, security };
    }
    if ("transport" in next && "transport" in cur && cur.transport) next.transport = cur.transport;
    if ("uuid" in cur && "uuid" in next) next.uuid = cur.uuid;
    if ("password" in cur && "password" in next) next.password = cur.password;
    if ("username" in cur && "username" in next) next.username = cur.username;
    if ("muxEnabled" in cur && "muxEnabled" in next) next.muxEnabled = cur.muxEnabled;
    if ("flow" in cur && "flow" in next) next.flow = cur.flow;
    if ("packetEncoding" in cur && "packetEncoding" in next)
      next.packetEncoding = cur.packetEncoding;
    if ("congestionControl" in cur && "congestionControl" in next)
      next.congestionControl = cur.congestionControl;
    return next;
  },

  async buildRouteShare(route: Route, blocks: RuleBlock[]): Promise<RouteSharePayload> {
    return {
      exportJson: exportRoutePackage(route, blocks),
      flatJson: flattenRoute(route, blocks),
      namesProfiles: routeNamesProfiles(route, blocks),
    };
  },

  async parseRoutePackage(text: string): Promise<RoutePackage | null> {
    return parseRoutePackage(text);
  },

  // Dev stub: one nested placeholder profile per line that holds a share link.
  async parseShareLinks(text: string): Promise<Profile[]> {
    await new Promise((r) => setTimeout(r, 150));
    return text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(isShareLink)
      .map((_line, i) =>
        mk("vless", {
          meta: { remarks: `Imported #${i + 1}` },
          endpoint: { address: "imported.example.com", port: 443 },
          root: { uuid: uid() },
        }),
      );
  },

  async resolveImportInput(text: string): Promise<ResolvedImport> {
    await new Promise((r) => setTimeout(r, 120));
    return simResolveImport(text);
  },

  // Dev stub: a fixed address stands in for the decrypted one.
  async revealSubscriptionUrl(url: string): Promise<string> {
    if (!isEncryptedLink(url)) throw new Error("not an encrypted link");
    return "https://sub.provider.example/api/v1/sub/9f2c7e41?token=a8d3";
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

  async importBackup(backup, mode) {
    // The migrations live only in Rust, so a profile without the current shape is
    // left out and counted, as the backend does with one that still doesn't fit.
    const profiles = backup.profiles.filter((p) => ProfileSchema.safeParse(p).success);
    const incoming = { ...backup, profiles };
    state = applyMutation(state, { kind: "importBackup", incoming, mode });
    return {
      state: { ...(await this.readState()), schemaVersion: SCHEMA_VERSION },
      skippedProfiles: backup.profiles.length - profiles.length,
    };
  },
};
