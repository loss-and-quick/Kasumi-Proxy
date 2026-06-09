// ============================================================
// src/lib/ksu-bridge.ts
// Real Bridge implementation talking to bin/kasumi-proxyctl through one
// of the available transports (KernelSU/APatch JS interface or the
// token-gated CGI endpoint). The UI never builds shell snippets;
// every call resolves to:  kasumi-proxyctl <method> [args]. A stdin payload is
// staged to a tmp file via the native writeFile bridge and fed in with `< tmp`,
// so large state never hits the shell argv length limit (MAX_ARG_STRLEN).
// ============================================================
import type { AppState, Bridge, ResourceUpdateMode, ServiceStatus, Subscription } from "./bridge";
import { parseCapabilities, parseServiceStatus } from "./bridge";
import {
  execNative,
  getModuleId,
  getRuntimeBridgeMode,
  hasCgiToken,
  hasKsuFileApi,
  hasKsuNativeApi,
  ksuListApps,
  readFileNative,
  writeFileNative,
} from "./ksu-webui";
import { profileAddress, profilePort } from "./profile";

const DEFAULT_MODULE_ID = "kasumi-proxy";
const CGI = "http://127.17.1.3/cgi-bin/exec";
// Backend data dir (kasumi-proxyctl DATADIR). State and profiles live here; the
// native file bridge reads/writes them directly, bypassing the shell argv limit.
const DATADIR = "/data/adb/kasumi-proxy";
const STATE_PATH = `${DATADIR}/app-state.json`;
const PROFILES_PATH = `${DATADIR}/profiles.json`;

type AssetDownloadResponse = { ok: boolean; error?: string };
type AssetDownloadStatus = { state: "idle" | "running" | "done"; ok?: boolean; error?: string };

function getCtlPath(): string {
  return `/data/adb/modules/${getModuleId(DEFAULT_MODULE_ID)}/bin/kasumi-proxyctl`;
}

function getToken(): string {
  const m = /[?&]token=([^&]+)/.exec(window.location.search);
  return m ? decodeURIComponent(m[1]) : "";
}

/** base64-encode a UTF-8 string (for safe stdin transport). */
function b64(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

/** Compose the shell command for calls without stdin. */
function composeCommand(method: string, args: string[]): string {
  const quotedArgs = args.map((a) => `'${a.replace(/'/g, "'\\''")}'`).join(" ");
  return `${getCtlPath()} ${method} ${quotedArgs}`.trim();
}

/**
 * Run a kasumi-proxyctl call whose payload is passed on stdin. The payload is
 * staged to a tmp file via the native writeFile bridge (a JNI argument, not a
 * shell argument), then fed to the backend with `< tmp`. This avoids embedding
 * the payload in the command string, which the shell rejects past MAX_ARG_STRLEN
 * (~128 KB) — exactly the failure that broke large profiles.json writes.
 */
async function runWithStdin(method: string, args: string[], stdin: string): Promise<string> {
  if (!hasKsuFileApi())
    throw new Error(
      `kasumi-proxyctl ${method}: stdin payloads require the native file bridge (ksu.writeFile), which this manager does not expose`,
    );
  const tmp = `/data/local/tmp/.kasumi_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  writeFileNative(tmp, stdin);
  // Clean up tmp in both branches. Crucially, do NOT use `exit` on success: the
  // KernelSU exec shell dies before libsu reads the exit-code marker, which made
  // a successful write report failure. `&&/||` returns the right code without it.
  const { errno, stdout, stderr } = await execNative(
    `{ ${composeCommand(method, args)} < '${tmp}'; } && rm -f '${tmp}' || { rm -f '${tmp}'; false; }`,
  );
  if (errno !== 0)
    throw new Error(stderr.trim() || `kasumi-proxyctl ${method} exited with code ${errno}`);
  return stdout;
}

function lifecycleError(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const error = (value as Record<string, unknown>).error;
  return typeof error === "string" && error.trim() ? error : null;
}

function expectServiceState(
  method: string,
  value: unknown,
  expected: ServiceStatus["state"],
): ServiceStatus {
  const error = lifecycleError(value);
  if (!value || typeof value !== "object" || !("state" in value)) {
    throw new Error(
      error ? `${method} failed: ${error}` : `${method} failed: invalid service status payload`,
    );
  }
  const status = parseServiceStatus(value);
  if (status.state !== expected) {
    throw new Error(
      error
        ? `${method} failed: ${error} (service is ${status.state})`
        : `${method} failed: service is ${status.state}`,
    );
  }
  if (error) throw new Error(`${method} failed: ${error}`);
  return status;
}

// Like expectServiceState but does NOT require the core to already report the
// target state. A slow start — e.g. the one-time .srs regeneration after a
// geoip/geosite update, which blocks the core launch for a few seconds —
// legitimately returns before sing-box is up. The periodic status poll plus the
// service.sh watchdog reconcile the real state, so demanding "running" here only
// produced false "Service error" toasts and connected/disconnected flapping. We
// still surface an explicit lifecycle error or a malformed payload.
function acceptServiceState(method: string, value: unknown): ServiceStatus {
  const error = lifecycleError(value);
  if (error) throw new Error(`${method} failed: ${error}`);
  if (!value || typeof value !== "object" || !("state" in value)) {
    throw new Error(`${method} failed: invalid service status payload`);
  }
  return parseServiceStatus(value);
}

function parseAssetDownloadResponse(value: unknown): AssetDownloadResponse {
  if (!value || typeof value !== "object")
    return { ok: false, error: "Invalid asset download response" };
  const obj = value as Record<string, unknown>;
  return {
    ok: obj.ok === true || obj.ok === 1 || obj.ok === "1",
    ...(typeof obj.error === "string" ? { error: obj.error } : {}),
  };
}

function parseAssetDownloadStatus(value: unknown): AssetDownloadStatus {
  if (!value || typeof value !== "object")
    return { state: "idle", ok: false, error: "Invalid asset download status" };
  const obj = value as Record<string, unknown>;
  const state = obj.state;
  return {
    state: state === "running" || state === "done" ? state : "idle",
    ...(obj.ok === true || obj.ok === 1 || obj.ok === "1" ? { ok: true } : {}),
    ...(typeof obj.error === "string" ? { error: obj.error } : {}),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

type TestJobStatus = { state: "idle" | "running" | "done"; ms?: number; bps?: number };

function parseTestJobStatus(value: unknown): TestJobStatus {
  if (!value || typeof value !== "object") return { state: "idle" };
  const obj = value as Record<string, unknown>;
  const state = obj.state === "running" || obj.state === "done" ? obj.state : "idle";
  return {
    state,
    ...(typeof obj.ms === "number" ? { ms: obj.ms } : {}),
    ...(typeof obj.bps === "number" ? { bps: obj.bps } : {}),
  };
}

/**
 * Drive a diagnostic (tcping/realping/speedtest) as a background job: fire a
 * quick *Start exec, then poll a quick *Status exec until done. Crucial because
 * every ksu.exec blocks the WebView renderer for its whole duration — a single
 * multi-second test exec froze the UI, so the work must be split into sub-250ms
 * execs. `statusKey` is whatever the runner keys its job file on (the inbound
 * port for realping/speedtest, the profile id for tcping).
 */
async function runTestJob(
  startMethod: string,
  statusMethod: string,
  startArgs: string[],
  statusKey: string,
  timeoutMs: number,
  config?: string,
): Promise<TestJobStatus> {
  const started = parseAssetDownloadResponse(await callJson(startMethod, startArgs, config));
  if (!started.ok) return { state: "done" };
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const status = parseTestJobStatus(await callJson(statusMethod, [statusKey]));
    if (status.state === "done") return status;
    await sleep(250);
  }
  return { state: "done" };
}

/**
 * Run a kasumi-proxyctl call via the best available transport → stdout text.
 * The KernelSU transport execs a shell, so it gets a composed command string;
 * the CGI transport receives structured fields (newline-joined argv + base64
 * stdin) so the server can exec the pinned binary with a fixed argv — never
 * `eval` attacker-influenced shell.
 */
async function run(method: string, args: string[], stdin?: string): Promise<string> {
  // 1) KernelSU / APatch injected interface
  if (hasKsuNativeApi()) {
    if (stdin !== undefined) return runWithStdin(method, args, stdin);
    const { errno, stdout, stderr } = await execNative(composeCommand(method, args));
    if (errno !== 0)
      throw new Error(stderr.trim() || `kasumi-proxyctl ${method} exited with code ${errno}`);
    return stdout;
  }

  // 2) CGI fallback (token-gated). argv is base64 of newline-joined
  // [method, ...args]; the CGI rebuilds positional params and execs $CTL.
  // (App args never contain newlines — the only multiline payload is stdin.)
  if (!hasCgiToken()) {
    throw new Error(`kasumi-proxyctl ${method} is unavailable: no KernelSU bridge or CGI token`);
  }
  const token = getToken();
  const params = new URLSearchParams();
  params.set("argv", b64([method, ...args].join("\n")));
  if (stdin !== undefined) params.set("stdin", b64(stdin));
  const resp = await fetch(`${CGI}?token=${encodeURIComponent(token)}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  return resp.text();
}

/** Run and parse JSON output from kasumi-proxyctl. */
async function callJson(method: string, args: string[] = [], stdin?: string): Promise<unknown> {
  const out = (await run(method, args, stdin)).trim();
  try {
    return JSON.parse(out);
  } catch {
    throw new Error(`kasumi-proxyctl ${method} returned non-JSON: ${out.slice(0, 200)}`);
  }
}

/**
 * Ask the backend for a list of currently-free local ports. The backend only
 * knows which ports are *already* listening (it reads /proc/net/tcp), so this is
 * a single snapshot: one call returns `count` distinct, non-overlapping port
 * blocks, each `span` consecutive ports wide. Batch diagnostics allocate all
 * their worker ports here in one shot instead of repeated per-worker calls —
 * a test core binds its port asynchronously (after *Start returns), so repeated
 * calls would all see the same snapshot and hand back the same "free"
 * port, making the concurrent cores collide. `span` covers the widest test situation.
 */
const TEST_PORT_SPAN = 3;
async function freePorts(start: number, count: number, span = TEST_PORT_SPAN): Promise<number[]> {
  const resp = (await callJson("freePorts", [String(start), String(count), String(span)])) as {
    ports?: unknown;
  };
  return Array.isArray(resp?.ports)
    ? resp.ports.filter((n): n is number => typeof n === "number")
    : [];
}

/** Detect whether a real backend transport is reachable. */
export function hasNativeTransport(): boolean {
  return getRuntimeBridgeMode() !== "mock";
}

let lastState: AppState | null = null;

export const ksuBridge: Bridge = {
  async start(profileId) {
    const state = lastState ?? (await this.readState());
    const profile = state.profiles.find((p) => p.id === profileId);
    if (!profile) throw new Error(`Profile not found: ${profileId}`);
    const { resolveCore } = await import("./schema/core");
    const engine = resolveCore(profile, state.settings);
    const config =
      engine === "sing-box"
        ? (await import("./singbox-config")).buildSingboxConfigJSON(
            profile,
            state.settings,
            state.routingRules ?? [],
            state.profiles,
          )
        : (await import("./xray-config")).buildXrayConfigJSON(
            profile,
            state.settings,
            state.routingRules ?? [],
            state.profiles,
          );
    const socksPort = String(state.settings.localSocksPort ?? 10808);
    return acceptServiceState(
      "start",
      await callJson("start", [profileId, socksPort, engine], config),
    );
  },
  async stop() {
    return expectServiceState("stop", await callJson("stop"), "stopped");
  },
  async restart() {
    return acceptServiceState("restart", await callJson("restart"));
  },
  async status() {
    return parseServiceStatus(await callJson("status"));
  },
  async capabilities() {
    return {
      ...parseCapabilities(await callJson("capabilities")),
      bridge: getRuntimeBridgeMode(),
    };
  },
  onStatus(cb) {
    // No push channel from shell; poll periodically.
    // Guard against overlapping: if the previous status call is still in flight
    // (blocked behind a long-running exec), skip this tick instead of queuing.
    let polling = false;
    const t = setInterval(async () => {
      if (polling) return;
      polling = true;
      try {
        cb(await this.status());
      } catch {
        /* ignore transient errors */
      } finally {
        polling = false;
      }
    }, 1000);
    return () => clearInterval(t);
  },

  async ping(profileId) {
    const state = lastState ?? (await this.readState());
    const p = state.profiles.find((x) => x.id === profileId);
    if (!p) return 0;
    const addr = profileAddress(p),
      port = profilePort(p);
    if (!addr || port == null) return 0;
    const status = await runTestJob(
      "pingStart",
      "pingStatus",
      [profileId, addr, String(port)],
      profileId,
      8_000,
    );
    return typeof status.ms === "number" ? status.ms : 0;
  },
  async pingAll(onResult) {
    const state = lastState ?? (await this.readState());
    const out: Record<string, number> = {};
    const CONCURRENCY = state.settings.pingConcurrency ?? 10;
    const profiles = state.profiles.filter((p) => {
      const addr = profileAddress(p),
        port = profilePort(p);
      return addr && port != null;
    });
    let i = 0;
    const worker = async () => {
      while (i < profiles.length) {
        const p = profiles[i++];
        const addr = profileAddress(p);
        const port = profilePort(p);
        if (!addr || port == null) continue;
        // A failed/timed-out tcping reports 0 (→ "—" in the UI); always emit a
        // result so the row's spinner clears as soon as this profile resolves.
        let ms = 0;
        try {
          const status = await runTestJob(
            "pingStart",
            "pingStatus",
            [p.id, addr, String(port)],
            p.id,
            8_000,
          );
          if (typeof status.ms === "number") ms = status.ms;
        } catch {
          /* treat as failure (ms stays 0) */
        }
        out[p.id] = ms;
        onResult?.(p.id, ms);
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return out;
  },

  async realPing(profileId, port) {
    const state = lastState ?? (await this.readState());
    const p = state.profiles.find((x) => x.id === profileId);
    if (!p) return -1;
    const { resolveCore } = await import("./schema/core");
    const engine = resolveCore(p, state.settings);
    // Single test: grab one free block now. Batch runs pass `port` so every
    // worker gets a distinct block from one snapshot (see realPingAll).
    const realPingPort = port ?? (await freePorts(19000, 1))[0] ?? 19000;
    const patchedSettings = {
      ...state.settings,
      localSocksPort: realPingPort,
      localHttpPort: realPingPort + 1,
    };
    const config =
      engine === "sing-box"
        ? (await import("./singbox-config")).buildSingboxConfigJSON(
            p,
            patchedSettings,
            state.routingRules ?? [],
            state.profiles,
            { noTun: true },
          )
        : (await import("./xray-config")).buildXrayConfigJSON(
            p,
            patchedSettings,
            state.routingRules ?? [],
            state.profiles,
          );
    const status = await runTestJob(
      "realpingStart",
      "realpingStatus",
      [
        engine,
        state.settings.delayTestUrl || "http://www.gstatic.com/generate_204",
        String(realPingPort),
      ],
      String(realPingPort),
      20_000,
      config,
    );
    return typeof status.ms === "number" ? status.ms : -1;
  },

  async realPingAll(onResult) {
    const state = lastState ?? (await this.readState());
    const out: Record<string, number> = {};
    const CONCURRENCY = state.settings.pingConcurrency ?? 3;
    let i = 0;
    const profiles = state.profiles;
    // One snapshot of currently-free ports → one distinct block per worker, so
    // the concurrent test cores never share a SOCKS port / job file (which used
    // to make a parallel realPingAll return -1 for every profile). Each worker
    // reuses its own block across the profiles it pulls from the queue.
    const ports = await freePorts(19000, CONCURRENCY);
    const worker = async (slot: number) => {
      while (i < profiles.length) {
        const p = profiles[i++];
        let ms: number;
        try {
          ms = await this.realPing(p.id, ports[slot]);
        } catch {
          ms = -1;
        }
        out[p.id] = ms;
        onResult?.(p.id, ms);
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, (_, slot) => worker(slot)));
    return out;
  },

  async speedTest(profileId, port) {
    const state = lastState ?? (await this.readState());
    const p = state.profiles.find((x) => x.id === profileId);
    if (!p) return -1;
    const { resolveCore } = await import("./schema/core");
    const engine = resolveCore(p, state.settings);
    // Single test: grab one free block now. Batch runs pass `port` (see
    // speedTestAll). 19100 keeps speed tests clear of realping's 19000 band.
    const stPort = port ?? (await freePorts(19100, 1))[0] ?? 19100;
    const patchedSettings = {
      ...state.settings,
      localSocksPort: stPort,
      localHttpPort: stPort + 1,
    };
    const config =
      engine === "sing-box"
        ? (await import("./singbox-config")).buildSingboxConfigJSON(
            p,
            patchedSettings,
            state.routingRules ?? [],
            state.profiles,
            { noTun: true },
          )
        : (await import("./xray-config")).buildXrayConfigJSON(
            p,
            patchedSettings,
            state.routingRules ?? [],
            state.profiles,
          );
    const status = await runTestJob(
      "speedtestStart",
      "speedtestStatus",
      [
        engine,
        state.settings.speedTestUrl || "http://speed.cloudflare.com/__down?bytes=10000000",
        String(stPort),
        "15",
      ],
      String(stPort),
      30_000,
      config,
    );
    return typeof status.bps === "number" && status.bps > 0 ? status.bps : -1;
  },

  async speedTestAll(onResult) {
    const state = lastState ?? (await this.readState());
    const out: Record<string, number> = {};
    let i = 0;
    const profiles = state.profiles;
    const CONCURRENCY = state.settings.speedConcurrency ?? 1;
    // One snapshot → one distinct port block per worker (see realPingAll).
    const ports = await freePorts(19100, CONCURRENCY);
    const worker = async (slot: number) => {
      while (i < profiles.length) {
        const p = profiles[i++];
        let bps: number;
        try {
          bps = await this.speedTest(p.id, ports[slot]);
        } catch {
          bps = -1;
        }
        out[p.id] = bps;
        onResult?.(p.id, bps);
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, (_, slot) => worker(slot)));
    return out;
  },

  async log(input) {
    return run("log", [input?.target ?? "service", String(input?.lines ?? 300)]);
  },
  async clearLogs() {
    return parseAssetDownloadResponse(await callJson("clearLogs"));
  },

  async readState() {
    const { AppStateSchema } = await import("./schema/settings");
    let stateRaw: unknown;
    let profilesRaw: unknown;
    if (hasKsuFileApi()) {
      // Read straight from disk via the native bridge so a large profiles.json
      // never has to round-trip through exec's evaluateJavascript callback.
      const stateText = readFileNative(STATE_PATH).trim();
      stateRaw = stateText ? JSON.parse(stateText) : await callJson("readState");
      const profilesText = readFileNative(PROFILES_PATH).trim();
      profilesRaw = profilesText ? JSON.parse(profilesText) : [];
    } else {
      stateRaw = await callJson("readState");
      profilesRaw = await callJson("readProfiles").catch(() => []);
    }
    const stateObj = (stateRaw ?? {}) as { profiles?: unknown };
    let profiles = Array.isArray(profilesRaw) ? profilesRaw : [];
    // Legacy migration: before the split, profiles lived inside app-state.json and
    // there was no profiles.json. If the split file is empty but app-state still
    // carries the old array, adopt it and persist the split layout once below.
    const legacy = Array.isArray(stateObj.profiles) ? stateObj.profiles : [];
    const migrated = profiles.length === 0 && legacy.length > 0;
    if (migrated) profiles = legacy;
    const state = AppStateSchema.parse({ ...(stateObj as object), profiles });
    lastState = state;
    if (migrated) await this.writeState(state);
    return state;
  },
  async writeState(state) {
    lastState = state;
    const { profiles, ...rest } = state;
    await Promise.all([
      callJson("writeState", [], JSON.stringify({ ...rest, profiles: [] })),
      callJson("writeProfiles", [], JSON.stringify(profiles)),
    ]);
  },

  async fetchSubscription(url, opts) {
    const allow = opts?.allowInsecure ? "1" : "0";
    const ua = opts?.userAgent ?? "";
    const mode = opts?.mode ?? "auto";
    const raw = await run("fetchSubscription", [allow, mode, ua], url);
    return (await import("./share")).parseShareLinks(raw);
  },
  async listSubCache() {
    const out = await callJson("listSubCache");
    return Array.isArray(out)
      ? out.filter(
          (x): x is { id: string; fetchedAt: number } =>
            x && typeof x.id === "string" && typeof x.fetchedAt === "number",
        )
      : [];
  },
  async readSubCache(id) {
    return run("readSubCache", [id]);
  },
  async clearSubCache(id) {
    await run("clearSubCache", [id]);
  },
  async subWakeup() {
    await run("subWakeup", []);
  },
  async downloadAsset(filename, url, mode: ResourceUpdateMode = "auto") {
    const started = parseAssetDownloadResponse(
      await callJson("downloadAssetStart", [filename, mode], url),
    );
    if (!started.ok) return started;

    const deadline = Date.now() + 95_000;
    while (Date.now() < deadline) {
      const status = parseAssetDownloadStatus(await callJson("downloadAssetStatus", [filename]));
      if (status.state === "done") {
        return { ok: status.ok === true, ...(status.error ? { error: status.error } : {}) };
      }
      await sleep(250);
    }

    return { ok: false, error: "download timed out" };
  },
  async listAssets() {
    const out = await callJson("listAssets");
    return Array.isArray(out) ? out.filter((item): item is string => typeof item === "string") : [];
  },
  async listApps() {
    if (hasKsuNativeApi()) return ksuListApps();
    const out = await callJson("listApps");
    if (!Array.isArray(out)) return [];
    return out.filter(
      (x): x is { pkg: string; uid: number; system: boolean } =>
        x && typeof x.pkg === "string" && typeof x.uid === "number",
    );
  },
  async reloadAppFilter() {
    return parseAssetDownloadResponse(await callJson("reloadAppFilter"));
  },

  async parseShareLinks(text) {
    return (await import("./share")).parseShareLinks(text);
  },
  async buildShareLink(p) {
    return (await import("./share")).buildShareLink(p);
  },
  async exportBackup() {
    const state = await this.readState();
    return new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
  },
  async importBackup(file, mode) {
    const text = await file.text();
    const { AppStateSchema } = await import("./schema/settings");
    const incoming = AppStateSchema.parse(JSON.parse(text));
    const current = await this.readState();
    const merged: AppState =
      mode === "replace"
        ? { ...incoming, profiles: current.profiles }
        : {
            ...current,
            profiles: [...current.profiles, ...incoming.profiles],
            groups: [...current.groups, ...incoming.groups],
            subscriptions: [...current.subscriptions, ...incoming.subscriptions],
            routingRules: [...current.routingRules, ...incoming.routingRules],
            assetFiles: [...current.assetFiles, ...incoming.assetFiles],
            settings: incoming.settings,
          };
    await this.writeState(merged);
  },
};

export type { Subscription };
