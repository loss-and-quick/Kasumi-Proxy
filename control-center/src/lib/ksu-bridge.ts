// ============================================================
// src/lib/ksu-bridge.ts
// Real Bridge implementation talking to bin/kasumi-proxyctl through one
// of the available transports (KernelSU/APatch JS interface or the
// token-gated CGI endpoint). The UI never builds shell snippets;
// every call resolves to:  kasumi-proxyctl <method> [args]  with the
// payload (if any) piped on stdin as base64 to avoid quoting bugs.
// ============================================================
import type { AppState, Bridge, ResourceUpdateMode, ServiceStatus, Subscription } from "./bridge";
import { parseCapabilities, parseServiceStatus } from "./bridge";
import {
  execNative,
  getModuleId,
  getRuntimeBridgeMode,
  hasCgiToken,
  hasKsuNativeApi,
  ksuListApps,
} from "./ksu-webui";
import { profileAddress, profilePort } from "./profile";

const DEFAULT_MODULE_ID = "kasumi-proxy";
const CGI = "http://127.17.1.3/cgi-bin/exec";
type PingResponse = { ms: number | null };
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

/** Compose the shell command: decode stdin from base64, pipe into kasumi-proxyctl. */
function composeCommand(method: string, args: string[], stdin?: string): string {
  const quotedArgs = args.map((a) => `'${a.replace(/'/g, "'\\''")}'`).join(" ");
  const tail = `${getCtlPath()} ${method} ${quotedArgs}`.trim();
  if (stdin === undefined) return tail;
  return `printf '%s' '${b64(stdin)}' | base64 -d | ${tail}`;
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

function parsePingResponse(value: unknown): PingResponse {
  if (!value || typeof value !== "object") return { ms: null };
  const ms = (value as Record<string, unknown>).ms;
  return { ms: typeof ms === "number" ? ms : null };
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
    const { errno, stdout, stderr } = await execNative(composeCommand(method, args, stdin));
    if (errno !== 0 && !stdout.trim()) {
      throw new Error(stderr.trim() || `kasumi-proxyctl ${method} exited with code ${errno}`);
    }
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
    const t = setInterval(async () => {
      try {
        cb(await this.status());
      } catch {
        /* ignore transient errors */
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
    const r = parsePingResponse(await callJson("ping", [addr, String(port)]));
    return r.ms ?? 0;
  },
  async pingAll() {
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
        try {
          const r = parsePingResponse(await callJson("ping", [addr, String(port)]));
          if (r.ms != null) out[p.id] = r.ms;
        } catch {
          /* skip */
        }
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return out;
  },

  async realPing(profileId) {
    const state = lastState ?? (await this.readState());
    const p = state.profiles.find((x) => x.id === profileId);
    if (!p) return -1;
    const { resolveCore } = await import("./schema/core");
    const engine = resolveCore(p, state.settings);
    const portResp = (await callJson("freePort", ["19000"])) as { port?: number };
    const realPingPort = portResp?.port || 19000;
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
          )
        : (await import("./xray-config")).buildXrayConfigJSON(
            p,
            patchedSettings,
            state.routingRules ?? [],
            state.profiles,
          );
    const r = parsePingResponse(
      await callJson(
        "realping",
        [
          engine,
          state.settings.delayTestUrl || "http://www.gstatic.com/generate_204",
          String(realPingPort),
        ],
        config,
      ),
    );
    return r.ms ?? -1;
  },

  async realPingAll() {
    const state = lastState ?? (await this.readState());
    const out: Record<string, number> = {};
    const CONCURRENCY = state.settings.pingConcurrency ?? 3;
    let i = 0;
    const profiles = state.profiles;
    const worker = async () => {
      while (i < profiles.length) {
        const p = profiles[i++];
        try {
          out[p.id] = await this.realPing(p.id);
        } catch {
          out[p.id] = -1;
        }
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    return out;
  },

  async speedTest(profileId) {
    const state = lastState ?? (await this.readState());
    const p = state.profiles.find((x) => x.id === profileId);
    if (!p) return -1;
    const { resolveCore } = await import("./schema/core");
    const engine = resolveCore(p, state.settings);
    const portResp = (await callJson("freePort", ["19100"])) as { port?: number };
    const stPort = portResp?.port || 19100;
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
          )
        : (await import("./xray-config")).buildXrayConfigJSON(
            p,
            patchedSettings,
            state.routingRules ?? [],
            state.profiles,
          );
    const raw = (await callJson(
      "speedtest",
      [
        engine,
        state.settings.speedTestUrl || "http://speed.cloudflare.com/__down?bytes=10000000",
        String(stPort),
        "15",
      ],
      config,
    )) as { bps?: number };
    return typeof raw?.bps === "number" && raw.bps > 0 ? raw.bps : -1;
  },

  async speedTestAll() {
    const state = lastState ?? (await this.readState());
    const out: Record<string, number> = {};
    let i = 0;
    const profiles = state.profiles;
    const CONCURRENCY = state.settings.speedConcurrency ?? 1;
    const worker = async () => {
      while (i < profiles.length) {
        const p = profiles[i++];
        try {
          out[p.id] = await this.speedTest(p.id);
        } catch {
          out[p.id] = -1;
        }
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
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
    const state = AppStateSchema.parse(await callJson("readState"));
    lastState = state;
    return state;
  },
  async writeState(state) {
    lastState = state;
    await callJson("writeState", [], JSON.stringify(state));
  },

  async fetchSubscription(url, opts) {
    const allow = opts?.allowInsecure ? "1" : "0";
    const ua = opts?.userAgent ?? "";
    const raw = await run("fetchSubscription", [allow, "1", ua], url);
    return (await import("./share")).parseShareLinks(raw);
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
        ? incoming
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
