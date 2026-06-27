// ============================================================
// src/lib/dispatch-bridge.ts
// The transport-neutral Bridge implementation. Both transports (desktop Tauri
// `invoke` and the Android daemon WS) carry the same typed Command/Response
// generated from Rust (src/generated/bindings.ts); this builds the typed commands
// and parses the typed replies. Diagnostics concurrency and port allocation live in
// the daemon now — a batch here is just one per-profile call fired per id. A
// transport only provides `dispatch(cmd)` plus the two push subscriptions.
// ============================================================

import type { Command, Profile, Response } from "../generated/bindings";
import type {
  AppEntry,
  AppState,
  Bridge,
  MutationIntent,
  ResourceUpdateMode,
  ServiceStatus,
} from "./bridge";
import { parseCapabilities, parseServiceStatus } from "./bridge";
import { profileAddress, profilePort } from "./profile-utils";

/** Run one typed command and resolve its typed reply (or reject on a backend error). */
export type Dispatch = (cmd: Command) => Promise<Response>;

/** Push streams a transport exposes. Each callback gets the raw payload object. */
export interface PushStreams {
  subscribeStatus(cb: (raw: unknown) => void): () => void;
  subscribeSubApplied(cb: (raw: unknown) => void): () => void;
}

// ---- typed Response unwrapping ----

function wrongKind(r: Response, want: string): never {
  throw new Error(`expected ${want} reply, got "${r.kind}"`);
}
const asState = (r: Response): AppState =>
  r.kind === "state" ? (r.value as unknown as AppState) : wrongKind(r, "state");
const asProfiles = (r: Response): Profile[] =>
  r.kind === "profiles" ? (r.value as unknown as Profile[]) : wrongKind(r, "profiles");
const asText = (r: Response): string =>
  r.kind === "text" ? r.value : r.kind === "ok" ? "" : wrongKind(r, "text");
const asAssets = (r: Response): string[] =>
  r.kind === "assets" ? r.value : wrongKind(r, "assets");
// The wire carries `null` for "no result"; the Bridge contract still uses the
// `-1` sentinel (collapsed at the frontend boundary until the store migrates).
const asPing = (r: Response): number =>
  r.kind === "ping" ? (r.value ?? -1) : wrongKind(r, "ping");
const asSpeed = (r: Response): number =>
  r.kind === "speed" ? (r.value ?? -1) : wrongKind(r, "speed");

/** Build a Bridge over a dispatcher + push streams. The on-disk split (state file
 *  without profiles, profiles file) and the UI's status shaping live here. */
export function createBridge(dispatch: Dispatch, push: PushStreams): Bridge {
  // The status command returns only the ServiceState (no activeId/core); the push
  // stream carries the full ServiceStatus. Cache the last of each so status() can
  // compose the full shape between pushes.
  let lastState: AppState | null = null;
  let lastStatus: ServiceStatus | null = null;

  /** Compose the UI ServiceStatus from a status-command ServiceState + cached id/core. */
  function composeStatus(raw: unknown): ServiceStatus {
    const s = (raw && typeof raw === "object" ? { ...(raw as object) } : {}) as Record<
      string,
      unknown
    >;
    return parseServiceStatus({
      ...s,
      activeId: lastStatus?.activeId ?? lastState?.activeId ?? null,
      core: lastStatus?.core ?? "",
    });
  }

  const bridge: Bridge = {
    async start(profileId) {
      await dispatch({ cmd: "start", profileId } as Command);
      return this.status();
    },
    async stop() {
      await dispatch({ cmd: "stop" } as Command);
      return this.status();
    },
    async restart() {
      await dispatch({ cmd: "restart" } as Command);
      return this.status();
    },
    async status() {
      const r = await dispatch({ cmd: "status" } as Command);
      if (r.kind !== "status") wrongKind(r, "status");
      return composeStatus(r.value);
    },
    onStatus(cb) {
      return push.subscribeStatus((raw) => {
        const s = parseServiceStatus(raw);
        lastStatus = s;
        cb(s);
      });
    },
    async capabilities() {
      const r = await dispatch({ cmd: "capabilities" } as Command);
      if (r.kind !== "capabilities") wrongKind(r, "capabilities");
      return parseCapabilities(r.value);
    },

    async ping(profileId) {
      const state = lastState ?? (await this.readState());
      const p = state.profiles.find((x) => x.meta.id === profileId);
      if (!p || !profileAddress(p) || profilePort(p) == null) return 0;
      return asPing(await dispatch({ cmd: "ping", profileId } as Command));
    },
    async pingAll(ids, onResult) {
      const state = lastState ?? (await this.readState());
      const out: Record<string, number> = {};
      const want = new Set(ids);
      const profiles = state.profiles.filter(
        (p) => want.has(p.meta.id) && profileAddress(p) && profilePort(p) != null,
      );
      const concurrency = state.settings.pingConcurrency ?? 10;
      let i = 0;
      const worker = async () => {
        while (i < profiles.length) {
          const p = profiles[i++];
          let ms = 0;
          try {
            ms = await this.ping(p.meta.id);
          } catch {
            /* failure → 0 */
          }
          out[p.meta.id] = ms;
          onResult?.(p.meta.id, ms);
        }
      };
      await Promise.all(Array.from({ length: concurrency }, worker));
      return out;
    },

    async realPing(profileId) {
      return asPing(await dispatch({ cmd: "realPing", profileId } as Command));
    },
    async realPingAll(ids, onResult) {
      const state = lastState ?? (await this.readState());
      const out: Record<string, number> = {};
      const want = new Set(ids);
      const profiles = state.profiles.filter((p) => want.has(p.meta.id));
      // Fire one per profile and let the daemon bound how many probe cores run at
      // once; each resolves independently so results stream in as they land.
      // Ok(None) (unreachable) comes back as -1; a thrown error is the infra-failure
      // case (-2 → "err"), kept distinct.
      await Promise.all(
        profiles.map(async (p) => {
          let ms: number;
          try {
            ms = await this.realPing(p.meta.id);
          } catch {
            ms = -2;
          }
          out[p.meta.id] = ms;
          onResult?.(p.meta.id, ms);
        }),
      );
      return out;
    },

    async speedTest(profileId) {
      return asSpeed(await dispatch({ cmd: "speedTest", profileId } as Command));
    },
    async speedTestAll(ids, onResult) {
      const state = lastState ?? (await this.readState());
      const out: Record<string, number> = {};
      const want = new Set(ids);
      const profiles = state.profiles.filter((p) => want.has(p.meta.id));
      await Promise.all(
        profiles.map(async (p) => {
          let bps: number;
          try {
            bps = await this.speedTest(p.meta.id);
          } catch {
            bps = -2;
          }
          out[p.meta.id] = bps;
          onResult?.(p.meta.id, bps);
        }),
      );
      return out;
    },

    async log(input) {
      return asText(
        await dispatch({
          cmd: "log",
          target: input?.target ?? "daemon",
          lines: input?.lines ?? 300,
        } as Command),
      );
    },
    async clearLogs() {
      return okResult(() => dispatch({ cmd: "clearLogs" } as Command));
    },

    async readState() {
      // One read: the backend returns the full canonical state — profiles merged in,
      // schema-migrated and normalized (base group ensured, legacy assets dropped,
      // dangling active_id nulled). The UI renders it as-is; no client-side merge,
      // ensure, or persist (the read counterpart of the single Mutate write path).
      const state = asState(await dispatch({ cmd: "readState" } as Command));
      lastState = state;
      return state;
    },
    async mutate(intent) {
      const next = asState(await dispatch({ cmd: "mutate", intent } as unknown as Command));
      lastState = next;
      return next;
    },

    async fetchSubscription(url, opts) {
      const profiles = await dispatch({
        cmd: "fetchSubscription",
        url,
        mode: opts?.mode ?? "auto",
        userAgent: opts?.userAgent ?? null,
        allowInsecure: opts?.allowInsecure ?? false,
      } as Command);
      return asProfiles(profiles);
    },
    async applySubscription(subId) {
      return asState(await dispatch({ cmd: "applySubscription", subId } as Command));
    },
    onSubApplied(cb) {
      return push.subscribeSubApplied((raw) => {
        const o = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
        if (typeof o.subId === "string") {
          cb({
            subId: o.subId,
            remarks: typeof o.remarks === "string" ? o.remarks : "",
            count: typeof o.count === "number" ? o.count : 0,
          });
        }
      });
    },
    async downloadAsset(filename, url, mode: ResourceUpdateMode = "auto") {
      return okResult(() => dispatch({ cmd: "downloadAsset", filename, url, mode } as Command));
    },
    async listAssets() {
      return asAssets(await dispatch({ cmd: "listAssets" } as Command));
    },
    async listApps(): Promise<AppEntry[]> {
      const r = await dispatch({ cmd: "listApps" } as Command);
      if (r.kind !== "apps") return [];
      return r.value.filter(
        (x): x is AppEntry => !!x && typeof x.pkg === "string" && typeof x.uid === "number",
      );
    },
    async reloadAppFilter() {
      return okResult(() => dispatch({ cmd: "reloadAppFilter" } as Command));
    },

    async parseShareLinks(text) {
      const r = await dispatch({ cmd: "parseShareLinks", text } as Command);
      return asProfiles(r);
    },
    async buildShareLink(p) {
      return asText(await dispatch({ cmd: "buildShareLink", profile: p } as unknown as Command));
    },
    async exportBackup() {
      const state = await this.readState();
      return new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    },
    async importBackup(file, mode) {
      const text = await file.text();
      const { AppStateSchema } = await import("../generated/schemas");
      const incoming = AppStateSchema.parse(JSON.parse(text)) as unknown as AppState;
      // Let the backend own the merge + invariants; ship the parsed backup as an
      // importBackup intent.
      await this.mutate({ kind: "importBackup", incoming, mode } as unknown as MutationIntent);
    },
  };
  return bridge;
}

/** A typed dispatch rejects on a backend error, so reaching the resolve = success. */
async function okResult(run: () => Promise<unknown>): Promise<{ ok: boolean; error?: string }> {
  try {
    await run();
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
