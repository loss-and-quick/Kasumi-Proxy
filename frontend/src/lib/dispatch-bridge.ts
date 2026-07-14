// ============================================================
// src/lib/dispatch-bridge.ts
// The transport-neutral Bridge implementation. Both transports (desktop Tauri
// `invoke` and the Android daemon WS) carry the same typed Command/Response
// generated from Rust (src/generated/bindings.ts); this builds the typed commands
// and parses the typed replies. Diagnostics concurrency and port allocation live in
// the daemon now — a batch here is just one per-profile call fired per id. A
// transport only provides `dispatch(cmd)` plus the two push subscriptions.
// ============================================================

import type {
  AppState_Serialize,
  Command_Deserialize,
  Profile,
  Response_Serialize,
} from "../generated/bindings";
import type { AppEntry, AppState, Bridge, ResourceUpdateMode, ServiceStatus } from "./bridge";
import { parseCapabilities, parseServiceStatus } from "./bridge";
import { profileAddress, profilePort } from "./profile-utils";

// The transport speaks the two concrete serde phases, not the `Serialize |
// Deserialize` union aliases: a command is what the backend *deserializes*
// (`Command_Deserialize`), a reply is what it *serializes* (`Response_Serialize`).
// Pinning both ends to the phase the wire actually carries lets the typed command
// literals and reply unwrapping check structurally, with no `as unknown` bridging.
/** Run one typed command and resolve its typed reply (or reject on a backend error). */
export type Dispatch = (cmd: Command_Deserialize) => Promise<Response_Serialize>;

/** Push streams a transport exposes. Each callback gets the raw payload object. */
export interface PushStreams {
  subscribeStatus(cb: (raw: unknown) => void): () => void;
  subscribeSubApplied(cb: (raw: unknown) => void): () => void;
}

// ---- typed Response unwrapping ----

function wrongKind(r: Response_Serialize, want: string): never {
  throw new Error(`expected ${want} reply, got "${r.kind}"`);
}
// `state` carries `AppState_Serialize`; the UI's `AppState` is that minus the
// backend-owned `schemaVersion`, so the reply is assignable as-is.
const asState = (r: Response_Serialize): AppState =>
  r.kind === "state" ? r.value : wrongKind(r, "state");
const asProfiles = (r: Response_Serialize): Profile[] =>
  r.kind === "profiles" ? r.value : wrongKind(r, "profiles");
const asText = (r: Response_Serialize): string =>
  r.kind === "text" ? r.value : r.kind === "ok" ? "" : wrongKind(r, "text");
const asAssets = (r: Response_Serialize): string[] =>
  r.kind === "assets" ? r.value : wrongKind(r, "assets");
// The wire carries `null` for "no result"; the Bridge contract still uses the
// `-1` sentinel (collapsed at the frontend boundary until the store migrates).
const asPing = (r: Response_Serialize): number =>
  r.kind === "ping" ? (r.value ?? -1) : wrongKind(r, "ping");
const asSpeed = (r: Response_Serialize): number =>
  r.kind === "speed" ? (r.value ?? -1) : wrongKind(r, "speed");

/** Build a Bridge over a dispatcher + push streams. The on-disk split (state file
 *  without profiles, profiles file) and the UI's status shaping live here. */
export function createBridge(dispatch: Dispatch, push: PushStreams): Bridge {
  // The status command returns only the ServiceState (no activeId/core); the push
  // stream carries the full ServiceStatus. Cache the last of each so status() can
  // compose the full shape between pushes.
  let lastState: AppState | null = null;
  let lastStatus: ServiceStatus | null = null;

  /** Compose the UI ServiceStatus from a status-command ServiceState + the cached
   *  push-only fields (active id, core label, pending-restart flag). */
  function composeStatus(raw: unknown): ServiceStatus {
    const s = (raw && typeof raw === "object" ? { ...(raw as object) } : {}) as Record<
      string,
      unknown
    >;
    return parseServiceStatus({
      ...s,
      activeId: lastStatus?.activeId ?? lastState?.activeId ?? null,
      core: lastStatus?.core ?? "",
      pendingRestart: lastStatus?.pendingRestart ?? false,
    });
  }

  const bridge: Bridge = {
    async start(profileId) {
      await dispatch({ cmd: "start", profileId });
      return this.status();
    },
    async stop() {
      await dispatch({ cmd: "stop" });
      return this.status();
    },
    async restart() {
      await dispatch({ cmd: "restart" });
      return this.status();
    },
    async status() {
      const r = await dispatch({ cmd: "status" });
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
      const r = await dispatch({ cmd: "capabilities" });
      if (r.kind !== "capabilities") wrongKind(r, "capabilities");
      return parseCapabilities(r.value);
    },

    async ping(profileId) {
      // Read fresh: a stale cache here would wrongly report "0" for a profile it no
      // longer knows about (and pingAll fans out through this path).
      const state = await this.readState();
      const p = state.profiles.find((x) => x.meta.id === profileId);
      if (!p || !profileAddress(p) || profilePort(p) == null) return 0;
      return asPing(await dispatch({ cmd: "ping", profileId }));
    },
    async pingAll(ids, onResult) {
      // TCP-ping needs each profile's address/port, so read fresh state rather than
      // trusting a possibly-stale cache — a stale cache would filter out the
      // requested ids and make the batch finish instantly without testing anything.
      const state = await this.readState();
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
            // We already read fresh state above and filtered to profiles with a
            // valid address/port, so dispatch the ping command directly instead of
            // going through this.ping() (which would re-read state per profile).
            ms = asPing(await dispatch({ cmd: "ping", profileId: p.meta.id }));
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
      return asPing(await dispatch({ cmd: "realPing", profileId }));
    },
    async realPingAll(ids, onResult) {
      const out: Record<string, number> = {};
      // Fire one per profile id straight at the daemon (it loads the profile from
      // disk and bounds how many probe cores run at once); each resolves
      // independently so results stream in as they land. We deliberately don't
      // gate on the cached state here — a stale cache would silently drop ids and
      // make the whole batch a no-op. Ok(None) (unreachable) comes back as -1; a
      // thrown error is the infra-failure case (-2 → "err"), kept distinct.
      await Promise.all(
        [...new Set(ids)].map(async (id) => {
          let ms: number;
          try {
            ms = await this.realPing(id);
          } catch {
            ms = -2;
          }
          out[id] = ms;
          onResult?.(id, ms);
        }),
      );
      return out;
    },

    async speedTest(profileId) {
      return asSpeed(await dispatch({ cmd: "speedTest", profileId }));
    },
    async speedTestAll(ids, onResult) {
      const out: Record<string, number> = {};
      // Same as realPingAll: drive the batch off the ids the caller passed, not the
      // cached state — the daemon resolves each profile by id, so a stale cache
      // must never be allowed to collapse the list into a silent no-op.
      await Promise.all(
        [...new Set(ids)].map(async (id) => {
          let bps: number;
          try {
            bps = await this.speedTest(id);
          } catch {
            bps = -2;
          }
          out[id] = bps;
          onResult?.(id, bps);
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
        }),
      );
    },
    async testLog(profileId, kind) {
      return asText(await dispatch({ cmd: "testLog", profileId, kind }));
    },
    async clearLogs() {
      return okResult(() => dispatch({ cmd: "clearLogs" }));
    },

    async readState() {
      // One read: the backend returns the full canonical state — profiles merged in,
      // schema-migrated and normalized (base group ensured, legacy assets dropped,
      // dangling active_id nulled). The UI renders it as-is; no client-side merge,
      // ensure, or persist (the read counterpart of the single Mutate write path).
      const state = asState(await dispatch({ cmd: "readState" }));
      lastState = state;
      return state;
    },
    async mutate(intent) {
      const next = asState(await dispatch({ cmd: "mutate", intent }));
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
      });
      return asProfiles(profiles);
    },
    async applySubscription(subId) {
      // Returns the canonical state — refresh the cache like readState/mutate do, so
      // the next cache reader (e.g. ping's address/port lookup) can't drift after a
      // subscription apply swaps the profile set out from under it.
      const next = asState(await dispatch({ cmd: "applySubscription", subId }));
      lastState = next;
      return next;
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
      return okResult(() => dispatch({ cmd: "downloadAsset", filename, url, mode }));
    },
    async listAssets() {
      return asAssets(await dispatch({ cmd: "listAssets" }));
    },
    async listApps(): Promise<AppEntry[]> {
      const r = await dispatch({ cmd: "listApps" });
      if (r.kind !== "apps") return [];
      return r.value.filter(
        (x): x is AppEntry => !!x && typeof x.pkg === "string" && typeof x.uid === "number",
      );
    },
    async reloadAppFilter() {
      return okResult(() => dispatch({ cmd: "reloadAppFilter" }));
    },

    async resolveCores(profiles) {
      const r = await dispatch({ cmd: "resolveCores", profiles });
      return r.kind === "coreResolutions" ? r.value : wrongKind(r, "coreResolutions");
    },

    async parseShareLinks(text) {
      const r = await dispatch({ cmd: "parseShareLinks", text });
      return asProfiles(r);
    },
    async buildShareLink(p) {
      return asText(await dispatch({ cmd: "buildShareLink", profile: p }));
    },
    async exportBackup() {
      const state = await this.readState();
      return new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
    },
    async importBackup(file, mode) {
      const text = await file.text();
      const { AppStateSchema } = await import("../generated/schemas");
      // `parse` returns the `Serialize | Deserialize` union; narrow to the all-fields
      // phase the intent carries (the backend re-validates and owns the merge).
      const incoming = AppStateSchema.parse(JSON.parse(text)) as AppState_Serialize;
      await this.mutate({ kind: "importBackup", incoming, mode });
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
