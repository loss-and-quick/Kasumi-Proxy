// ============================================================
// src/store/useAppStore.ts
// Zustand store — the single in-memory source the UI reads from.
// It hydrates from the bridge (app-state.json on device, mock in
// dev) and writes through on every mutation (debounced).
// ============================================================

import { create } from "zustand";
import type { Profile } from "../generated/bindings";
import { translateCurrent } from "../i18n";
import type {
  AdvancedSettings,
  AppState,
  AssetFile,
  Capabilities,
  MutationIntent,
  ResourceUpdateMode,
  RoutingRule,
  ServiceStatus,
  SubAppliedEvent,
  Subscription,
} from "../lib/bridge";
import { isServiceUp } from "../lib/bridge";
import { bridge } from "../lib/bridge-provider";
import { showNativeToast } from "../lib/ksu-webui";
import { uid } from "../lib/utils";
import type { ActivityEvent } from "./activity";
import { ActivityService } from "./activity";
import { EMPTY_SETTINGS, mergeSettings } from "./defaults";
import { errorMessage } from "./errors";

/** A queued, auto-dismissing notification shown by the <Toaster>. */
export interface ToastItem {
  id: string;
  msg: string;
}

// Most toasts the stack shows at once; older ones drop off as new ones arrive.
const TOAST_LIMIT = 3;
const TOAST_DURATION_MS = 2600;

interface Store extends AppState {
  service: ServiceStatus;
  uploadRate: number;
  downloadRate: number;
  caps: Capabilities | null;
  hydrated: boolean;
  busy: boolean; // true while a service lifecycle op is in flight
  pinging: Set<string>; // profile ids currently being pinged
  speedTesting: Set<string>; // profile ids currently being speed-tested
  toasts: ToastItem[];
  recentActivity: ActivityEvent[];
  recentProfileIds: string[]; // most-recently-activated first, for the tray quick-switch

  hydrate: () => Promise<void>;
  notify: (msg: string) => void;
  dismissToast: (id: string) => void;

  // service
  setActive: (id: string) => Promise<void>;
  toggleService: () => Promise<void>;
  restart: () => Promise<void>;
  refreshStatus: () => Promise<void>;

  // profiles
  upsertProfile: (p: Profile) => Promise<void>;
  removeProfile: (id: string) => Promise<void>;
  removeProfiles: (ids: string[]) => Promise<void>;
  cloneProfile: (id: string) => Promise<void>;
  moveProfiles: (ids: string[], groupId: string) => Promise<void>;
  addProfiles: (profiles: Profile[]) => Promise<void>;
  pingProfile: (id: string) => Promise<void>;
  realPingProfile: (id: string) => Promise<void>;
  speedTestProfile: (id: string) => Promise<void>;
  pingAll: (groupId?: string) => Promise<void>;
  realPingAll: (groupId?: string) => Promise<void>;
  speedTestAll: (groupId?: string) => Promise<void>;
  removeUnreachable: (groupId?: string) => Promise<void>;
  removeDuplicates: (groupId?: string) => Promise<void>;
  selectBest: (groupId?: string) => Promise<void>;

  // groups
  addGroup: (name: string) => Promise<string>;
  renameGroup: (id: string, name: string) => Promise<void>;
  removeGroup: (id: string) => Promise<void>;
  reorderGroups: (from: number, to: number) => Promise<void>;

  // subscriptions
  upsertSub: (s: Subscription) => Promise<void>;
  removeSub: (id: string) => Promise<void>;
  updateSub: (id: string) => Promise<void>;
  updateAllSubs: () => Promise<void>;

  // routing rules
  addRoutingRule: (rule: RoutingRule) => Promise<void>;
  updateRoutingRule: (id: string, patch: Partial<RoutingRule>) => Promise<void>;
  removeRoutingRule: (id: string) => Promise<void>;
  reorderRoutingRules: (from: number, to: number) => Promise<void>;
  importRoutingRules: (rules: RoutingRule[], mode: "merge" | "replace") => Promise<void>;

  // asset files
  addAssetFile: (asset: AssetFile) => Promise<void>;
  updateAssetFile: (id: string, patch: Partial<AssetFile>) => Promise<void>;
  removeAssetFile: (id: string) => Promise<void>;
  downloadAsset: (id: string, mode?: ResourceUpdateMode) => Promise<void>;

  // settings
  setSetting: <K extends keyof AdvancedSettings>(k: K, v: AdvancedSettings[K]) => Promise<void>;
  setAppFilterMode: (key: string, mode: "force-proxy" | "bypass" | null) => Promise<void>;

  // backup
  importBackup: (json: string, mode: "merge" | "replace") => Promise<void>;
}

export const useAppStore = create<Store>((set, get) => {
  const activity = new ActivityService();
  const pushActivity = (icon: string, text: string, color?: string) => {
    set({ recentActivity: activity.add(icon, text, color) });
  };
  // Adopt the canonical persisted-state slice the backend returned (the rest of
  // the store — service status, toasts, etc. — is UI-only and left untouched).
  const applyState = (next: AppState) =>
    set({
      profiles: next.profiles,
      groups: next.groups,
      subscriptions: next.subscriptions,
      routingRules: next.routingRules,
      assetFiles: next.assetFiles,
      settings: mergeSettings(next.settings),
      activeId: next.activeId,
      version: next.version ?? __MODULE_VERSION__,
    });
  // The single write path: dispatch one domain intent and render the canonical
  // AppState the backend returns. No local invariant logic, no full-state shipping.
  const mutate = (intent: MutationIntent) => bridge.mutate(intent).then(applyState);
  let lastTrafficSample: { uploadBytes: number; downloadBytes: number; at: number } | null = null;
  // hydrate() can run more than once (tests, dev StrictMode) — register the
  // background watchers a single time.
  let subAppliedWatchStarted = false;
  const syncService = (service: ServiceStatus) => {
    const now = Date.now();
    let uploadRate = 0;
    let downloadRate = 0;

    if (isServiceUp(service.state) && lastTrafficSample) {
      const elapsedSec = Math.max((now - lastTrafficSample.at) / 1000, 0.001);
      const uploadDelta =
        service.uploadBytes >= lastTrafficSample.uploadBytes
          ? service.uploadBytes - lastTrafficSample.uploadBytes
          : 0;
      const downloadDelta =
        service.downloadBytes >= lastTrafficSample.downloadBytes
          ? service.downloadBytes - lastTrafficSample.downloadBytes
          : 0;
      uploadRate = Math.round(uploadDelta / elapsedSec);
      downloadRate = Math.round(downloadDelta / elapsedSec);
    }

    lastTrafficSample = isServiceUp(service.state)
      ? { uploadBytes: service.uploadBytes, downloadBytes: service.downloadBytes, at: now }
      : null;

    set({ service, uploadRate, downloadRate });
  };
  // The daemon fetched & applied a subscription headlessly (it owns the restart
  // decision too) — re-read the persisted state so the UI reflects the new
  // profiles. Safe to overwrite in-memory data: every user mutation writes
  // through immediately, so at most an in-flight edit races this.
  const onDaemonSubApplied = async (info: SubAppliedEvent) => {
    try {
      const state = await bridge.readState();
      set({
        profiles: state.profiles,
        groups: state.groups,
        subscriptions: state.subscriptions,
        routingRules: state.routingRules,
        assetFiles: state.assetFiles,
        settings: mergeSettings(state.settings),
        activeId: state.activeId,
      });
    } catch {
      return;
    }
    pushActivity("cloud_sync", translateCurrent("activity.subUpdated", { name: info.remarks }));
  };
  const waitForUiPaint = () =>
    new Promise<void>((resolve) => {
      if (typeof window !== "undefined" && typeof window.requestAnimationFrame === "function") {
        window.requestAnimationFrame(() => setTimeout(resolve, 0));
        return;
      }
      setTimeout(resolve, 0);
    });
  const showStartingState = async (nextActiveId: string | null) => {
    lastTrafficSample = null;
    set((s) => ({
      busy: true,
      uploadRate: 0,
      downloadRate: 0,
      service: {
        ...s.service,
        state: "connecting",
        activeId: nextActiveId,
      },
    }));
    await waitForUiPaint();
  };

  const stopServiceIfRunning = async (reason?: string) => {
    if (!isServiceUp(get().service.state)) return;
    set({ busy: true });
    try {
      syncService(await bridge.stop());
      if (reason) get().notify(reason);
    } finally {
      set({ busy: false });
      await get().refreshStatus();
    }
  };

  return {
    profiles: [],
    groups: [],
    subscriptions: [],
    routingRules: [],
    assetFiles: [],
    settings: EMPTY_SETTINGS,
    activeId: null,
    hydrated: false,
    busy: false,
    pinging: new Set<string>(),
    speedTesting: new Set<string>(),
    toasts: [],
    recentActivity: [],
    recentProfileIds: [],
    caps: null,
    uploadRate: 0,
    downloadRate: 0,
    service: {
      state: "stopped",
      activeId: null,
      uploadBytes: 0,
      downloadBytes: 0,
      uptimeSec: 0,
      core: "",
      engine: null,
    },

    async hydrate() {
      const state = await bridge.readState();
      const needsMigration = !state.version;
      const subscriptions = needsMigration
        ? state.subscriptions.map((s) => ({ ...s, interval: s.interval * 60 }))
        : state.subscriptions;
      // Base group, legacy default assets and a dangling active_id are normalized by
      // the backend read path now; the frontend just renders what it returns.
      const assetFiles0 = state.assetFiles;
      const settings = mergeSettings(state.settings);
      set({
        ...state,
        subscriptions,
        assetFiles: assetFiles0,
        settings,
        version: __MODULE_VERSION__,
        hydrated: true,
        recentProfileIds: state.activeId ? [state.activeId] : [],
      });
      // Status/caps first — fast and needed for UI responsiveness.
      bridge.onStatus((service) => syncService(service));
      try {
        syncService(await bridge.status());
      } catch {
        /* ignore */
      }
      try {
        set({ caps: await bridge.capabilities() });
      } catch {
        /* ignore */
      }
      // Post-hydrate: verify asset files on disk, write if migration needed.
      let assetFiles = assetFiles0;
      try {
        const onDisk = new Set(await bridge.listAssets());
        assetFiles = assetFiles0.map((a) =>
          a.lastUpdated != null && !onDisk.has(a.remarks) ? { ...a, lastUpdated: null } : a,
        );
      } catch {
        /* ignore */
      }
      if (
        needsMigration ||
        assetFiles.length !== state.assetFiles.length ||
        assetFiles.some((a, i) => a.lastUpdated !== state.assetFiles[i]?.lastUpdated) ||
        settings.routingMode !== state.settings.routingMode
      ) {
        set({ assetFiles });
        // One-time client migration: persist the corrected state wholesale via the
        // bulk replace intent (the only non-granular write path).
        await mutate({
          kind: "replaceState",
          state: { ...state, subscriptions, assetFiles, settings, version: __MODULE_VERSION__ },
        } as unknown as MutationIntent);
      }
      // The daemon fetches & applies subscriptions headlessly; reload the
      // persisted state whenever it pushes a subApplied event.
      if (!subAppliedWatchStarted) {
        subAppliedWatchStarted = true;
        bridge.onSubApplied((info) => void onDaemonSubApplied(info));
      }
    },
    notify(msg) {
      showNativeToast(msg);
      const id = uid();
      set((s) => ({ toasts: [...s.toasts, { id, msg }].slice(-TOAST_LIMIT) }));
      setTimeout(() => {
        get().dismissToast(id);
      }, TOAST_DURATION_MS);
    },
    dismissToast(id) {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    },

    async refreshStatus() {
      try {
        syncService(await bridge.status());
      } catch {
        /* ignore */
      }
    },

    async setActive(id) {
      set((s) => ({
        recentProfileIds: [id, ...s.recentProfileIds.filter((x) => x !== id)].slice(0, 5),
      }));
      await mutate({ kind: "setActive", id });
      if (isServiceUp(get().service.state)) {
        try {
          await showStartingState(id);
          syncService(await bridge.start(id));
          const remarks = get().profiles.find((p) => p.meta.id === id)?.meta.remarks ?? id;
          pushActivity(
            "swap_horiz",
            translateCurrent("activity.profileSwitched", { remarks }),
            "var(--primary)",
          );
          get().notify(translateCurrent("store.service.switched"));
        } catch (e: unknown) {
          get().notify(translateCurrent("store.service.restartFailed", { error: errorMessage(e) }));
        } finally {
          set({ busy: false });
          await get().refreshStatus();
        }
      }
    },
    async toggleService() {
      const { service, activeId } = get();
      try {
        if (isServiceUp(service.state)) {
          set({ busy: true });
          syncService(await bridge.stop());
          pushActivity("stop_circle", translateCurrent("activity.serviceStopped"), "var(--error)");
          get().notify(translateCurrent("store.service.stopped"));
        } else if (activeId) {
          await showStartingState(activeId);
          syncService(await bridge.start(activeId));
          const remarks =
            get().profiles.find((p) => p.meta.id === activeId)?.meta.remarks ?? activeId;
          pushActivity(
            "play_circle",
            translateCurrent("activity.serviceStarted", { remarks }),
            "var(--running)",
          );
          get().notify(translateCurrent("store.service.started"));
        } else {
          get().notify(translateCurrent("store.service.selectActiveFirst"));
        }
      } catch (e: unknown) {
        get().notify(translateCurrent("store.service.error", { error: errorMessage(e) }));
      } finally {
        set({ busy: false });
        await get().refreshStatus();
      }
    },
    async restart() {
      const { activeId } = get();
      try {
        if (activeId) {
          await showStartingState(activeId);
          syncService(await bridge.start(activeId));
        } else {
          await showStartingState(get().service.activeId);
          syncService(await bridge.restart());
        }
        const remarks =
          get().profiles.find((p) => p.meta.id === (activeId ?? get().service.activeId))?.meta
            .remarks ?? "";
        pushActivity(
          "restart_alt",
          translateCurrent("activity.serviceRestarted", { remarks }),
          "var(--warn)",
        );
        get().notify(translateCurrent("store.service.restarted"));
      } catch (e: unknown) {
        get().notify(translateCurrent("store.service.restartFailed", { error: errorMessage(e) }));
      } finally {
        set({ busy: false });
        await get().refreshStatus();
      }
    },

    async upsertProfile(p) {
      await mutate({ kind: "upsertProfile", profile: p });
      pushActivity(
        "edit_note",
        translateCurrent("activity.profileSaved", { remarks: p.meta.remarks }),
      );
    },
    async removeProfile(id) {
      if (get().activeId === id)
        await stopServiceIfRunning(translateCurrent("store.service.stoppedProfileRemoved"));
      await mutate({ kind: "removeProfiles", ids: [id] });
    },
    async removeProfiles(ids) {
      const activeId = get().activeId;
      if (activeId != null && ids.includes(activeId))
        await stopServiceIfRunning(translateCurrent("store.service.stoppedProfileDeleted"));
      await mutate({ kind: "removeProfiles", ids });
    },
    cloneProfile(id) {
      const src = get().profiles.find((p) => p.meta.id === id);
      if (!src) return Promise.resolve();
      return mutate({
        kind: "cloneProfile",
        id,
        newId: uid(),
        remarks: `${src.meta.remarks} (${translateCurrent("store.profile.copySuffix")})`,
      });
    },
    moveProfiles(ids, groupId) {
      return mutate({ kind: "moveProfiles", ids, groupId });
    },
    async addProfiles(profiles) {
      if (!profiles.length) return;
      await mutate({ kind: "addProfiles", profiles });
      pushActivity(
        "download",
        translateCurrent("activity.profileImported", { count: profiles.length }),
      );
      get().notify(translateCurrent("store.profile.imported", { count: profiles.length }));
    },

    async pingProfile(id) {
      if (get().pinging.has(id)) return;
      set((s) => ({ pinging: new Set([...s.pinging, id]) }));
      try {
        const ms = await bridge.ping(id);
        set((s) => ({
          profiles: s.profiles.map((p) =>
            p.meta.id === id ? { ...p, meta: { ...p.meta, ping: ms || null } } : p,
          ),
          pinging: new Set([...s.pinging].filter((x) => x !== id)),
        }));
      } catch {
        set((s) => ({ pinging: new Set([...s.pinging].filter((x) => x !== id)) }));
      }
    },
    async realPingProfile(id) {
      if (get().pinging.has(id)) return;
      set((s) => ({ pinging: new Set([...s.pinging, id]) }));
      try {
        const ms = await bridge.realPing(id);
        set((s) => ({
          profiles: s.profiles.map((p) =>
            p.meta.id === id ? { ...p, meta: { ...p.meta, ping: ms } } : p,
          ),
          pinging: new Set([...s.pinging].filter((x) => x !== id)),
        }));
      } catch (e) {
        // A surfaced error (the probe core couldn't start) is the infra-failure
        // state (-2 → "err"), distinct from an unreachable server (-1 → "✗") which
        // comes back as a normal Ok(None). Tell the user why.
        set((s) => ({
          profiles: s.profiles.map((p) =>
            p.meta.id === id ? { ...p, meta: { ...p.meta, ping: -2 } } : p,
          ),
          pinging: new Set([...s.pinging].filter((x) => x !== id)),
        }));
        get().notify(translateCurrent("store.ping.testFailed", { error: errorMessage(e) }));
      }
    },
    async speedTestProfile(id) {
      if (get().speedTesting.has(id)) return;
      set((s) => ({ speedTesting: new Set([...s.speedTesting, id]) }));
      try {
        const bps = await bridge.speedTest(id);
        set((s) => ({
          profiles: s.profiles.map((p) =>
            p.meta.id === id ? { ...p, meta: { ...p.meta, speed: bps } } : p,
          ),
          speedTesting: new Set([...s.speedTesting].filter((x) => x !== id)),
        }));
      } catch (e) {
        set((s) => ({
          profiles: s.profiles.map((p) =>
            p.meta.id === id ? { ...p, meta: { ...p.meta, speed: -2 } } : p,
          ),
          speedTesting: new Set([...s.speedTesting].filter((x) => x !== id)),
        }));
        get().notify(translateCurrent("store.ping.testFailed", { error: errorMessage(e) }));
      }
    },
    // Batch tests run their concurrency + port allocation inside the bridge
    // (so the on-demand test cores never collide on a SOCKS port — see
    // ws-bridge realPingAll). The bridge streams each profile's result back
    // via the callback the moment it resolves, so we update that one profile
    // and clear its spinner progressively instead of waiting for the whole run.
    async pingAll(groupId?: string) {
      if (get().pinging.size) return;
      const ids = get()
        .profiles.filter((p) => !groupId || groupId === "all" || p.meta.groupId === groupId)
        .map((p) => p.meta.id);
      if (!ids.length) return;
      get().notify(translateCurrent("store.ping.started"));
      set({ pinging: new Set(ids) });
      try {
        await bridge.pingAll(ids, (id, ms) => {
          set((s) => ({
            profiles: s.profiles.map((p) =>
              p.meta.id === id ? { ...p, meta: { ...p.meta, ping: ms || null } } : p,
            ),
            pinging: new Set([...s.pinging].filter((x) => x !== id)),
          }));
        });
      } finally {
        set({ pinging: new Set() });
      }
      get().notify(translateCurrent("store.ping.complete"));
      pushActivity("speed", translateCurrent("activity.pingComplete", { count: ids.length }));
    },

    async realPingAll(groupId?: string) {
      if (get().pinging.size) return;
      const ids = get()
        .profiles.filter((p) => !groupId || groupId === "all" || p.meta.groupId === groupId)
        .map((p) => p.meta.id);
      if (!ids.length) return;
      get().notify(translateCurrent("store.ping.started"));
      set({ pinging: new Set(ids) });
      try {
        await bridge.realPingAll(ids, (id, ms) => {
          set((s) => ({
            profiles: s.profiles.map((p) =>
              p.meta.id === id ? { ...p, meta: { ...p.meta, ping: ms } } : p,
            ),
            pinging: new Set([...s.pinging].filter((x) => x !== id)),
          }));
        });
      } finally {
        set({ pinging: new Set() });
      }
      get().notify(translateCurrent("store.ping.complete"));
      pushActivity("speed", translateCurrent("activity.pingComplete", { count: ids.length }));
    },

    async speedTestAll(groupId?: string) {
      if (get().speedTesting.size) return;
      const ids = get()
        .profiles.filter((p) => !groupId || groupId === "all" || p.meta.groupId === groupId)
        .map((p) => p.meta.id);
      if (!ids.length) return;
      get().notify(translateCurrent("store.ping.started"));
      set({ speedTesting: new Set(ids) });
      try {
        await bridge.speedTestAll(ids, (id, bps) => {
          set((s) => ({
            profiles: s.profiles.map((p) =>
              p.meta.id === id ? { ...p, meta: { ...p.meta, speed: bps } } : p,
            ),
            speedTesting: new Set([...s.speedTesting].filter((x) => x !== id)),
          }));
        });
      } finally {
        set({ speedTesting: new Set() });
      }
      get().notify(translateCurrent("store.ping.complete"));
      pushActivity("speed", translateCurrent("activity.speedTestComplete", { count: ids.length }));
    },

    async removeUnreachable(groupId?: string) {
      const { profiles, activeId } = get();
      const affected =
        !groupId || groupId === "all"
          ? profiles
          : profiles.filter((p) => p.meta.groupId === groupId);
      const unreachable = new Set(affected.filter((p) => p.meta.ping === -1).map((p) => p.meta.id));
      if (!unreachable.size) {
        get().notify(translateCurrent("store.ping.noUnreachable"));
        return;
      }
      if (activeId != null && unreachable.has(activeId))
        await stopServiceIfRunning(translateCurrent("store.service.stoppedProfileRemoved"));
      await mutate({ kind: "removeUnreachable", groupId: groupId ?? null });
      pushActivity(
        "delete_sweep",
        translateCurrent("activity.unreachableRemoved", { count: unreachable.size }),
        "var(--error)",
      );
      get().notify(translateCurrent("store.ping.removeUnreachable", { count: unreachable.size }));
    },

    async selectBest(groupId?: string) {
      const { profiles } = get();
      const candidates =
        !groupId || groupId === "all"
          ? profiles
          : profiles.filter((p) => p.meta.groupId === groupId);
      const best = candidates
        .filter((p) => p.meta.ping != null && p.meta.ping > 0)
        .sort((a, b) => (a.meta.ping ?? Infinity) - (b.meta.ping ?? Infinity))[0];
      if (!best) {
        get().notify(translateCurrent("store.ping.noPingData"));
        return;
      }
      const done = get().setActive(best.meta.id);
      pushActivity(
        "stars",
        translateCurrent("activity.bestSelected", { remarks: best.meta.remarks }),
        "var(--primary)",
      );
      get().notify(translateCurrent("store.ping.selectBest"));
      await done;
    },

    async removeDuplicates(groupId?: string) {
      const { profiles, activeId } = get();
      const before = profiles.length;
      // Dedup runs server-side and always keeps the active profile, so the running
      // data-path is never affected.
      await mutate({ kind: "deduplicateProfiles", activeId, groupId: groupId ?? null });
      const removed = before - get().profiles.length;
      if (!removed) {
        get().notify(translateCurrent("store.dedup.none"));
        return;
      }
      pushActivity(
        "content_cut",
        translateCurrent("activity.duplicatesRemoved", { count: removed }),
      );
      get().notify(translateCurrent("store.dedup.done", { count: removed }));
    },

    async addGroup(name) {
      const id = uid();
      await mutate({ kind: "addGroup", id, name });
      return id;
    },
    renameGroup(id, name) {
      return mutate({ kind: "renameGroup", id, name });
    },
    reorderGroups(from, to) {
      return mutate({ kind: "reorderGroups", from, to });
    },
    async removeGroup(id) {
      if (id === "g-main") return;
      const { profiles, activeId } = get();
      const activeProfile = profiles.find((p) => p.meta.id === activeId);
      // The group holding the active profile is protected from deletion.
      if (activeProfile?.meta.groupId === id) return;
      await mutate({ kind: "removeGroup", id });
    },

    async upsertSub(sub) {
      // The daemon's auto-update loop re-reads state every tick, so a new or
      // edited subscription is picked up within a minute — no wakeup needed.
      await mutate({ kind: "upsertSub", subscription: sub });
    },
    async removeSub(id) {
      const { profiles, activeId } = get();
      const activeProfile = profiles.find((p) => p.meta.id === activeId);
      if (activeProfile?.meta.subId === id)
        await stopServiceIfRunning(translateCurrent("store.service.stoppedSubRemoved"));
      await mutate({ kind: "removeSub", id });
    },
    async updateSub(id) {
      const { subscriptions, service } = get();
      const sub = subscriptions.find((x) => x.id === id);
      if (!sub) return;

      // "proxy" mode can only fetch through a live core — guard it client-side so
      // the failure is explained up front rather than as a fetch timeout (the
      // backend can't tell a stopped proxy from an unreachable URL).
      if (sub.updateMode === "proxy" && !isServiceUp(service.state)) {
        await mutate({
          kind: "upsertSub",
          subscription: { ...sub, lastError: translateCurrent("common.proxyNotRunning") },
        });
        get().notify(translateCurrent("common.proxyNotRunning"));
        return;
      }

      get().notify(translateCurrent("store.sub.updating", { name: sub.remarks }));
      let next: AppState;
      try {
        // The backend fetches, maps, dedups, applies, persists, and restarts the
        // active data-path when affected; we just reflect the result.
        next = await bridge.applySubscription(id);
      } catch (e: unknown) {
        await mutate({ kind: "upsertSub", subscription: { ...sub, lastError: errorMessage(e) } });
        get().notify(translateCurrent("store.sub.updateFailed", { name: sub.remarks }));
        return;
      }

      applyState(next);
      await get().refreshStatus();

      const updated = next.subscriptions.find((x) => x.id === id);
      if (updated?.lastError) {
        get().notify(translateCurrent("store.sub.updateFailed", { name: sub.remarks }));
        return;
      }
      get().notify(
        translateCurrent("store.sub.updatedProfiles", {
          count: updated?.count ?? 0,
          name: sub.remarks,
        }),
      );
      pushActivity("cloud_sync", translateCurrent("activity.subUpdated", { name: sub.remarks }));
    },
    async updateAllSubs() {
      for (const sub of get().subscriptions.filter((s) => s.enabled)) {
        await get().updateSub(sub.id);
      }
    },

    addRoutingRule(rule) {
      return mutate({ kind: "upsertRoutingRule", rule });
    },
    updateRoutingRule(id, rulePatch) {
      const rule = get().routingRules.find((r) => r.id === id);
      if (!rule) return Promise.resolve();
      return mutate({ kind: "upsertRoutingRule", rule: { ...rule, ...rulePatch } });
    },
    removeRoutingRule(id) {
      return mutate({ kind: "removeRoutingRule", id });
    },
    reorderRoutingRules(from, to) {
      return mutate({ kind: "reorderRoutingRules", from, to });
    },
    importRoutingRules(rules, mode) {
      // Re-id imported rules so they never collide with existing ones.
      const incoming = rules.map((rule) => ({ ...rule, id: uid() }));
      return mutate({ kind: "importRoutingRules", rules: incoming, mode });
    },

    addAssetFile(asset) {
      return mutate({ kind: "upsertAssetFile", asset });
    },
    updateAssetFile(id, assetPatch) {
      const asset = get().assetFiles.find((a) => a.id === id);
      if (!asset) return Promise.resolve();
      return mutate({ kind: "upsertAssetFile", asset: { ...asset, ...assetPatch } });
    },
    removeAssetFile(id) {
      return mutate({ kind: "removeAssetFile", id });
    },
    async downloadAsset(id, mode = "auto") {
      const asset = get().assetFiles.find((item) => item.id === id);
      if (!asset) return;
      const result = await bridge.downloadAsset(asset.remarks, asset.url, mode);
      if (!result.ok) {
        get().notify(
          result.error
            ? translateCurrent("store.asset.downloadFailedReason", {
                mode,
                name: asset.remarks,
                reason: result.error,
              })
            : translateCurrent("store.asset.downloadFailed", { mode, name: asset.remarks }),
        );
        return;
      }
      await mutate({
        kind: "upsertAssetFile",
        asset: { ...asset, lastUpdated: Date.now() },
      });
      pushActivity(
        "file_download_done",
        translateCurrent("activity.assetDownloaded", { name: asset.remarks }),
      );
      get().notify(translateCurrent("store.asset.updated", { mode, name: asset.remarks }));
    },

    setSetting(k, v) {
      return mutate({ kind: "setSettings", settings: { ...get().settings, [k]: v } });
    },

    setAppFilterMode(key, mode) {
      const appFilter = { ...(get().settings.appFilter ?? {}) };
      if (mode === null) delete appFilter[key];
      else appFilter[key] = mode;
      return mutate({ kind: "setSettings", settings: { ...get().settings, appFilter } });
    },

    async importBackup(json, mode) {
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(json);
      } catch {
        get().notify(translateCurrent("store.backup.invalidJson"));
        return;
      }
      const { AppStateSchema } = await import("../generated/schemas");
      const parsed = AppStateSchema.safeParse(parsedJson);
      if (!parsed.success) {
        get().notify(translateCurrent("store.backup.invalidStructure"));
        return;
      }
      const incoming = parsed.data as unknown as AppState;
      // AppStateSchema silently drops invalid profiles (logged with reasons via
      // console.warn). Surface how many were skipped so a partial import is visible.
      const rawProfiles = (parsedJson as { profiles?: unknown }).profiles;
      const skipped = Array.isArray(rawProfiles)
        ? rawProfiles.length - incoming.profiles.length
        : 0;
      if (mode === "replace" && isServiceUp(get().service.state)) {
        await stopServiceIfRunning(translateCurrent("store.service.stoppedBeforeBackupRestore"));
      }
      // `incoming` is a Zod-parsed AppState; it carries schemaVersion at runtime
      // even though the UI's AppState type omits it (the backend owns it).
      await mutate({ kind: "importBackup", incoming, mode } as unknown as MutationIntent);
      pushActivity("backup", translateCurrent("activity.backupRestored"));
      get().notify(
        skipped > 0
          ? translateCurrent("store.backup.profilesSkipped", { count: skipped })
          : translateCurrent(mode === "replace" ? "store.backup.restored" : "store.backup.merged"),
      );
    },
  };
});

export type StoreProfile = Profile & { subId: string | null };
