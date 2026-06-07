// ============================================================
// src/store/useAppStore.ts
// Zustand store — the single in-memory source the UI reads from.
// It hydrates from the bridge (app-state.json on device, mock in
// dev) and writes through on every mutation (debounced).
// ============================================================
import { create } from "zustand";
import { translateCurrent } from "../i18n";
import type {
  AdvancedSettings,
  AppState,
  Capabilities,
  ResourceUpdateMode,
  ServiceStatus,
  Subscription,
} from "../lib/bridge";
import { bridge } from "../lib/bridge-provider";
import { showNativeToast } from "../lib/ksu-webui";
import type { AssetFile, Profile, RoutingRule } from "../lib/schema";
import { uid } from "../lib/utils";
import type { ActivityEvent } from "./activity";
import { ActivityService } from "./activity";
import { EMPTY_SETTINGS, mergeSettings } from "./defaults";
import { errorMessage } from "./errors";
import { profileFilterRegex } from "./profile-filter";
import {
  activeIdAfterProfileRemoval,
  activeIdAfterSubRemoval,
  deduplicateProfiles,
  insertAfterId,
  mapFetchedSubscriptionProfiles,
  mergeBackupState,
  moveItemByIndex,
  moveProfilesToGroup,
  nextActiveIdAfterSubscriptionUpdate,
  removeProfilesByIds,
  removeProfilesBySubId,
  upsertById,
} from "./state-mutations";

const LEGACY_DEFAULT_ASSET_IDS = new Set(["asset-geoip", "asset-geosite"]);

function stripLegacyDefaultAssets(assetFiles: AssetFile[]): AssetFile[] {
  return assetFiles.filter((asset) => !(asset.locked && LEGACY_DEFAULT_ASSET_IDS.has(asset.id)));
}

interface Store extends AppState {
  service: ServiceStatus;
  uploadRate: number;
  downloadRate: number;
  caps: Capabilities | null;
  hydrated: boolean;
  busy: boolean; // true while a service lifecycle op is in flight
  pinging: Set<string>; // profile ids currently being pinged
  speedTesting: Set<string>; // profile ids currently being speed-tested
  toast: string | null;
  recentActivity: ActivityEvent[];

  hydrate: () => Promise<void>;
  flush: () => Promise<void>;
  notify: (msg: string) => void;

  // service
  setActive: (id: string) => Promise<void>;
  toggleService: () => Promise<void>;
  restart: () => Promise<void>;
  refreshStatus: () => Promise<void>;

  // profiles
  upsertProfile: (p: Profile) => void;
  removeProfile: (id: string) => Promise<void>;
  removeProfiles: (ids: string[]) => Promise<void>;
  cloneProfile: (id: string) => void;
  moveProfiles: (ids: string[], groupId: string) => void;
  addProfiles: (profiles: Profile[]) => void;
  pingProfile: (id: string) => Promise<void>;
  realPingProfile: (id: string) => Promise<void>;
  speedTestProfile: (id: string) => Promise<void>;
  pingAll: () => Promise<void>;
  realPingAll: () => Promise<void>;
  speedTestAll: () => Promise<void>;
  removeUnreachable: () => Promise<void>;
  removeDuplicates: () => void;
  selectBest: () => void;

  // groups
  addGroup: (name: string) => void;
  removeGroup: (id: string) => void;

  // subscriptions
  upsertSub: (s: Subscription) => void;
  removeSub: (id: string) => Promise<void>;
  updateSub: (id: string) => Promise<void>;
  updateAllSubs: () => Promise<void>;

  // routing rules
  addRoutingRule: (rule: RoutingRule) => void;
  updateRoutingRule: (id: string, patch: Partial<RoutingRule>) => void;
  removeRoutingRule: (id: string) => void;
  reorderRoutingRules: (from: number, to: number) => void;
  importRoutingRules: (rules: RoutingRule[], mode: "merge" | "replace") => void;

  // asset files
  addAssetFile: (asset: AssetFile) => void;
  updateAssetFile: (id: string, patch: Partial<AssetFile>) => void;
  removeAssetFile: (id: string) => void;
  downloadAsset: (id: string, mode?: ResourceUpdateMode) => Promise<void>;

  // settings
  setSetting: <K extends keyof AdvancedSettings>(k: K, v: AdvancedSettings[K]) => void;
  setAppFilterMode: (key: string, mode: "force-proxy" | "bypass" | null) => void;

  // backup
  importBackup: (json: string, mode: "merge" | "replace") => Promise<void>;
}

export const useAppStore = create<Store>((set, get) => {
  const activity = new ActivityService();
  const pushActivity = (icon: string, text: string, color?: string) => {
    set({ recentActivity: activity.add(icon, text, color) });
  };
  let t: ReturnType<typeof setTimeout> | null = null;
  const persist = () => {
    if (t) clearTimeout(t);
    t = setTimeout(() => get().flush(), 400);
  };
  const patch = (fn: (s: Store) => Partial<Store>) => {
    set(fn);
    persist();
  };
  let lastTrafficSample: { uploadBytes: number; downloadBytes: number; at: number } | null = null;
  const syncService = (service: ServiceStatus) => {
    const now = Date.now();
    let uploadRate = 0;
    let downloadRate = 0;

    if (service.state === "running" && lastTrafficSample) {
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

    lastTrafficSample =
      service.state === "running"
        ? { uploadBytes: service.uploadBytes, downloadBytes: service.downloadBytes, at: now }
        : null;

    set({ service, uploadRate, downloadRate });
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
    if (get().service.state !== "running") return;
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
    toast: null,
    recentActivity: [],
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
    },

    async hydrate() {
      const state = await bridge.readState();
      let assetFiles = stripLegacyDefaultAssets(state.assetFiles);
      const settings = mergeSettings(state.settings);
      try {
        const onDisk = new Set(await bridge.listAssets());
        assetFiles = assetFiles.map((a) =>
          a.lastUpdated != null && !onDisk.has(a.remarks) ? { ...a, lastUpdated: null } : a,
        );
      } catch {
        /* ignore */
      }
      if (
        assetFiles.length !== state.assetFiles.length ||
        assetFiles.some((a, i) => a.lastUpdated !== state.assetFiles[i]?.lastUpdated) ||
        settings.routingMode !== state.settings.routingMode
      ) {
        await bridge.writeState({ ...state, assetFiles, settings });
      }
      set({ ...state, assetFiles, settings, hydrated: true });
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
    },
    async flush() {
      const { profiles, groups, subscriptions, routingRules, assetFiles, settings, activeId } =
        get();
      await bridge.writeState({
        profiles,
        groups,
        subscriptions,
        routingRules,
        assetFiles,
        settings,
        activeId,
      });
    },
    notify(msg) {
      showNativeToast(msg);
      set({ toast: msg });
      setTimeout(() => {
        if (get().toast === msg) set({ toast: null });
      }, 2600);
    },

    async refreshStatus() {
      try {
        syncService(await bridge.status());
      } catch {
        /* ignore */
      }
    },

    async setActive(id) {
      set({ activeId: id });
      await get().flush();
      if (get().service.state === "running") {
        try {
          await showStartingState(id);
          syncService(await bridge.start(id));
          const remarks = get().profiles.find((p) => p.id === id)?.remarks ?? id;
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
        if (service.state === "running") {
          set({ busy: true });
          syncService(await bridge.stop());
          pushActivity("stop_circle", translateCurrent("activity.serviceStopped"), "var(--error)");
          get().notify(translateCurrent("store.service.stopped"));
        } else if (activeId) {
          await get().flush();
          await showStartingState(activeId);
          syncService(await bridge.start(activeId));
          const remarks = get().profiles.find((p) => p.id === activeId)?.remarks ?? activeId;
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
          await get().flush();
          await showStartingState(activeId);
          syncService(await bridge.start(activeId));
        } else {
          await showStartingState(get().service.activeId);
          syncService(await bridge.restart());
        }
        const remarks =
          get().profiles.find((p) => p.id === (activeId ?? get().service.activeId))?.remarks ?? "";
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

    upsertProfile(p) {
      patch((s) => ({ profiles: upsertById(s.profiles, p, "front") }));
    },
    async removeProfile(id) {
      const wasActive = get().activeId === id;
      if (wasActive)
        await stopServiceIfRunning(translateCurrent("store.service.stoppedProfileRemoved"));
      set((s) => ({
        profiles: removeProfilesByIds(s.profiles, new Set([id])),
        activeId: activeIdAfterProfileRemoval(s.activeId, new Set([id])),
      }));
      await get().flush();
    },
    async removeProfiles(ids) {
      const removed = new Set(ids);
      const activeId = get().activeId;
      const removingActive = activeId != null && removed.has(activeId);
      if (removingActive)
        await stopServiceIfRunning(translateCurrent("store.service.stoppedProfileDeleted"));
      set((s) => ({
        profiles: removeProfilesByIds(s.profiles, removed),
        activeId: activeIdAfterProfileRemoval(s.activeId, removed),
      }));
      await get().flush();
    },
    cloneProfile(id) {
      patch((s) => {
        const src = s.profiles.find((p) => p.id === id);
        if (!src) return {};
        const copy: Profile = { ...src, id: uid(), remarks: `${src.remarks} (copy)`, subId: null };
        return { profiles: insertAfterId(s.profiles, id, copy) };
      });
    },
    moveProfiles(ids, groupId) {
      patch((s) => ({ profiles: moveProfilesToGroup(s.profiles, ids, groupId) }));
    },
    addProfiles(profiles) {
      if (!profiles.length) return;
      patch((s) => ({ profiles: [...profiles, ...s.profiles] }));
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
          profiles: s.profiles.map((p) => (p.id === id ? { ...p, ping: ms || null } : p)),
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
          profiles: s.profiles.map((p) => (p.id === id ? { ...p, ping: ms } : p)),
          pinging: new Set([...s.pinging].filter((x) => x !== id)),
        }));
      } catch {
        set((s) => ({ pinging: new Set([...s.pinging].filter((x) => x !== id)) }));
      }
    },
    async speedTestProfile(id) {
      if (get().speedTesting.has(id)) return;
      set((s) => ({ speedTesting: new Set([...s.speedTesting, id]) }));
      try {
        const bps = await bridge.speedTest(id);
        set((s) => ({
          profiles: s.profiles.map((p) => (p.id === id ? { ...p, speed: bps } : p)),
          speedTesting: new Set([...s.speedTesting].filter((x) => x !== id)),
        }));
      } catch {
        set((s) => ({ speedTesting: new Set([...s.speedTesting].filter((x) => x !== id)) }));
      }
    },
    async pingAll() {
      if (get().pinging.size) return;
      get().notify(translateCurrent("store.ping.started"));
      const ids = get().profiles.map((p) => p.id);
      set({ pinging: new Set(ids) });
      try {
        const result = await bridge.pingAll();
        set((s) => ({
          profiles: s.profiles.map((p) => ({ ...p, ping: result[p.id] ?? p.ping })),
          pinging: new Set(),
        }));
      } catch {
        set({ pinging: new Set() });
      }
      get().notify(translateCurrent("store.ping.complete"));
      pushActivity(
        "speed",
        translateCurrent("activity.pingComplete", { count: get().profiles.length }),
      );
    },

    async realPingAll() {
      if (get().pinging.size) return;
      get().notify(translateCurrent("store.ping.started"));
      const ids = get().profiles.map((p) => p.id);
      set({ pinging: new Set(ids) });
      try {
        const result = await bridge.realPingAll();
        set((s) => ({
          profiles: s.profiles.map((p) => ({ ...p, ping: result[p.id] ?? p.ping })),
          pinging: new Set(),
        }));
      } catch {
        set({ pinging: new Set() });
      }
      get().notify(translateCurrent("store.ping.complete"));
      pushActivity(
        "speed",
        translateCurrent("activity.pingComplete", { count: get().profiles.length }),
      );
    },

    async speedTestAll() {
      if (get().speedTesting.size) return;
      get().notify(translateCurrent("store.ping.started"));
      const ids = get().profiles.map((p) => p.id);
      set({ speedTesting: new Set(ids) });
      try {
        const result = await bridge.speedTestAll();
        set((s) => ({
          profiles: s.profiles.map((p) => ({ ...p, speed: result[p.id] ?? p.speed })),
          speedTesting: new Set(),
        }));
      } catch {
        set({ speedTesting: new Set() });
      }
      get().notify(translateCurrent("store.ping.complete"));
      pushActivity(
        "speed",
        translateCurrent("activity.speedTestComplete", { count: get().profiles.length }),
      );
    },

    async removeUnreachable() {
      const { profiles, activeId } = get();
      const unreachable = new Set(profiles.filter((p) => p.ping === -1).map((p) => p.id));
      if (!unreachable.size) {
        get().notify(translateCurrent("store.ping.noUnreachable"));
        return;
      }
      const removingActive = activeId != null && unreachable.has(activeId);
      if (removingActive)
        await stopServiceIfRunning(translateCurrent("store.service.stoppedProfileRemoved"));
      set((s) => ({
        profiles: removeProfilesByIds(s.profiles, unreachable),
        activeId: activeIdAfterProfileRemoval(s.activeId, unreachable),
      }));
      await get().flush();
      pushActivity(
        "delete_sweep",
        translateCurrent("activity.unreachableRemoved", { count: unreachable.size }),
        "var(--error)",
      );
      get().notify(translateCurrent("store.ping.removeUnreachable", { count: unreachable.size }));
    },

    selectBest() {
      const { profiles } = get();
      const best = profiles
        .filter((p) => p.ping != null && p.ping > 0)
        .sort((a, b) => (a.ping ?? Infinity) - (b.ping ?? Infinity))[0];
      if (!best) {
        get().notify(translateCurrent("store.ping.noPingData"));
        return;
      }
      void get().setActive(best.id);
      pushActivity(
        "stars",
        translateCurrent("activity.bestSelected", { remarks: best.remarks }),
        "var(--primary)",
      );
      get().notify(translateCurrent("store.ping.selectBest"));
    },

    removeDuplicates() {
      const { profiles, activeId } = get();
      const { kept, removedCount } = deduplicateProfiles(profiles, activeId);
      if (!removedCount) {
        get().notify(translateCurrent("store.dedup.none"));
        return;
      }
      patch(() => ({ profiles: kept }));
      pushActivity(
        "content_cut",
        translateCurrent("activity.duplicatesRemoved", { count: removedCount }),
      );
      get().notify(translateCurrent("store.dedup.done", { count: removedCount }));
    },

    addGroup(name) {
      patch((s) => ({ groups: [...s.groups, { id: uid(), name }] }));
    },
    removeGroup(id) {
      patch((s) => ({
        groups: s.groups.filter((g) => g.id !== id),
        profiles: s.profiles.map((p) => (p.groupId === id ? { ...p, groupId: "g-main" } : p)),
      }));
    },

    upsertSub(sub) {
      patch((s) => ({ subscriptions: upsertById(s.subscriptions, sub) }));
    },
    async removeSub(id) {
      const activeProfile = get().profiles.find((p) => p.id === get().activeId);
      if (activeProfile?.subId === id)
        await stopServiceIfRunning(translateCurrent("store.service.stoppedSubRemoved"));
      set((s) => ({
        subscriptions: s.subscriptions.filter((x) => x.id !== id),
        profiles: removeProfilesBySubId(s.profiles, id),
        activeId: activeIdAfterSubRemoval(s.profiles, s.activeId, id),
      }));
      await get().flush();
    },
    async updateSub(id) {
      const current = get();
      const sub = current.subscriptions.find((x) => x.id === id);
      if (!sub) return;
      if (!sub.url.trim()) {
        patch((s) => ({
          subscriptions: s.subscriptions.map((x) =>
            x.id === id ? { ...x, lastError: translateCurrent("store.sub.urlRequired") } : x,
          ),
        }));
        get().notify(translateCurrent("store.sub.updateFailed", { name: sub.remarks }));
        return;
      }

      const filter = profileFilterRegex(sub.filter);
      if (sub.filter.trim() && !filter) {
        patch((s) => ({
          subscriptions: s.subscriptions.map((x) =>
            x.id === id ? { ...x, lastError: translateCurrent("store.sub.invalidFilter") } : x,
          ),
        }));
        get().notify(translateCurrent("store.sub.invalidFilterNotify", { name: sub.remarks }));
        return;
      }

      get().notify(translateCurrent("store.sub.updating", { name: sub.remarks }));
      try {
        const freshRaw = await bridge.fetchSubscription(sub.url, {
          userAgent: sub.userAgent,
          allowInsecure: sub.allowInsecure,
        });
        const freshMapped = mapFetchedSubscriptionProfiles(freshRaw, sub, filter);
        const nextActiveId = nextActiveIdAfterSubscriptionUpdate(current, id, freshMapped);
        const activeAffected =
          current.profiles.find((p) => p.id === current.activeId)?.subId === id;

        set((s) => ({
          profiles: [...removeProfilesBySubId(s.profiles, id), ...freshMapped],
          subscriptions: s.subscriptions.map((x) =>
            x.id === id
              ? {
                  ...x,
                  lastUpdated: new Date().toISOString(),
                  count: freshMapped.length,
                  lastError: null,
                }
              : x,
          ),
          activeId: nextActiveId,
        }));
        await get().flush();

        if (activeAffected && current.service.state === "running") {
          set({ busy: true });
          try {
            if (nextActiveId) {
              syncService(await bridge.start(nextActiveId));
              get().notify(
                translateCurrent("store.sub.updatedProfilesRemapped", {
                  count: freshMapped.length,
                  name: sub.remarks,
                }),
              );
            } else {
              syncService(await bridge.stop());
              get().notify(
                translateCurrent("store.sub.updatedProfilesRemoved", {
                  count: freshMapped.length,
                  name: sub.remarks,
                }),
              );
            }
          } finally {
            set({ busy: false });
            await get().refreshStatus();
          }
        } else {
          get().notify(
            translateCurrent("store.sub.updatedProfiles", {
              count: freshMapped.length,
              name: sub.remarks,
            }),
          );
        }
        pushActivity("cloud_sync", translateCurrent("activity.subUpdated", { name: sub.remarks }));
      } catch (e: unknown) {
        patch((s) => ({
          subscriptions: s.subscriptions.map((x) =>
            x.id === id ? { ...x, lastError: errorMessage(e) } : x,
          ),
        }));
        get().notify(translateCurrent("store.sub.updateFailed", { name: sub.remarks }));
      }
    },
    async updateAllSubs() {
      for (const sub of get().subscriptions.filter((s) => s.enabled)) {
        await get().updateSub(sub.id);
      }
    },

    addRoutingRule(rule) {
      patch((s) => ({ routingRules: upsertById(s.routingRules, rule) }));
    },
    updateRoutingRule(id, rulePatch) {
      patch((s) => ({
        routingRules: s.routingRules.map((rule) =>
          rule.id === id ? { ...rule, ...rulePatch } : rule,
        ),
      }));
    },
    removeRoutingRule(id) {
      patch((s) => ({ routingRules: s.routingRules.filter((rule) => rule.id !== id) }));
    },
    reorderRoutingRules(from, to) {
      patch((s) => ({ routingRules: moveItemByIndex(s.routingRules, from, to) }));
    },
    importRoutingRules(rules, mode) {
      // Re-id imported rules so they never collide with existing ones.
      const incoming = rules.map((rule) => ({ ...rule, id: uid() }));
      patch((s) => ({
        routingRules: mode === "replace" ? incoming : [...s.routingRules, ...incoming],
      }));
    },

    addAssetFile(asset) {
      patch((s) => ({ assetFiles: upsertById(s.assetFiles, asset) }));
    },
    updateAssetFile(id, assetPatch) {
      patch((s) => ({
        assetFiles: s.assetFiles.map((asset) =>
          asset.id === id ? { ...asset, ...assetPatch } : asset,
        ),
      }));
    },
    removeAssetFile(id) {
      patch((s) => ({
        assetFiles: s.assetFiles.filter((asset) => asset.id !== id),
      }));
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
      patch((s) => ({
        assetFiles: s.assetFiles.map((item) =>
          item.id === id ? { ...item, lastUpdated: Date.now() } : item,
        ),
      }));
      pushActivity(
        "file_download_done",
        translateCurrent("activity.assetDownloaded", { name: asset.remarks }),
      );
      get().notify(translateCurrent("store.asset.updated", { mode, name: asset.remarks }));
    },

    setSetting(k, v) {
      patch((s) => ({
        settings: { ...s.settings, [k]: v },
      }));
    },

    setAppFilterMode(key, mode) {
      // Functional update reads the latest appFilter inside the setter, so
      // rapid toggles never overwrite each other via a stale closure.
      patch((s) => {
        const next = { ...(s.settings.appFilter ?? {}) };
        if (mode === null) delete next[key];
        else next[key] = mode;
        return {
          settings: { ...s.settings, appFilter: next },
        };
      });
    },

    async importBackup(json, mode) {
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(json);
      } catch {
        get().notify(translateCurrent("store.backup.invalidJson"));
        return;
      }
      const { AppStateSchema } = await import("../lib/schema/settings");
      const parsed = AppStateSchema.safeParse(parsedJson);
      if (!parsed.success) {
        get().notify(translateCurrent("store.backup.invalidStructure"));
        return;
      }
      const incoming: AppState = parsed.data;
      if (mode === "replace" && get().service.state === "running") {
        await stopServiceIfRunning(translateCurrent("store.service.stoppedBeforeBackupRestore"));
      }
      patch((s) => mergeBackupState(s, incoming, mode));
      await get().flush();
      pushActivity("backup", translateCurrent("activity.backupRestored"));
      get().notify(
        translateCurrent(mode === "replace" ? "store.backup.restored" : "store.backup.merged"),
      );
    },
  };
});

export type StoreProfile = Profile & { subId: string | null };
