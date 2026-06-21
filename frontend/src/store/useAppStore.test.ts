import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AssetFile, Profile } from "../generated/bindings";
import type {
  AdvancedSettings,
  AppState,
  Bridge,
  LogTarget,
  ServiceStatus,
  SubAppliedEvent,
  Subscription,
} from "../lib/bridge";
import { emptyProfile } from "../lib/profile-utils";

type Vless = Extract<Profile, { protocol: "vless" }>;
type UseAppStoreModule = typeof import("./useAppStore");
type BridgeMock = {
  [K in keyof Bridge]: ReturnType<typeof vi.fn<Bridge[K]>>;
};

import { uid } from "../lib/utils";
import { EMPTY_SETTINGS } from "./defaults";

const DEFAULT_SETTINGS: AdvancedSettings = {
  ...EMPTY_SETTINGS,
  autoStart: false,
};

const DEFAULT_STATUS: ServiceStatus = {
  state: "stopped",
  activeId: null,
  uploadBytes: 0,
  downloadBytes: 0,
  uptimeSec: 0,
  core: "Xray",
  engine: null,
};

// Nested-model builder: Vless is `meta`/`endpoint`/`transport`/`tls`/ root
// fields. Built from `emptyProfile("vless")` so every serde default is present;
// overrides accept any of those groups plus root credentials. `meta` is
// `Partial<Meta>` so a test can stub just `id`.
type VlessOverrides = Omit<Partial<Vless>, "meta" | "endpoint" | "transport" | "tls"> & {
  meta?: Partial<Vless["meta"]>;
  endpoint?: Partial<Vless["endpoint"]>;
  transport?: Vless["transport"];
  tls?: Partial<NonNullable<Vless["tls"]>>;
};
function makeVless(overrides: VlessOverrides = {}): Vless {
  const base = emptyProfile("vless") as Vless;
  return {
    ...base,
    ...overrides,
    meta: {
      ...base.meta,
      ...(overrides.meta ?? {}),
      id: overrides.meta?.id ?? uid(),
      remarks: overrides.meta?.remarks ?? "Node",
      groupId: overrides.meta?.groupId ?? "g-main",
      subId: overrides.meta?.subId ?? null,
      ping: overrides.meta?.ping ?? null,
    },
    endpoint: { ...base.endpoint, ...overrides.endpoint },
    transport: overrides.transport ?? base.transport,
    tls: overrides.tls ? { ...base.tls, ...overrides.tls } : base.tls,
  };
}

function makeSub(overrides: Partial<Subscription> = {}): Subscription {
  return {
    id: overrides.id ?? "s1",
    remarks: overrides.remarks ?? "Sub",
    url: overrides.url ?? "https://example.com/sub",
    enabled: overrides.enabled ?? true,
    groupId: overrides.groupId ?? "g-main",
    autoUpdate: overrides.autoUpdate ?? false,
    interval: overrides.interval ?? 6,
    allowInsecure: overrides.allowInsecure ?? false,
    userAgent: overrides.userAgent ?? "",
    filter: overrides.filter ?? "",
    updateMode: overrides.updateMode ?? "auto",
    lastUpdated: overrides.lastUpdated ?? "",
    count: overrides.count ?? 0,
    lastError: overrides.lastError ?? null,
    prevProfile: overrides.prevProfile ?? null,
    nextProfile: overrides.nextProfile ?? null,
  };
}

function makeAsset(overrides: Partial<AssetFile> = {}): AssetFile {
  return {
    id: overrides.id ?? uid(),
    remarks: overrides.remarks ?? "geoip.dat",
    url: overrides.url ?? "https://example.com/geoip.dat",
    lastUpdated: overrides.lastUpdated ?? Date.now(),
    locked: overrides.locked ?? false,
  };
}

function makeState(overrides: Partial<AppState> = {}): AppState {
  return {
    profiles: overrides.profiles ?? [],
    groups: overrides.groups ?? [
      { id: "g-main", name: "Main" },
      { id: "g-alt", name: "Alt" },
    ],
    subscriptions: overrides.subscriptions ?? [],
    routingRules: overrides.routingRules ?? [],
    assetFiles: overrides.assetFiles ?? [],
    settings: overrides.settings ?? DEFAULT_SETTINGS,
    activeId: overrides.activeId ?? null,
    version: overrides.version,
  };
}

function createBridgeMock(): BridgeMock {
  return {
    start: vi.fn(async (profileId: string) => ({
      ...DEFAULT_STATUS,
      state: "connected",
      activeId: profileId,
    })),
    stop: vi.fn(async () => DEFAULT_STATUS),
    restart: vi.fn(async () => ({ ...DEFAULT_STATUS, state: "connected" })),
    status: vi.fn(async () => DEFAULT_STATUS),
    onStatus: vi.fn((_cb: (s: ServiceStatus) => void) => () => {}),
    ping: vi.fn(async (_profileId: string) => 0),
    pingAll: vi.fn(async () => ({})),
    log: vi.fn(async (_input?: { target?: LogTarget; lines?: number }) => ""),
    clearLogs: vi.fn(async () => ({ ok: true })),
    realPing: vi.fn(async () => 0),
    realPingAll: vi.fn(async () => ({})),
    speedTest: vi.fn(async () => 0),
    speedTestAll: vi.fn(async () => ({})),
    capabilities: vi.fn(async () => ({
      bridge: "mock",
      core: "",
      singboxVersion: "",
      curl: false,
      tun: false,
    })),
    listApps: vi.fn(async () => []),
    reloadAppFilter: vi.fn(async () => ({ ok: true })),
    readState: vi.fn(async () => makeState()),
    writeState: vi.fn(async (_state: AppState) => {}),
    fetchSubscription: vi.fn(
      async (_url: string, _opts?: { userAgent?: string; allowInsecure?: boolean }) => [],
    ),
    applySubscription: vi.fn(async (_subId: string) => makeState()),
    deduplicateProfiles: vi.fn(async (profiles: Profile[], _activeId: string | null) => {
      // Canonical dedup key (protocol + endpoint); mirrors the backend logic.
      const seen = new Set<string>();
      const out: Profile[] = [];
      for (const p of profiles) {
        const ep = "endpoint" in p ? `${p.endpoint.address}:${p.endpoint.port}` : "";
        const key = `${p.protocol}|${ep}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(p);
      }
      return out;
    }),
    removeProfilesBySubId: vi.fn(async (profiles: Profile[], _subId: string) =>
      profiles.filter((p) => p.meta.subId !== _subId),
    ),
    onSubApplied: vi.fn((_cb: (info: SubAppliedEvent) => void) => () => {}),
    downloadAsset: vi.fn(
      async (_filename: string, _url: string, _mode?: "auto" | "proxy" | "direct") => ({
        ok: true,
      }),
    ),
    listAssets: vi.fn(async () => []),
    parseShareLinks: vi.fn(async (_text: string) => []),
    buildShareLink: vi.fn(async (_profile: Profile) => ""),
    exportBackup: vi.fn(async () => new Blob()),
    importBackup: vi.fn(async (_file: Blob, _mode: "merge" | "replace") => {}),
  };
}

let bridge: BridgeMock;
let useAppStore: UseAppStoreModule["useAppStore"];

beforeEach(async () => {
  vi.resetModules();
  vi.clearAllMocks();

  bridge = createBridgeMock();
  vi.doMock("../lib/bridge-provider", () => ({ bridge }));
  vi.doMock("../generated/schemas", async () => ({
    ...(await vi.importActual<typeof import("../generated/schemas")>("../generated/schemas")),
    AppStateSchema: {
      safeParse: (value: unknown) => ({ success: true, data: value }),
    },
  }));

  ({ useAppStore } = await import("./useAppStore"));
});

describe("useAppStore", () => {
  it("hydrate merges default settings with persisted state", async () => {
    const profile = makeVless({ meta: { id: "p1" } });
    bridge.readState.mockResolvedValue(
      makeState({
        profiles: [profile],
        activeId: profile.meta.id,
        settings: {
          ...DEFAULT_SETTINGS,
          muxXudpConcurrency: undefined,
          muxXudp443: undefined,
        },
      }),
    );
    bridge.status.mockResolvedValue({ ...DEFAULT_STATUS, core: "Xray 25.5.16" });

    await useAppStore.getState().hydrate();

    const state = useAppStore.getState();
    expect(state.hydrated).toBe(true);
    expect(state.profiles[0].meta.id).toBe("p1");
    expect(state.settings.muxXudpConcurrency).toBe(8);
    expect(state.settings.muxXudp443).toBe("reject");
    expect(bridge.onStatus).toHaveBeenCalledTimes(1);
  });

  it("computes upload and download rates from successive service samples", async () => {
    let statusListener: ((status: ServiceStatus) => void) | undefined;
    bridge.onStatus.mockImplementation((cb: (status: ServiceStatus) => void) => {
      statusListener = cb;
      return () => {};
    });
    bridge.status.mockResolvedValue({
      ...DEFAULT_STATUS,
      state: "connected",
      activeId: "p1",
      uploadBytes: 2048,
      downloadBytes: 4096,
    });

    const nowSpy = vi.spyOn(Date, "now");
    nowSpy.mockReturnValueOnce(1_000).mockReturnValueOnce(2_000);

    try {
      await useAppStore.getState().hydrate();
      statusListener?.({
        ...DEFAULT_STATUS,
        state: "connected",
        activeId: "p1",
        uploadBytes: 4096,
        downloadBytes: 8192,
      });
    } finally {
      nowSpy.mockRestore();
    }

    const state = useAppStore.getState();
    expect(state.uploadRate).toBe(2048);
    expect(state.downloadRate).toBe(4096);
  });

  it("hydrate migrates the legacy bypass-lan mode to global", async () => {
    bridge.readState.mockResolvedValue(
      makeState({
        settings: { ...DEFAULT_SETTINGS, routingMode: "bypass-lan" as never },
        assetFiles: [],
      }),
    );

    await useAppStore.getState().hydrate();

    expect(useAppStore.getState().settings.routingMode).toBe("global");
    expect(bridge.writeState).toHaveBeenCalledWith(
      expect.objectContaining({
        settings: expect.objectContaining({ routingMode: "global" }),
      }),
    );
  });

  it("hydrate migrates legacy subscription interval from hours to minutes", async () => {
    bridge.readState.mockResolvedValue(
      makeState({ subscriptions: [makeSub({ id: "s1", interval: 6 })] }), // no version → legacy
    );

    await useAppStore.getState().hydrate();

    expect(useAppStore.getState().subscriptions[0].interval).toBe(360);
    const written = bridge.writeState.mock.calls[bridge.writeState.mock.calls.length - 1]?.[0];
    expect(written?.subscriptions[0].interval).toBe(360);
    expect(written?.version).toBeTruthy();
  });

  it("hydrate leaves versioned state intact (no re-migration)", async () => {
    bridge.readState.mockResolvedValue(
      makeState({ subscriptions: [makeSub({ id: "s1", interval: 360 })], version: "v0.3.2" }),
    );

    await useAppStore.getState().hydrate();

    expect(useAppStore.getState().subscriptions[0].interval).toBe(360);
  });

  it("setActive flushes and restarts when service is running", async () => {
    const p1 = makeVless({ meta: { id: "p1", remarks: "One" } });
    const p2 = makeVless({
      meta: { id: "p2", remarks: "Two" },
      uuid: "22222222-2222-2222-2222-222222222222",
    });
    useAppStore.setState({
      profiles: [p1, p2],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: p1.meta.id,
      service: { ...DEFAULT_STATUS, state: "connected", activeId: p1.meta.id },
    });

    await useAppStore.getState().setActive("p2");

    expect(useAppStore.getState().activeId).toBe("p2");
    expect(bridge.writeState).toHaveBeenCalled();
    expect(bridge.start).toHaveBeenCalledWith("p2");
  });

  it("toggleService exposes connecting state before start resolves", async () => {
    const profile = makeVless({ meta: { id: "p1", remarks: "One" } });
    let resolveStart: ((value: ServiceStatus) => void) | null = null;
    bridge.start.mockImplementation(
      () =>
        new Promise<ServiceStatus>((resolve) => {
          resolveStart = resolve;
        }),
    );
    useAppStore.setState({
      profiles: [profile],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: profile.meta.id,
      service: DEFAULT_STATUS,
    });

    const pending = useAppStore.getState().toggleService();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(useAppStore.getState().busy).toBe(true);
    expect(useAppStore.getState().service.state).toBe("connecting");
    expect(useAppStore.getState().service.activeId).toBe(profile.meta.id);

    (resolveStart as unknown as (value: ServiceStatus) => void)({
      ...DEFAULT_STATUS,
      state: "connected",
      activeId: profile.meta.id,
    });
    await pending;
  });

  it("upsertProfile inserts then updates by id", () => {
    const p1 = makeVless({ meta: { id: "p1", remarks: "One" } });
    const p2 = makeVless({
      meta: { id: "p2", remarks: "Two" },
      uuid: "22222222-2222-2222-2222-222222222222",
    });
    useAppStore.setState({
      profiles: [p1],
      groups: [],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: null,
    });

    useAppStore.getState().upsertProfile(p2);
    expect(useAppStore.getState().profiles.map((p) => p.meta.id)).toEqual(["p2", "p1"]);

    useAppStore.getState().upsertProfile({ ...p2, meta: { ...p2.meta, remarks: "Two updated" } });
    expect(useAppStore.getState().profiles).toHaveLength(2);
    expect(useAppStore.getState().profiles[0].meta.remarks).toBe("Two updated");
  });

  it("cloneProfile resets ping/speed stats and subscription link", () => {
    const src = makeVless({
      meta: { id: "p1", remarks: "Node", ping: 123, speed: 9_000, subId: "s1" },
    });
    useAppStore.setState({
      profiles: [src],
      groups: [],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: null,
    });

    useAppStore.getState().cloneProfile("p1");

    const copy = useAppStore.getState().profiles.find((p) => p.meta.id !== "p1");
    expect(copy).toBeDefined();
    expect(copy?.meta.remarks).toBe("Node (copy)");
    expect(copy?.meta.ping).toBeNull();
    expect(copy?.meta.speed).toBeNull();
    expect(copy?.meta.subId).toBeNull();
  });

  it("ping/realPing/speed results land in meta (nested), not a flat top-level field", async () => {
    const p = makeVless({ meta: { id: "p1", ping: null, speed: null } });
    useAppStore.setState({
      profiles: [p],
      groups: [],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: null,
    });

    bridge.ping.mockResolvedValueOnce(88);
    await useAppStore.getState().pingProfile("p1");
    let stored = useAppStore.getState().profiles[0];
    expect(stored.meta.ping).toBe(88);
    expect((stored as Record<string, unknown>).ping).toBeUndefined();

    bridge.realPing.mockResolvedValueOnce(150);
    await useAppStore.getState().realPingProfile("p1");
    stored = useAppStore.getState().profiles[0];
    expect(stored.meta.ping).toBe(150);

    bridge.speedTest.mockResolvedValueOnce(1_500_000);
    await useAppStore.getState().speedTestProfile("p1");
    stored = useAppStore.getState().profiles[0];
    expect(stored.meta.speed).toBe(1_500_000);
    expect((stored as Record<string, unknown>).speed).toBeUndefined();
  });

  it("removeProfile stops service and clears active id when removing active profile", async () => {
    const active = makeVless({ meta: { id: "p1", subId: null } });
    const other = makeVless({
      meta: { id: "p2" },
      uuid: "22222222-2222-2222-2222-222222222222",
    });
    useAppStore.setState({
      profiles: [active, other],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: active.meta.id,
      service: { ...DEFAULT_STATUS, state: "connected", activeId: active.meta.id },
    });

    await useAppStore.getState().removeProfile(active.meta.id);

    expect(bridge.stop).toHaveBeenCalled();
    expect(useAppStore.getState().activeId).toBeNull();
    expect(useAppStore.getState().profiles.map((p) => p.meta.id)).toEqual(["p2"]);
  });

  it("removeAssetFile removes the asset without touching routing settings", () => {
    const geoip = makeAsset({ id: "asset-geoip" });
    useAppStore.setState({
      profiles: [],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [],
      assetFiles: [geoip],
      settings: { ...DEFAULT_SETTINGS, routingMode: "rules" },
      activeId: null,
    });

    useAppStore.getState().removeAssetFile(geoip.id);

    expect(useAppStore.getState().assetFiles).toEqual([]);
    expect(useAppStore.getState().settings.routingMode).toBe("rules");
  });

  it("updateSub surfaces a soft error recorded by the backend", async () => {
    const sub = makeSub({ id: "s1", remarks: "Broken", filter: "[" });
    useAppStore.setState({
      profiles: [],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [sub],
      settings: DEFAULT_SETTINGS,
      activeId: null,
    });
    bridge.applySubscription.mockResolvedValue(
      makeState({ subscriptions: [{ ...sub, lastError: "invalid profile filter" }] }),
    );

    await useAppStore.getState().updateSub("s1");

    expect(bridge.applySubscription).toHaveBeenCalledWith("s1");
    expect(useAppStore.getState().subscriptions[0].lastError).toBe("invalid profile filter");
  });

  it("updateSub reflects the state the backend applied", async () => {
    const sub = makeSub({ id: "s1", remarks: "Main sub", groupId: "g-alt" });
    const newActive = makeVless({
      meta: { id: "new-active", remarks: "Node A", subId: "s1", groupId: "g-alt" },
    });
    const newB = makeVless({
      meta: { id: "new-b", remarks: "Node B", subId: "s1", groupId: "g-alt" },
    });

    useAppStore.setState({
      profiles: [makeVless({ meta: { id: "old-active", subId: "s1" } })],
      groups: [
        { id: "g-main", name: "Main" },
        { id: "g-alt", name: "Alt" },
      ],
      subscriptions: [sub],
      settings: DEFAULT_SETTINGS,
      activeId: "old-active",
      service: DEFAULT_STATUS,
    });
    // The backend returns the post-apply state (it ran fetch + map + dedup + apply
    // and already restarted the active data-path if needed).
    bridge.applySubscription.mockResolvedValue(
      makeState({
        profiles: [newActive, newB],
        subscriptions: [{ ...sub, count: 2, lastError: null }],
        activeId: "new-active",
      }),
    );

    await useAppStore.getState().updateSub("s1");

    const state = useAppStore.getState();
    expect(state.activeId).toBe("new-active");
    expect(state.profiles.map((p) => p.meta.id)).toEqual(["new-active", "new-b"]);
    expect(state.subscriptions[0].count).toBe(2);
    expect(state.subscriptions[0].lastError).toBeNull();
    // The backend owns the restart; the store never starts the core itself.
    expect(bridge.start).not.toHaveBeenCalled();
  });

  it("daemon subApplied push reloads the persisted state", async () => {
    let push: ((info: SubAppliedEvent) => void) | null = null;
    bridge.onSubApplied.mockImplementation((cb) => {
      push = cb;
      return () => {};
    });
    await useAppStore.getState().hydrate();
    expect(push).not.toBeNull();

    // The daemon applied a subscription headlessly and rewrote the state files.
    const sub = makeSub({ id: "s1", remarks: "Cached sub", count: 1 });
    const fresh = makeVless({ meta: { id: "fresh", remarks: "Fresh", subId: "s1" } });
    bridge.readState.mockResolvedValue(
      makeState({ profiles: [fresh], subscriptions: [sub], activeId: "fresh" }),
    );

    (push as unknown as (info: SubAppliedEvent) => void)({
      subId: "s1",
      remarks: "Cached sub",
      count: 1,
    });
    await vi.waitFor(() => {
      expect(useAppStore.getState().profiles.map((p) => p.meta.id)).toEqual(["fresh"]);
    });

    const state = useAppStore.getState();
    expect(state.activeId).toBe("fresh");
    expect(state.subscriptions[0].count).toBe(1);
    expect(state.recentActivity[0]?.icon).toBe("cloud_sync");
  });

  describe("recentActivity", () => {
    it("starts empty", async () => {
      await useAppStore.getState().hydrate();
      expect(useAppStore.getState().recentActivity).toHaveLength(0);
    });

    it("toggleService start pushes serviceStarted activity", async () => {
      const profile = makeVless({ meta: { id: "p1", remarks: "MyNode" } });
      bridge.readState.mockResolvedValue(
        makeState({ profiles: [profile], activeId: profile.meta.id }),
      );
      await useAppStore.getState().hydrate();

      await useAppStore.getState().toggleService();

      const feed = useAppStore.getState().recentActivity;
      expect(feed).toHaveLength(1);
      expect(feed[0].icon).toBe("play_circle");
      expect(feed[0].text).toContain("MyNode");
      expect(feed[0].color).toBe("var(--running)");
      expect(feed[0].at).toBeGreaterThan(0);
    });

    it("toggleService stop pushes serviceStopped activity", async () => {
      const profile = makeVless({ meta: { id: "p1", remarks: "MyNode" } });
      bridge.readState.mockResolvedValue(
        makeState({ profiles: [profile], activeId: profile.meta.id }),
      );
      bridge.status.mockResolvedValue({
        ...DEFAULT_STATUS,
        state: "connected",
        activeId: profile.meta.id,
      });
      await useAppStore.getState().hydrate();

      await useAppStore.getState().toggleService();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("stop_circle");
      expect(feed[0].color).toBe("var(--error)");
    });

    it("addProfiles pushes profileImported activity", async () => {
      await useAppStore.getState().hydrate();
      const profiles = [makeVless({ meta: { id: "p1" } }), makeVless({ meta: { id: "p2" } })];
      useAppStore.getState().addProfiles(profiles);

      const feed = useAppStore.getState().recentActivity;
      expect(feed).toHaveLength(1);
      expect(feed[0].icon).toBe("download");
      expect(feed[0].text).toMatch(/2/);
    });

    it("updateSub pushes subUpdated activity on success", async () => {
      const sub = makeSub({ id: "s1", remarks: "MySub" });
      bridge.readState.mockResolvedValue(makeState({ subscriptions: [sub] }));
      bridge.applySubscription.mockResolvedValue(
        makeState({
          profiles: [makeVless({ meta: { id: "p1", subId: "s1" } })],
          subscriptions: [{ ...sub, count: 1 }],
        }),
      );
      await useAppStore.getState().hydrate();

      await useAppStore.getState().updateSub("s1");

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("cloud_sync");
      expect(feed[0].text).toContain("MySub");
    });

    it("selectBest pushes bestSelected activity", async () => {
      const best = makeVless({ meta: { id: "p1", remarks: "FastNode", ping: 10 } });
      const slow = makeVless({ meta: { id: "p2", remarks: "SlowNode", ping: 200 } });
      bridge.readState.mockResolvedValue(
        makeState({ profiles: [best, slow], activeId: best.meta.id }),
      );
      await useAppStore.getState().hydrate();

      useAppStore.getState().selectBest();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("stars");
      expect(feed[0].text).toContain("FastNode");
    });

    it("newer events appear before older ones", async () => {
      await useAppStore.getState().hydrate();
      useAppStore.getState().addProfiles([makeVless({ meta: { id: "p1" } })]);
      useAppStore.getState().addProfiles([makeVless({ meta: { id: "p2" } })]);

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].at).toBeGreaterThanOrEqual(feed[1].at);
    });

    it("speedTestAll pushes speedTestComplete activity", async () => {
      const profile = makeVless({ meta: { id: "p1" } });
      bridge.readState.mockResolvedValue(makeState({ profiles: [profile] }));
      bridge.speedTestAll = vi.fn(async () => ({ [profile.meta.id]: 5_000_000 }));
      await useAppStore.getState().hydrate();

      await useAppStore.getState().speedTestAll();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("speed");
      expect(feed[0].text).toMatch(/1/);
    });

    it("removeUnreachable pushes unreachableRemoved activity", async () => {
      const dead = makeVless({ meta: { id: "p1", ping: -1 } });
      const alive = makeVless({ meta: { id: "p2", ping: 20 } });
      bridge.readState.mockResolvedValue(makeState({ profiles: [dead, alive] }));
      await useAppStore.getState().hydrate();

      await useAppStore.getState().removeUnreachable();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("delete_sweep");
      expect(feed[0].color).toBe("var(--error)");
      expect(feed[0].text).toMatch(/1/);
    });

    it("removeDuplicates pushes duplicatesRemoved activity", async () => {
      const a = makeVless({
        meta: { id: "p1", remarks: "Node" },
        endpoint: { address: "1.2.3.4", port: 443 },
      });
      const b = makeVless({
        meta: { id: "p2", remarks: "Node" },
        endpoint: { address: "1.2.3.4", port: 443 },
      });
      bridge.readState.mockResolvedValue(makeState({ profiles: [a, b] }));
      await useAppStore.getState().hydrate();

      await useAppStore.getState().removeDuplicates();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("content_cut");
      expect(feed[0].text).toMatch(/1/);
    });

    it("downloadAsset pushes assetDownloaded activity on success", async () => {
      const asset = makeAsset({ id: "a1", remarks: "geoip.dat" });
      bridge.readState.mockResolvedValue(makeState({ assetFiles: [asset] }));
      bridge.downloadAsset.mockResolvedValue({ ok: true });
      await useAppStore.getState().hydrate();

      await useAppStore.getState().downloadAsset("a1");

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("file_download_done");
      expect(feed[0].text).toContain("geoip.dat");
    });

    it("upsertProfile pushes profileSaved activity", async () => {
      await useAppStore.getState().hydrate();
      const profile = makeVless({ meta: { id: "p1", remarks: "MyNode" } });

      useAppStore.getState().upsertProfile(profile);

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("edit_note");
      expect(feed[0].text).toContain("MyNode");
    });
  });
});
