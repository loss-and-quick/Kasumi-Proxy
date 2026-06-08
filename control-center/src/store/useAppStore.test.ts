import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AdvancedSettings,
  AppState,
  Bridge,
  ServiceStatus,
  Subscription,
} from "../lib/bridge";
import type { AssetFile, Profile } from "../lib/schema";

type Vless = Extract<Profile, { protocol: "vless" }>;
type UseAppStoreModule = typeof import("./useAppStore");
type BridgeMock = {
  [K in keyof Bridge]: ReturnType<typeof vi.fn<Bridge[K]>>;
};

import { uid } from "../lib/utils";

const DEFAULT_SETTINGS: AdvancedSettings = {
  routingMode: "global",
  domainSniffing: true,
  routeOnly: false,
  domainStrategy: "IPIfNonMatch",
  domainStrategy4Singbox: "prefer_ipv4",
  dnsViaProxy: true,
  fakeDns: false,
  preferIpv6: false,
  mux: false,
  muxConcurrency: 8,
  muxXudpConcurrency: 8,
  muxXudp443: "reject",
  fragment: false,
  fragmentPackets: "tlshello",
  mtu: 1350,
};

const DEFAULT_STATUS: ServiceStatus = {
  state: "stopped",
  activeId: null,
  uploadBytes: 0,
  downloadBytes: 0,
  uptimeSec: 0,
  core: "Xray",
};

function makeVless(overrides: Partial<Vless> = {}): Vless {
  return {
    protocol: "vless",
    id: overrides.id ?? uid(),
    remarks: overrides.remarks ?? "Node",
    address: overrides.address ?? "ex.com",
    port: overrides.port ?? 443,
    groupId: overrides.groupId ?? "g-main",
    subId: overrides.subId ?? null,
    ping: overrides.ping ?? null,
    network: overrides.network ?? "tcp",
    headerType: overrides.headerType ?? "none",
    host: overrides.host ?? "",
    path: overrides.path ?? "",
    muxEnabled: overrides.muxEnabled ?? false,
    security: overrides.security ?? "tls",
    sni: overrides.sni ?? "",
    disableSni: overrides.disableSni ?? false,
    fingerprint: overrides.fingerprint ?? "chrome",
    alpn: overrides.alpn ?? "",
    allowInsecure: overrides.allowInsecure ?? false,
    tlsMinVersion: overrides.tlsMinVersion ?? "",
    tlsMaxVersion: overrides.tlsMaxVersion ?? "",
    tlsCipherSuites: overrides.tlsCipherSuites ?? "",
    tlsCurvePreferences: overrides.tlsCurvePreferences ?? "",
    cert: overrides.cert ?? "",
    disableSystemRoot: overrides.disableSystemRoot ?? false,
    publicKey: overrides.publicKey ?? "",
    shortId: overrides.shortId ?? "",
    spiderX: overrides.spiderX ?? "",
    ech: overrides.ech ?? "",
    vcn: overrides.vcn ?? "",
    pcs: overrides.pcs ?? "",
    pqv: overrides.pqv ?? "",
    flow: overrides.flow ?? "",
    uuid: overrides.uuid ?? "11111111-1111-1111-1111-111111111111",
    encryption: overrides.encryption ?? "none",
    grpcMode: overrides.grpcMode ?? "",
    serviceName: overrides.serviceName ?? "",
    authority: overrides.authority ?? "",
    xhttpMode: overrides.xhttpMode ?? "",
    xhttpExtra: overrides.xhttpExtra ?? "",
    ...overrides,
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
  };
}

function createBridgeMock(): BridgeMock {
  return {
    start: vi.fn(async (profileId: string) => ({
      ...DEFAULT_STATUS,
      state: "running",
      activeId: profileId,
    })),
    stop: vi.fn(async () => DEFAULT_STATUS),
    restart: vi.fn(async () => ({ ...DEFAULT_STATUS, state: "running" })),
    status: vi.fn(async () => DEFAULT_STATUS),
    onStatus: vi.fn((_cb: (s: ServiceStatus) => void) => () => {}),
    ping: vi.fn(async (_profileId: string) => 0),
    pingAll: vi.fn(async () => ({})),
    log: vi.fn(
      async (_input?: {
        target?: "xray" | "singbox" | "tun2socks" | "service" | "proxy_control";
        lines?: number;
      }) => "",
    ),
    clearLogs: vi.fn(async () => ({ ok: true })),
    readState: vi.fn(async () => makeState()),
    writeState: vi.fn(async (_state: AppState) => {}),
    fetchSubscription: vi.fn(
      async (_url: string, _opts?: { userAgent?: string; allowInsecure?: boolean }) => [],
    ),
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
  vi.doMock("../lib/schema", () => ({
    AppStateSchema: {
      safeParse: (value: unknown) => ({ success: true, data: value }),
    },
  }));

  ({ useAppStore } = await import("./useAppStore"));
});

describe("useAppStore", () => {
  it("hydrate merges default settings with persisted state", async () => {
    const profile = makeVless({ id: "p1" });
    bridge.readState.mockResolvedValue(
      makeState({
        profiles: [profile],
        activeId: profile.id,
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
    expect(state.profiles[0].id).toBe("p1");
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
      state: "running",
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
        state: "running",
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

  it("setActive flushes and restarts when service is running", async () => {
    const p1 = makeVless({ id: "p1", remarks: "One" });
    const p2 = makeVless({
      id: "p2",
      remarks: "Two",
      uuid: "22222222-2222-2222-2222-222222222222",
    });
    useAppStore.setState({
      profiles: [p1, p2],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: p1.id,
      service: { ...DEFAULT_STATUS, state: "running", activeId: p1.id },
    });

    await useAppStore.getState().setActive("p2");

    expect(useAppStore.getState().activeId).toBe("p2");
    expect(bridge.writeState).toHaveBeenCalled();
    expect(bridge.start).toHaveBeenCalledWith("p2");
  });

  it("toggleService exposes connecting state before start resolves", async () => {
    const profile = makeVless({ id: "p1", remarks: "One" });
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
      activeId: profile.id,
      service: DEFAULT_STATUS,
    });

    const pending = useAppStore.getState().toggleService();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(useAppStore.getState().busy).toBe(true);
    expect(useAppStore.getState().service.state).toBe("connecting");
    expect(useAppStore.getState().service.activeId).toBe(profile.id);

    resolveStart?.({ ...DEFAULT_STATUS, state: "running", activeId: profile.id });
    await pending;
  });

  it("upsertProfile inserts then updates by id", () => {
    const p1 = makeVless({ id: "p1", remarks: "One" });
    const p2 = makeVless({
      id: "p2",
      remarks: "Two",
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
    expect(useAppStore.getState().profiles.map((p) => p.id)).toEqual(["p2", "p1"]);

    useAppStore.getState().upsertProfile({ ...p2, remarks: "Two updated" });
    expect(useAppStore.getState().profiles).toHaveLength(2);
    expect(useAppStore.getState().profiles[0].remarks).toBe("Two updated");
  });

  it("cloneProfile resets ping/speed stats and subscription link", () => {
    const src = {
      ...makeVless({ id: "p1", remarks: "Node", ping: 123 }),
      speed: 9_000,
      subId: "s1",
    };
    useAppStore.setState({
      profiles: [src],
      groups: [],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: null,
    });

    useAppStore.getState().cloneProfile("p1");

    const copy = useAppStore.getState().profiles.find((p) => p.id !== "p1");
    expect(copy).toBeDefined();
    expect(copy?.remarks).toBe("Node (copy)");
    expect(copy?.ping).toBeNull();
    expect(copy?.speed).toBeNull();
    expect(copy?.subId).toBeNull();
  });

  it("removeProfile stops service and clears active id when removing active profile", async () => {
    const active = makeVless({ id: "p1", subId: null });
    const other = makeVless({ id: "p2", uuid: "22222222-2222-2222-2222-222222222222" });
    useAppStore.setState({
      profiles: [active, other],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [],
      settings: DEFAULT_SETTINGS,
      activeId: active.id,
      service: { ...DEFAULT_STATUS, state: "running", activeId: active.id },
    });

    await useAppStore.getState().removeProfile(active.id);

    expect(bridge.stop).toHaveBeenCalled();
    expect(useAppStore.getState().activeId).toBeNull();
    expect(useAppStore.getState().profiles.map((p) => p.id)).toEqual(["p2"]);
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

  it("updateSub records invalid regex and skips fetch", async () => {
    const sub = makeSub({ id: "s1", remarks: "Broken", filter: "[" });
    useAppStore.setState({
      profiles: [],
      groups: [{ id: "g-main", name: "Main" }],
      subscriptions: [sub],
      settings: DEFAULT_SETTINGS,
      activeId: null,
    });

    await useAppStore.getState().updateSub("s1");

    expect(bridge.fetchSubscription).not.toHaveBeenCalled();
    expect(useAppStore.getState().subscriptions[0].lastError).toBe("Invalid filter regex");
  });

  it("updateSub remaps active profile and replaces subscription profiles", async () => {
    const oldActive = makeVless({
      id: "old-active",
      remarks: "Node A",
      address: "a.example.com",
      port: 443,
      subId: "s1",
    });
    const unrelated = makeVless({
      id: "other",
      remarks: "Other",
      address: "other.example.com",
      port: 443,
      subId: null,
      uuid: "33333333-3333-3333-3333-333333333333",
    });
    const sub = makeSub({ id: "s1", remarks: "Main sub", groupId: "g-alt" });
    const fetchedA = makeVless({
      id: "new-active",
      remarks: "Node A",
      address: "a.example.com",
      port: 443,
      subId: null,
      uuid: "44444444-4444-4444-4444-444444444444",
    });
    const fetchedB = makeVless({
      id: "new-b",
      remarks: "Node B",
      address: "b.example.com",
      port: 8443,
      subId: null,
      uuid: "55555555-5555-5555-5555-555555555555",
    });

    useAppStore.setState({
      profiles: [oldActive, unrelated],
      groups: [
        { id: "g-main", name: "Main" },
        { id: "g-alt", name: "Alt" },
      ],
      subscriptions: [sub],
      settings: DEFAULT_SETTINGS,
      activeId: oldActive.id,
      service: DEFAULT_STATUS,
    });
    bridge.fetchSubscription.mockResolvedValue([fetchedA, fetchedB]);

    await useAppStore.getState().updateSub("s1");

    const state = useAppStore.getState();
    expect(state.activeId).toBe("new-active");
    expect(state.profiles.find((p) => p.id === "old-active")).toBeUndefined();
    expect(state.profiles.find((p) => p.id === "new-active")?.subId).toBe("s1");
    expect(state.profiles.find((p) => p.id === "new-active")?.groupId).toBe("g-alt");
    expect(state.profiles.find((p) => p.id === "new-b")?.subId).toBe("s1");
    expect(state.subscriptions[0].count).toBe(2);
    expect(state.subscriptions[0].lastError).toBeNull();
    expect(bridge.start).not.toHaveBeenCalled();
  });

  describe("recentActivity", () => {
    it("starts empty", async () => {
      await useAppStore.getState().hydrate();
      expect(useAppStore.getState().recentActivity).toHaveLength(0);
    });

    it("toggleService start pushes serviceStarted activity", async () => {
      const profile = makeVless({ id: "p1", remarks: "MyNode" });
      bridge.readState.mockResolvedValue(makeState({ profiles: [profile], activeId: profile.id }));
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
      const profile = makeVless({ id: "p1", remarks: "MyNode" });
      bridge.readState.mockResolvedValue(makeState({ profiles: [profile], activeId: profile.id }));
      bridge.status.mockResolvedValue({
        ...DEFAULT_STATUS,
        state: "running",
        activeId: profile.id,
      });
      await useAppStore.getState().hydrate();

      await useAppStore.getState().toggleService();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("stop_circle");
      expect(feed[0].color).toBe("var(--error)");
    });

    it("addProfiles pushes profileImported activity", async () => {
      await useAppStore.getState().hydrate();
      const profiles = [makeVless({ id: "p1" }), makeVless({ id: "p2" })];
      useAppStore.getState().addProfiles(profiles);

      const feed = useAppStore.getState().recentActivity;
      expect(feed).toHaveLength(1);
      expect(feed[0].icon).toBe("download");
      expect(feed[0].text).toMatch(/2/);
    });

    it("updateSub pushes subUpdated activity on success", async () => {
      const sub = makeSub({ id: "s1", remarks: "MySub" });
      bridge.readState.mockResolvedValue(makeState({ subscriptions: [sub] }));
      bridge.fetchSubscription.mockResolvedValue([makeVless({ id: "p1", subId: "s1" })]);
      await useAppStore.getState().hydrate();

      await useAppStore.getState().updateSub("s1");

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("cloud_sync");
      expect(feed[0].text).toContain("MySub");
    });

    it("selectBest pushes bestSelected activity", async () => {
      const best = makeVless({ id: "p1", remarks: "FastNode", ping: 10 });
      const slow = makeVless({ id: "p2", remarks: "SlowNode", ping: 200 });
      bridge.readState.mockResolvedValue(makeState({ profiles: [best, slow], activeId: best.id }));
      await useAppStore.getState().hydrate();

      useAppStore.getState().selectBest();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("stars");
      expect(feed[0].text).toContain("FastNode");
    });

    it("newer events appear before older ones", async () => {
      await useAppStore.getState().hydrate();
      useAppStore.getState().addProfiles([makeVless({ id: "p1" })]);
      useAppStore.getState().addProfiles([makeVless({ id: "p2" })]);

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].at).toBeGreaterThanOrEqual(feed[1].at);
    });

    it("speedTestAll pushes speedTestComplete activity", async () => {
      const profile = makeVless({ id: "p1" });
      bridge.readState.mockResolvedValue(makeState({ profiles: [profile] }));
      bridge.speedTestAll = vi.fn(async () => ({ [profile.id]: 5_000_000 }));
      await useAppStore.getState().hydrate();

      await useAppStore.getState().speedTestAll();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("speed");
      expect(feed[0].text).toMatch(/1/);
    });

    it("removeUnreachable pushes unreachableRemoved activity", async () => {
      const dead = makeVless({ id: "p1", ping: -1 });
      const alive = makeVless({ id: "p2", ping: 20 });
      bridge.readState.mockResolvedValue(makeState({ profiles: [dead, alive] }));
      await useAppStore.getState().hydrate();

      await useAppStore.getState().removeUnreachable();

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("delete_sweep");
      expect(feed[0].color).toBe("var(--error)");
      expect(feed[0].text).toMatch(/1/);
    });

    it("removeDuplicates pushes duplicatesRemoved activity", async () => {
      const a = makeVless({ id: "p1", remarks: "Node", address: "1.2.3.4", port: 443 });
      const b = makeVless({ id: "p2", remarks: "Node", address: "1.2.3.4", port: 443 });
      bridge.readState.mockResolvedValue(makeState({ profiles: [a, b] }));
      await useAppStore.getState().hydrate();

      useAppStore.getState().removeDuplicates();

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
      const profile = makeVless({ id: "p1", remarks: "MyNode" });

      useAppStore.getState().upsertProfile(profile);

      const feed = useAppStore.getState().recentActivity;
      expect(feed[0].icon).toBe("edit_note");
      expect(feed[0].text).toContain("MyNode");
    });
  });
});
