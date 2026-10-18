import { describe, expect, it, vi } from "vitest";
import type { Profile, ResolvedIdentity, Response_Serialize } from "../../generated/bindings";
import { DEFAULT_ADVANCED_SETTINGS } from "../../generated/defaults";
import type { AppState } from "../bridge";
import { createBridge, type Dispatch, type PushStreams } from "../dispatch-bridge";

const noPush: PushStreams = {
  subscribeStatus: () => () => {},
  subscribeSubApplied: () => () => {},
  subscribeAssetsUpdated: () => () => {},
};

// A bare AppState shell — the bridge only ever reads `.profiles`/`.settings` here.
const stateWith = (profiles: unknown[]): AppState =>
  ({ profiles, settings: {} }) as unknown as AppState;

const endpointProfile = (id: string) => ({
  meta: { id },
  endpoint: { address: `${id}.example`, port: 443 },
});

describe("dispatch-bridge batch diagnostics", () => {
  // Regression: batch ops used to filter the requested ids against the bridge's
  // cached `lastState`. A stale/empty cache collapsed the list to nothing, so the
  // batch resolved instantly without probing anything or surfacing an error — while
  // single-profile probes (which dispatch by id) kept working. These guard that the
  // batch fans out by id and never silently no-ops.

  it("realPingAll probes every requested id even with an empty state cache", async () => {
    const seen: string[] = [];
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "realPing") {
        seen.push(cmd.profileId);
        return { kind: "ping", value: 42 } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    const results: Record<string, number> = {};
    const out = await bridge.realPingAll(["a", "b", "c"], (id, ms) => {
      results[id] = ms;
    });

    expect(seen.sort()).toEqual(["a", "b", "c"]);
    expect(out).toEqual({ a: 42, b: 42, c: 42 });
    expect(results).toEqual({ a: 42, b: 42, c: 42 });
  });

  it("speedTestAll probes every requested id even with an empty state cache", async () => {
    const seen: string[] = [];
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "speedTest") {
        seen.push(cmd.profileId);
        return { kind: "speed", value: 1000 } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    const results: Record<string, number> = {};
    await bridge.speedTestAll(["a", "b"], (id, bps) => {
      results[id] = bps;
    });

    expect(seen.sort()).toEqual(["a", "b"]);
    expect(results).toEqual({ a: 1000, b: 1000 });
  });

  it("pingAll reads fresh state so a stale cache can't drop the requested ids", async () => {
    let readStateCalls = 0;
    const pinged: string[] = [];
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "readState") {
        readStateCalls++;
        return {
          kind: "state",
          value: stateWith([endpointProfile("a"), endpointProfile("b")]),
        } as Response_Serialize;
      }
      if (cmd.cmd === "ping") {
        pinged.push(cmd.profileId);
        return { kind: "ping", value: 7 } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    const results: Record<string, number> = {};
    await bridge.pingAll(["a", "b"], (id, ms) => {
      results[id] = ms;
    });

    expect(readStateCalls).toBe(1); // fresh read, once — not re-read per profile
    expect(pinged.sort()).toEqual(["a", "b"]);
    expect(results).toEqual({ a: 7, b: 7 });
  });
});

describe("dispatch-bridge core resolution", () => {
  it("resolveCores ships the profiles and unwraps the typed reply", async () => {
    const profiles = [endpointProfile("a"), endpointProfile("b")];
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "resolveCores") {
        expect(cmd.profiles).toHaveLength(2);
        return {
          kind: "coreResolutions",
          value: [
            { resolved: "xray", forced: null },
            { resolved: "sing-box", forced: "sing-box" },
          ],
        } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    const out = await bridge.resolveCores(profiles as unknown as Profile[]);
    expect(out).toEqual([
      { resolved: "xray", forced: null },
      { resolved: "sing-box", forced: "sing-box" },
    ]);
  });
});

describe("dispatch-bridge chain candidates", () => {
  it("chainCandidates ships the draft and unwraps the id list", async () => {
    const draft = endpointProfile("draft");
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "chainCandidates") {
        expect(cmd.profile.meta.id).toBe("draft");
        return { kind: "profileIds", value: ["a", "b"] } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    expect(await bridge.chainCandidates(draft as unknown as Profile)).toEqual(["a", "b"]);
  });

  it("chainConflicts ships the draft and unwraps the conflicting hops", async () => {
    const draft = endpointProfile("draft");
    const conflict = { kind: "chainCoreConflict", xray: "x", singBox: "s" } as const;
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "chainConflicts") {
        expect(cmd.profile.meta.id).toBe("draft");
        return { kind: "hopConflicts", value: [{ id: "a", conflict }] } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    expect(await bridge.chainConflicts(draft as unknown as Profile)).toEqual([
      { id: "a", conflict },
    ]);
  });
});

describe("dispatch-bridge local ports", () => {
  it("checkLocalPorts ships the draft settings and unwraps the clash", async () => {
    const clash = { port: 10808, first: "socks", second: "http" } as const;
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "checkLocalPorts") {
        expect(cmd.settings.localHttpPort).toBe(10808);
        return { kind: "portCollision", value: clash } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    const draft = { ...DEFAULT_ADVANCED_SETTINGS, localHttpPort: 10808 };
    expect(await bridge.checkLocalPorts(draft)).toEqual(clash);
  });
});

describe("dispatch-bridge catch-all rules", () => {
  it("catchAllRules ships the rules and unwraps one flag per rule", async () => {
    const rules = [
      { id: "a", remarks: "", enabled: true, outboundTag: "direct", domain: ["x"] },
      { id: "b", remarks: "", enabled: true, outboundTag: "direct", network: "tcp,udp" as const },
    ];
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "catchAllRules") {
        expect(cmd.rules).toEqual(rules);
        return { kind: "flags", value: [false, true] } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);

    expect(await bridge.catchAllRules(rules)).toEqual([false, true]);
  });
});

describe("dispatch-bridge status stream", () => {
  const statusFrame = (extra: Record<string, unknown>) => ({
    state: "connected",
    uploadBytes: 0,
    downloadBytes: 0,
    uptimeSec: 1,
    engine: "xray",
    activeId: "p1",
    core: "Xray 1.0",
    ...extra,
  });

  it("carries pendingRestart from pushes into composed status() replies", async () => {
    let pushStatus: ((raw: unknown) => void) | undefined;
    const push: PushStreams = {
      subscribeStatus: (cb) => {
        pushStatus = cb;
        return () => {};
      },
      subscribeSubApplied: () => () => {},
      subscribeAssetsUpdated: () => () => {},
    };
    // The status command replies with the bare ServiceState — no pendingRestart —
    // so status() must fill it from the last push.
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "status") {
        return {
          kind: "status",
          value: {
            state: "connected",
            uploadBytes: 0,
            downloadBytes: 0,
            uptimeSec: 1,
            engine: "xray",
          },
        } as Response_Serialize;
      }
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, push);

    const seen: boolean[] = [];
    bridge.onStatus((s) => seen.push(s.pendingRestart));

    pushStatus?.(statusFrame({ pendingRestart: true }));
    expect(seen).toEqual([true]);
    expect((await bridge.status()).pendingRestart).toBe(true);

    // A frame without the field (an older sender) parses as not pending.
    pushStatus?.(statusFrame({}));
    expect(seen).toEqual([true, false]);
    expect((await bridge.status()).pendingRestart).toBe(false);
  });

  it("reads the tethering offload flag from status replies and pushes", async () => {
    let pushStatus: ((raw: unknown) => void) | undefined;
    const push: PushStreams = {
      subscribeStatus: (cb) => {
        pushStatus = cb;
        return () => {};
      },
      subscribeSubApplied: () => () => {},
      subscribeAssetsUpdated: () => () => {},
    };
    // Unlike pendingRestart, the flag is part of the platform's ServiceState, so
    // the bare status reply carries it.
    const dispatch: Dispatch = vi.fn(async () => ({
      kind: "status",
      value: {
        state: "connected",
        uploadBytes: 0,
        downloadBytes: 0,
        uptimeSec: 1,
        engine: "sing-box",
        tetherOffloadBypass: true,
      },
    })) as Dispatch;
    const bridge = createBridge(dispatch, push);
    expect((await bridge.status()).tetherOffloadBypass).toBe(true);

    const seen: boolean[] = [];
    bridge.onStatus((s) => seen.push(s.tetherOffloadBypass));
    pushStatus?.(statusFrame({ tetherOffloadBypass: true }));
    // An older sender omits it: no warning.
    pushStatus?.(statusFrame({}));
    expect(seen).toEqual([true, false]);
  });
});

describe("dispatch-bridge provider links", () => {
  it("openUrl sends the link to the backend", async () => {
    const dispatch: Dispatch = vi.fn(async () => ({ kind: "ok" }) as Response_Serialize);
    const bridge = createBridge(dispatch, noPush);
    await bridge.openUrl("https://example.org/renew");
    expect(dispatch).toHaveBeenCalledWith({ cmd: "openUrl", url: "https://example.org/renew" });
  });

  it("openUrl rejects when the backend refuses", async () => {
    const dispatch: Dispatch = vi.fn(async () => {
      throw new Error("refusing to open this link");
    });
    const bridge = createBridge(dispatch, noPush);
    await expect(bridge.openUrl("javascript:alert(1)")).rejects.toThrow("refusing");
  });
});

describe("dispatch-bridge request identity", () => {
  const view: ResolvedIdentity = {
    hwid: "0123456789abcdef",
    hwidSource: "happComputed",
    autoHwid: "0123456789abcdef",
    autoHwidSource: "happComputed",
    facts: { os: "Android", osVersion: "16", model: "Pixel 9", locale: "ru-RU" },
    headers: [{ name: "Connection", value: "close" }],
    cookieJar: true,
    locks: { userAgent: false, sendHwid: false, hwidInCookie: false },
    providerHidesDevice: false,
    providerHwidCookie: false,
  };

  it("resolveRequestIdentity sends the sub id and the unsaved input", async () => {
    const dispatch: Dispatch = vi.fn(
      async () => ({ kind: "requestIdentity", value: view }) as Response_Serialize,
    );
    const bridge = createBridge(dispatch, noPush);
    const input = {
      defaults: DEFAULT_ADVANCED_SETTINGS.requestIdentity,
      request: { sendHwid: false },
      userAgent: "",
      client: "happ" as const,
    };
    expect(await bridge.resolveRequestIdentity({ subId: "s1", input })).toEqual(view);
    expect(dispatch).toHaveBeenCalledWith({ cmd: "resolveRequestIdentity", subId: "s1", input });
    await bridge.resolveRequestIdentity({});
    expect(dispatch).toHaveBeenLastCalledWith({
      cmd: "resolveRequestIdentity",
      subId: null,
      input: null,
    });
  });
});

describe("dispatch-bridge import input", () => {
  it("resolveImportInput returns the backend's sorting", async () => {
    const value = {
      subscriptions: [{ url: "happ://crypt5/abc", encrypted: true, name: null, client: "happ" }],
      routing: [],
      unsupported: [{ text: "happ://toggle", kind: "control" as const }],
      shareText: "vless://x",
    };
    const dispatch: Dispatch = vi.fn(
      async () => ({ kind: "importInput", value }) as Response_Serialize,
    );
    const bridge = createBridge(dispatch, noPush);
    expect(await bridge.resolveImportInput("text")).toEqual(value);
    expect(dispatch).toHaveBeenCalledWith({ cmd: "resolveImportInput", text: "text" });
  });

  it("revealSubscriptionUrl asks for the link it was given", async () => {
    const dispatch: Dispatch = vi.fn(
      async () => ({ kind: "text", value: "https://sub.example/s" }) as Response_Serialize,
    );
    const bridge = createBridge(dispatch, noPush);
    expect(await bridge.revealSubscriptionUrl("happ://crypt5/abc")).toBe("https://sub.example/s");
    expect(dispatch).toHaveBeenCalledWith({
      cmd: "revealSubscriptionUrl",
      url: "happ://crypt5/abc",
    });
  });
});

describe("dispatch-bridge route sharing and parsing", () => {
  it("dispatches buildRouteShare and returns route share payload", async () => {
    const payload = {
      exportJson: '{"kasumiRoute": 1}',
      flatJson: "[]",
      namesProfiles: false,
    };
    const dispatch: Dispatch = vi.fn(
      async () => ({ kind: "routeShare", value: payload }) as Response_Serialize,
    );
    const bridge = createBridge(dispatch, noPush);
    const route = { id: "r1", name: "Default" } as Parameters<typeof bridge.buildRouteShare>[0];
    expect(await bridge.buildRouteShare(route, [])).toEqual(payload);
    expect(dispatch).toHaveBeenCalledWith({ cmd: "buildRouteShare", route, blocks: [] });
  });

  it("dispatches parseRoutePackage and returns parsed package or null", async () => {
    const pkg = {
      name: "Default",
      finalOutbound: "proxy",
      blocks: [],
    };
    const dispatch: Dispatch = vi.fn(
      async () => ({ kind: "routePackage", value: pkg }) as Response_Serialize,
    );
    const bridge = createBridge(dispatch, noPush);
    expect(await bridge.parseRoutePackage('{"kasumiRoute": 1}')).toEqual(pkg);
    expect(dispatch).toHaveBeenCalledWith({
      cmd: "parseRoutePackage",
      text: '{"kasumiRoute": 1}',
    });
  });
});

describe("dispatch-bridge backup restore", () => {
  it("sends the backup as one command and returns what the backend left out", async () => {
    const restored = { state: { schemaVersion: 4 }, skippedProfiles: 1 };
    const dispatch: Dispatch = vi.fn(async (cmd) => {
      if (cmd.cmd === "importBackup" && cmd.mode === "merge")
        return { kind: "backupRestored", value: restored } as unknown as Response_Serialize;
      throw new Error(`unexpected command ${cmd.cmd}`);
    });
    const bridge = createBridge(dispatch, noPush);
    const backup = { profiles: [] } as unknown as Parameters<typeof bridge.importBackup>[0];
    await expect(bridge.importBackup(backup, "merge")).resolves.toEqual(restored);
  });
});

describe("dispatch-bridge check readiness", () => {
  it("dispatches checkReadiness with profileId and returns report", async () => {
    const report = {
      profileId: "p1",
      engine: "sing-box" as const,
      ok: true,
      issues: [],
    };
    const dispatch: Dispatch = vi.fn(
      async () => ({ kind: "readiness", value: report }) as Response_Serialize,
    );
    const bridge = createBridge(dispatch, noPush);
    expect(await bridge.checkReadiness("p1")).toEqual(report);
    expect(dispatch).toHaveBeenCalledWith({ cmd: "checkReadiness", profileId: "p1" });

    await bridge.checkReadiness();
    expect(dispatch).toHaveBeenLastCalledWith({ cmd: "checkReadiness", profileId: null });
  });
});
