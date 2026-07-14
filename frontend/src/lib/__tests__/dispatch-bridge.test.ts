import { describe, expect, it, vi } from "vitest";
import type { Profile, Response_Serialize } from "../../generated/bindings";
import type { AppState } from "../bridge";
import { createBridge, type Dispatch, type PushStreams } from "../dispatch-bridge";

const noPush: PushStreams = {
  subscribeStatus: () => () => {},
  subscribeSubApplied: () => () => {},
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
});
