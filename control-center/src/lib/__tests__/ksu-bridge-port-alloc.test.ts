/**
 * Regression test for the concurrent realPingAll / speedTestAll port-collision
 * bug: when multiple workers called freePorts individually, the backend
 * returned the same port to all of them (TOCTOU — the test core binds its
 * port *after* *Start returns, so the snapshot never changes between calls).
 * The fix is a single `freePorts` call that hands each worker a distinct block
 * from one snapshot.
 *
 * The invariant we check: every worker must receive a unique port for its
 * entire run — no two concurrent workers may share the same SOCKS port.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppState } from "../bridge";

// ── fake app state ───────────────────────────────────────────────────────────

const BASE_SETTINGS = {
  routingMode: "global" as const,
  domainSniffing: true,
  routeOnly: false,
  domainStrategy: "IPIfNonMatch" as const,
  domainStrategy4Singbox: "prefer_ipv4" as const,
  dnsViaProxy: true,
  fakeDns: false,
  preferIpv6: false,
  mux: false,
  muxConcurrency: 8,
  muxXudpConcurrency: 8,
  muxXudp443: "reject" as const,
  fragment: false,
  fragmentPackets: "tlshello" as const,
  mtu: 1350,
  pingConcurrency: 3,
  speedConcurrency: 3, // >1 to trigger the old bug
};

function makeProfile(id: string) {
  return {
    id,
    protocol: "vless" as const,
    remarks: id,
    address: "example.com",
    port: 443,
    groupId: "g-main",
    subId: null,
    ping: null,
    network: "tcp" as const,
    headerType: "none" as const,
    host: "",
    path: "",
    muxEnabled: false,
    security: "tls" as const,
    sni: "",
    disableSni: false,
    fingerprint: "chrome" as const,
    alpn: "",
    allowInsecure: false,
    tlsMinVersion: "",
    tlsMaxVersion: "",
    tlsCipherSuites: "",
    tlsCurvePreferences: "",
    cert: "",
    disableSystemRoot: false,
    publicKey: "",
    shortId: "",
    spiderX: "",
    ech: "",
    vcn: "",
    pcs: "",
    pqv: "",
    flow: "",
    uuid: "00000000-0000-0000-0000-000000000001",
    encryption: "none" as const,
    grpcMode: "",
    serviceName: "",
    authority: "",
    xhttpMode: "",
    xhttpExtra: "",
  };
}

const PROFILES = ["p1", "p2", "p3", "p4", "p5"];

const FAKE_STATE: AppState = {
  profiles: PROFILES.map(makeProfile),
  groups: [{ id: "g-main", name: "Main" }],
  subscriptions: [],
  routingRules: [],
  assetFiles: [],
  settings: BASE_SETTINGS,
  activeId: null,
};

// ── fake backend factory ─────────────────────────────────────────────────────

/**
 * Returns a fresh fake backend per test.
 *
 * Key invariant enforced: `freePorts` reads a *static* snapshot (no ports are
 * pre-occupied). When the old code called freePort per-worker, every worker got
 * the same port back because the snapshot never changed. We detect this by
 * recording every port handed out by *Start and asserting uniqueness.
 */
function makeBackend() {
  // All SOCKS ports handed to *Start calls, in order.
  const assignedPorts: number[] = [];

  function parseCommand(cmd: string): { method: string; args: string[] } {
    const pipeIdx = cmd.lastIndexOf("| ");
    const rest = pipeIdx !== -1 && cmd.includes("base64 -d") ? cmd.slice(pipeIdx + 2) : cmd;
    const trimmed = rest.replace(/^.*kasumi-proxyctl\s+/, "").trim();
    const parts = trimmed.split(/\s+/).map((t) => t.replace(/^'(.*)'$/, "$1"));
    const [method, ...args] = parts;
    return { method, args };
  }

  const execNative = vi.fn(async (cmd: string) => {
    const { method, args } = parseCommand(cmd);

    // freePorts — static snapshot (nothing is bound yet, as on a fresh call)
    if (method === "freePorts") {
      const start = Number(args[0] ?? 19000);
      const count = Number(args[1] ?? 1);
      const span = Number(args[2] ?? 3);
      const ports: number[] = [];
      let p = start;
      while (ports.length < count && p <= 65000 - span) {
        ports.push(p);
        p += span;
      }
      return { errno: 0, stdout: JSON.stringify({ ports }), stderr: "" };
    }

    // *Start — record the SOCKS port the worker actually used
    if (method === "realpingStart" || method === "speedtestStart") {
      assignedPorts.push(Number(args[2]));
      return { errno: 0, stdout: JSON.stringify({ ok: true }), stderr: "" };
    }

    if (method === "realpingStatus")
      return { errno: 0, stdout: JSON.stringify({ state: "done", ms: 50 }), stderr: "" };
    if (method === "speedtestStatus")
      return { errno: 0, stdout: JSON.stringify({ state: "done", bps: 1_000_000 }), stderr: "" };

    if (method === "readState") return { errno: 0, stdout: JSON.stringify(FAKE_STATE), stderr: "" };

    return { errno: 0, stdout: JSON.stringify({ ok: true }), stderr: "" };
  });

  return { execNative, assignedPorts };
}

// ── test suite ───────────────────────────────────────────────────────────────

describe("ksuBridge port allocation", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  async function loadBridge(execNative: ReturnType<typeof vi.fn>) {
    vi.doMock("../ksu-webui", () => ({
      hasKsuNativeApi: () => true,
      hasCgiToken: () => false,
      getRuntimeBridgeMode: () => "ksu",
      getModuleId: () => "kasumi-proxy",
      execNative,
      ksuListApps: vi.fn(async () => []),
    }));
    vi.doMock("../singbox-config", () => ({ buildSingboxConfigJSON: () => '{"fake":"sb"}' }));
    vi.doMock("../xray-config", () => ({ buildXrayConfigJSON: () => '{"fake":"xray"}' }));
    vi.doMock("../schema/settings", () => ({ AppStateSchema: { parse: (v: unknown) => v } }));
    vi.doMock("../schema/core", () => ({ resolveCore: () => "sing-box" }));
    const { ksuBridge } = await import("../ksu-bridge");
    return ksuBridge;
  }

  it("realPingAll: each concurrent worker receives a unique SOCKS port", async () => {
    const { execNative, assignedPorts } = makeBackend();
    const bridge = await loadBridge(execNative);

    const result = await bridge.realPingAll();

    // All 5 profiles must have returned a valid ms value
    for (const id of PROFILES) expect(result[id]).toBe(50);

    // The CONCURRENCY workers each have a fixed port; since workers process
    // profiles sequentially, the same port appears multiple times (once per
    // profile handled by that worker) — but the *set* of distinct ports used
    // must equal CONCURRENCY, never 1 (the old bug: all workers got 19000).
    const distinct = new Set(assignedPorts);
    expect(
      distinct.size,
      `expected ${BASE_SETTINGS.pingConcurrency} distinct ports, got [${[...distinct]}]`,
    ).toBe(BASE_SETTINGS.pingConcurrency);
  });

  it("speedTestAll: each concurrent worker receives a unique SOCKS port", async () => {
    const { execNative, assignedPorts } = makeBackend();
    const bridge = await loadBridge(execNative);

    const result = await bridge.speedTestAll();

    for (const id of PROFILES) expect(result[id]).toBe(1_000_000);

    const distinct = new Set(assignedPorts);
    expect(
      distinct.size,
      `expected ${BASE_SETTINGS.speedConcurrency} distinct ports, got [${[...distinct]}]`,
    ).toBe(BASE_SETTINGS.speedConcurrency);
  });

  it("realPing single: works without pre-allocated port", async () => {
    const { execNative } = makeBackend();
    const bridge = await loadBridge(execNative);
    expect(await bridge.realPing("p1")).toBe(50);
  });
});
