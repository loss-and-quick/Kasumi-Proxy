import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../ksu-webui", () => ({
  hasKsuNativeApi: () => true,
  getModuleId: () => "kasumi-proxy",
  execNative: async () => ({
    errno: 0,
    stdout: JSON.stringify({ kind: "wsInfo", value: { port: 1, token: "t" } }),
    stderr: "",
  }),
}));

/** A WebSocket the test opens, fails or closes by hand. */
class FakeSocket {
  static instances: FakeSocket[] = [];
  static readonly OPEN = 1;
  readyState = 0;
  private handlers = new Map<string, ((ev: unknown) => void)[]>();
  constructor(readonly url: string) {
    FakeSocket.instances.push(this);
  }
  addEventListener(type: string, fn: (ev: unknown) => void) {
    this.handlers.set(type, [...(this.handlers.get(type) ?? []), fn]);
  }
  private emit(type: string, ev: unknown = {}) {
    for (const fn of this.handlers.get(type) ?? []) fn(ev);
  }
  open() {
    this.readyState = FakeSocket.OPEN;
    this.emit("open");
  }
  fail() {
    this.emit("error");
  }
  close() {
    this.readyState = 3;
    this.emit("close");
  }
  push(value: unknown) {
    this.emit("message", { data: JSON.stringify({ event: "status", value }) });
  }
  send() {}
}

const last = () => FakeSocket.instances[FakeSocket.instances.length - 1];
// Lets the wsInfo lookup and the socket construction behind it run.
const settle = () => vi.advanceTimersByTimeAsync(0);

describe("ws-rpc push stream", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.resetModules();
    FakeSocket.instances = [];
    vi.stubGlobal("WebSocket", FakeSocket);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("keeps retrying with backoff until the daemon answers", async () => {
    const { subscribeStatus } = await import("../ws-rpc");
    const seen: unknown[] = [];
    subscribeStatus((s) => seen.push(s));

    await settle();
    last().fail();
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.instances).toHaveLength(2);
    last().fail();
    // The second retry waits twice as long.
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.instances).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.instances).toHaveLength(3);
    last().open();
    await settle();

    last().push({ uptimeSec: 7 });
    expect(seen).toEqual([{ uptimeSec: 7 }]);
  });

  it("doesn't reconnect once nobody listens", async () => {
    const { subscribeStatus } = await import("../ws-rpc");
    const unsubscribe = subscribeStatus(() => {});
    await settle();
    last().open();
    await settle();

    last().close();
    unsubscribe();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(FakeSocket.instances).toHaveLength(1);
  });

  it("reconnects after a drop, back on the short delay", async () => {
    const { subscribeStatus } = await import("../ws-rpc");
    subscribeStatus(() => {});
    await settle();
    last().open();
    await settle();

    last().close();
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.instances).toHaveLength(2);
    last().open();
    await settle();
    last().close();
    await vi.advanceTimersByTimeAsync(1000);
    expect(FakeSocket.instances).toHaveLength(3);
  });
});
