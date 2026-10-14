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
  beat(intervalMs: number) {
    this.emit("message", { data: JSON.stringify({ event: "heartbeat", value: { intervalMs } }) });
  }
  sent: { id: number }[] = [];
  send(data: string) {
    this.sent.push(JSON.parse(data) as { id: number });
  }
  reply(id: number, value: unknown) {
    this.emit("message", { data: JSON.stringify({ id, ok: true, value }) });
  }
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

  it("a socket closing after its replacement opened leaves the replacement alone", async () => {
    const { subscribeStatus, wsDispatch } = await import("../ws-rpc");
    subscribeStatus(() => {});
    await settle();
    const first = last();
    first.open();
    await settle();

    // Still closing when a request asks for a socket: a new one takes over.
    first.readyState = 2;
    let settled = false;
    void wsDispatch({ cmd: "status" } as never).then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await settle();
    expect(FakeSocket.instances).toHaveLength(2);
    last().open();
    await settle();

    first.close();
    await vi.advanceTimersByTimeAsync(10_000);
    // No reconnect, and the request on the new socket is still waiting for its reply.
    expect(FakeSocket.instances).toHaveLength(2);
    expect(settled).toBe(false);
  });

  it("a request waits as long as the daemon keeps beating", async () => {
    const { subscribeStatus, wsDispatch } = await import("../ws-rpc");
    subscribeStatus(() => {});
    await settle();
    const ws = last();
    ws.open();
    await settle();
    ws.beat(10_000);

    const reply = wsDispatch({ cmd: "status" } as never);
    await settle();
    // Five minutes of work, well past any fixed timeout.
    for (let i = 0; i < 30; i++) {
      await vi.advanceTimersByTimeAsync(10_000);
      ws.beat(10_000);
    }
    ws.reply(ws.sent[0].id, { kind: "ok" });
    await expect(reply).resolves.toEqual({ kind: "ok" });
    expect(FakeSocket.instances).toHaveLength(1);
  });

  it("a socket that falls silent fails its requests and reconnects", async () => {
    const { subscribeStatus, wsDispatch } = await import("../ws-rpc");
    subscribeStatus(() => {});
    await settle();
    last().open();
    await settle();
    last().beat(10_000);

    const reply = wsDispatch({ cmd: "status" } as never);
    const failed = expect(reply).rejects.toThrow("the daemon stopped responding");
    await vi.advanceTimersByTimeAsync(29_000);
    expect(FakeSocket.instances).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1_000);
    await failed;
    await vi.advanceTimersByTimeAsync(1_000);
    expect(FakeSocket.instances).toHaveLength(2);
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
