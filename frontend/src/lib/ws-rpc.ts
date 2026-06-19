// ============================================================
// src/lib/ws-rpc.ts
// WebSocket transport to the kasumi-proxy daemon (Android module). One persistent
// loopback socket carries the typed Command/Response envelope plus server-pushed
// status: a request is `{ id, ...Command }`, a reply `{ id, ok, value: Response,
// error }`, a push `{ event, value }`. Bootstrap (port + token) comes from one
// ksu.exec `kasumi-proxy wsInfo` in the manager WebUI, or the page's own origin +
// token query when the daemon serves the page itself (browser via action.sh).
// ============================================================

import type { Command, Response, WsInfo } from "../generated/bindings";
import { execNative, getModuleId, hasKsuNativeApi } from "./ksu-webui";

/** A daemon → client frame: an id-correlated reply or an event-tagged push. */
interface ReplyFrame {
  id?: number;
  ok?: boolean;
  value?: Response;
  error?: string;
  event?: string;
}

const RPC_TIMEOUT_MS = 90_000;

let socket: WebSocket | null = null;
let connecting: Promise<WebSocket> | null = null;
let nextId = 1;
const pending = new Map<number, { resolve: (v: Response) => void; reject: (e: Error) => void }>();
const statusCbs = new Set<(status: unknown) => void>();
const subAppliedCbs = new Set<(info: unknown) => void>();

/** Resolve the daemon's WS URL: ksu.exec wsInfo in the manager WebUI, the page's
 *  own origin + token query on a daemon-served page (browser). */
async function endpoint(): Promise<string> {
  if (hasKsuNativeApi()) {
    const ctl = `/data/adb/modules/${getModuleId("kasumi-proxy")}/bin/kasumi-proxy`;
    const { errno, stdout, stderr } = await execNative(`${ctl} wsInfo`);
    if (errno !== 0) throw new Error(stderr.trim() || "wsInfo failed");
    // The CLI prints the typed Response envelope `{ kind: "wsInfo", value: {...} }`;
    // unwrap it (older builds printed the bare WsInfo, so accept both).
    const parsed = JSON.parse(stdout.trim()) as WsInfo | { kind: string; value: WsInfo };
    const { port, token } = "value" in parsed ? parsed.value : parsed;
    return `ws://127.0.0.1:${port}/ws?token=${encodeURIComponent(token)}`;
  }
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const token = new URLSearchParams(location.search).get("token") ?? "";
  return `${proto}//${location.host}/ws?token=${encodeURIComponent(token)}`;
}

function handleMessage(ev: MessageEvent): void {
  let msg: ReplyFrame;
  try {
    msg = JSON.parse(typeof ev.data === "string" ? ev.data : "") as ReplyFrame;
  } catch {
    return;
  }
  if (msg.event === "status") {
    for (const cb of statusCbs) cb(msg.value);
    return;
  }
  if (msg.event === "subApplied") {
    for (const cb of subAppliedCbs) cb(msg.value);
    return;
  }
  if (typeof msg.id !== "number") return;
  const waiter = pending.get(msg.id);
  if (!waiter) return;
  pending.delete(msg.id);
  if (msg.ok && msg.value) waiter.resolve(msg.value);
  else waiter.reject(new Error(msg.error ?? "rpc failed"));
}

function onClose(): void {
  socket = null;
  connecting = null;
  for (const { reject } of pending.values()) reject(new Error("connection closed"));
  pending.clear();
  // Keep the push streams alive: reconnect lazily if anyone is still listening.
  if (statusCbs.size > 0 || subAppliedCbs.size > 0) {
    setTimeout(() => void ensureSocket().catch(() => {}), 1000);
  }
}

async function ensureSocket(): Promise<WebSocket> {
  if (socket && socket.readyState === WebSocket.OPEN) return socket;
  if (connecting) return connecting;
  connecting = (async () => {
    const url = await endpoint();
    const ws = new WebSocket(url);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => resolve(), { once: true });
      ws.addEventListener("error", () => reject(new Error("WebSocket connect failed")), {
        once: true,
      });
    });
    ws.addEventListener("message", handleMessage);
    ws.addEventListener("close", onClose);
    socket = ws;
    connecting = null;
    return ws;
  })();
  connecting.catch(() => {
    connecting = null;
  });
  return connecting;
}

/** Send one typed command and await its typed reply (or reject on a daemon error). */
export async function wsDispatch(cmd: Command): Promise<Response> {
  const ws = await ensureSocket();
  const id = nextId++;
  return new Promise<Response>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`rpc ${(cmd as { cmd: string }).cmd} timed out`));
    }, RPC_TIMEOUT_MS);
    pending.set(id, {
      resolve: (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      reject: (e) => {
        clearTimeout(timer);
        reject(e);
      },
    });
    ws.send(JSON.stringify({ id, ...cmd }));
  });
}

/** Subscribe to server-pushed status. Returns an unsubscribe function. */
export function subscribeStatus(cb: (status: unknown) => void): () => void {
  statusCbs.add(cb);
  void ensureSocket().catch(() => {});
  return () => {
    statusCbs.delete(cb);
  };
}

/** Subscribe to the daemon's "subscription applied" push. Returns an unsubscribe. */
export function subscribeSubApplied(cb: (info: unknown) => void): () => void {
  subAppliedCbs.add(cb);
  void ensureSocket().catch(() => {});
  return () => {
    subAppliedCbs.delete(cb);
  };
}
