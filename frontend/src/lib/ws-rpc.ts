// ============================================================
// src/lib/ws-rpc.ts
// WebSocket transport to the kasumi-proxy daemon (Android module). One persistent
// loopback socket carries the typed Command/Response envelope plus server-pushed
// status: a request is `{ id, ...Command }`, a reply `{ id, ok, value: Response,
// error }`, a push `{ event, value }`. Bootstrap (port + token) comes from one
// ksu.exec `kasumi-proxy wsInfo` in the manager WebUI, or the page's own origin +
// token query when the daemon serves the page itself (browser via action.sh).
// ============================================================

import type { Command_Deserialize, Response_Serialize, WsInfo } from "../generated/bindings";
import { WS_HEARTBEAT_MS } from "../generated/defaults";
import { execNative, getModuleId, hasKsuNativeApi } from "./ksu-webui";
import { logDebug, logWarn } from "./logger";

/** A daemon → client frame: an id-correlated reply or an event-tagged push. */
interface ReplyFrame {
  id?: number;
  ok?: boolean;
  value?: Response_Serialize;
  error?: string;
  event?: string;
}

/** How long a socket may stay silent before it counts as dead: three missed
 *  heartbeats. */
const SILENCE_LIMIT_MS = WS_HEARTBEAT_MS * 3;

let socket: WebSocket | null = null;
let connecting: Promise<WebSocket> | null = null;
let nextId = 1;
const pending = new Map<
  number,
  {
    socket: WebSocket;
    resolve: (v: Response_Serialize) => void;
    reject: (e: Error) => void;
  }
>();
const statusCbs = new Set<(status: unknown) => void>();
const subAppliedCbs = new Set<(info: unknown) => void>();
const assetsUpdatedCbs = new Set<(info: unknown) => void>();

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

let silenceTimer: ReturnType<typeof setTimeout> | null = null;

/** Restart the silence check. A request has no timeout of its own, since the daemon
 *  bounds its own work: it fails when its socket closes, or when the socket stays
 *  silent past the limit and so is dead even if the OS never reports it. */
function noteAlive(ws: WebSocket): void {
  if (ws !== socket) return;
  if (silenceTimer) clearTimeout(silenceTimer);
  silenceTimer = setTimeout(() => {
    silenceTimer = null;
    // A hidden page's frames may just be held back; judge it once it shows again.
    if (typeof document !== "undefined" && document.visibilityState === "hidden") {
      noteAlive(ws);
      return;
    }
    // The one failure the UI cannot explain on its own.
    logWarn("ws: the daemon stopped answering", { silentMs: SILENCE_LIMIT_MS });
    onClose(ws, "the daemon stopped responding");
    ws.close();
  }, SILENCE_LIMIT_MS);
}

function handleMessage(ws: WebSocket, ev: MessageEvent): void {
  noteAlive(ws);
  let msg: ReplyFrame;
  try {
    msg = JSON.parse(typeof ev.data === "string" ? ev.data : "") as ReplyFrame;
  } catch {
    // Our own daemon sends JSON; a frame that is not is either a stray version or
    // something else on the port. Nothing can be done about it here.
    logDebug("ws: dropped a frame that is not JSON");
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
  if (msg.event === "assetsUpdated") {
    for (const cb of assetsUpdatedCbs) cb(msg.value);
    return;
  }
  if (typeof msg.id !== "number") return;
  const waiter = pending.get(msg.id);
  if (!waiter) return;
  pending.delete(msg.id);
  if (msg.ok && msg.value) waiter.resolve(msg.value);
  else waiter.reject(new Error(msg.error ?? "rpc failed"));
}

const RECONNECT_FIRST_MS = 1000;
const RECONNECT_MAX_MS = 10_000;
let reconnectDelay = RECONNECT_FIRST_MS;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

const hasListeners = () =>
  statusCbs.size > 0 || subAppliedCbs.size > 0 || assetsUpdatedCbs.size > 0;

/** Keep the push streams alive: while anyone listens, retry until a socket opens.
 *  One failed attempt (the daemon restarting, `wsInfo` not answering while the
 *  WebView sat in the background) must not leave the status frozen. */
function scheduleReconnect(): void {
  if (reconnectTimer || !hasListeners()) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    // Everyone may have unsubscribed while it waited.
    if (!hasListeners()) return;
    ensureSocket().catch(() => {
      reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
      logDebug("ws: reconnect failed", { nextAttemptMs: reconnectDelay });
      scheduleReconnect();
    });
  }, reconnectDelay);
}

/** A closing socket settles only what it owns: one replaced while it was still
 *  closing must not drop the socket that took over. */
function onClose(closed: WebSocket, reason = "connection closed"): void {
  let dropped = 0;
  for (const [id, waiter] of pending) {
    if (waiter.socket !== closed) continue;
    waiter.reject(new Error(reason));
    pending.delete(id);
    dropped += 1;
  }
  // The callers that were waiting get an error they may show, but only the socket's
  // own log says how many calls a close took down.
  if (dropped > 0) {
    logDebug("ws: the socket closed with calls in flight", { dropped });
  }
  if (socket !== closed) return;
  socket = null;
  if (silenceTimer) {
    clearTimeout(silenceTimer);
    silenceTimer = null;
  }
  scheduleReconnect();
}

// A page brought back to the front reconnects at once instead of on the backoff.
if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible" || !hasListeners()) return;
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    void ensureSocket().catch(() => scheduleReconnect());
  });
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
    ws.addEventListener("message", (ev) => handleMessage(ws, ev));
    ws.addEventListener("close", () => onClose(ws));
    socket = ws;
    noteAlive(ws);
    connecting = null;
    reconnectDelay = RECONNECT_FIRST_MS;
    return ws;
  })();
  connecting.catch(() => {
    connecting = null;
  });
  return connecting;
}

/** Send one typed command and await its typed reply (or reject on a daemon error). */
export async function wsDispatch(cmd: Command_Deserialize): Promise<Response_Serialize> {
  const ws = await ensureSocket();
  const id = nextId++;
  return new Promise<Response_Serialize>((resolve, reject) => {
    pending.set(id, { socket: ws, resolve, reject });
    ws.send(JSON.stringify({ id, ...cmd }));
  });
}

/** Subscribe to server-pushed status. Returns an unsubscribe function. */
export function subscribeStatus(cb: (status: unknown) => void): () => void {
  statusCbs.add(cb);
  void ensureSocket().catch(() => scheduleReconnect());
  return () => {
    statusCbs.delete(cb);
  };
}

/** Subscribe to the daemon's "subscription applied" push. Returns an unsubscribe. */
export function subscribeSubApplied(cb: (info: unknown) => void): () => void {
  subAppliedCbs.add(cb);
  void ensureSocket().catch(() => scheduleReconnect());
  return () => {
    subAppliedCbs.delete(cb);
  };
}

/** Subscribe to the daemon's "geo assets updated" push. Returns an unsubscribe. */
export function subscribeAssetsUpdated(cb: (info: unknown) => void): () => void {
  assetsUpdatedCbs.add(cb);
  void ensureSocket().catch(() => scheduleReconnect());
  return () => {
    assetsUpdatedCbs.delete(cb);
  };
}
