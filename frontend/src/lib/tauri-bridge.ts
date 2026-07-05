// ============================================================
// src/lib/tauri-bridge.ts
// The desktop Bridge: the typed Command/Response travels over native Tauri IPC
// (`invoke("dispatch", { cmd })`) and the status / subApplied pushes arrive as
// typed Tauri events. Everything is the generated binding surface
// (src/generated/bindings.ts); the shared dispatch-bridge does the rest.
// ============================================================

import { commands, events } from "../generated/bindings";
import type { Bridge } from "./bridge";
import { createBridge, type Dispatch, type PushStreams } from "./dispatch-bridge";

// `commands.dispatch` already speaks the phases `Dispatch` uses
// (`Command_Deserialize` in, `Response_Serialize` out), so the command and reply
// pass through untouched.
const dispatch: Dispatch = async (cmd) => {
  const res = await commands.dispatch(cmd);
  if (res.status === "error") throw new Error(res.error);
  return res.data;
};

/** Bridge a tauri-specta event's promise-returning `listen` to a sync unsubscribe. */
function listen<T>(
  channel: { listen: (cb: (e: { payload: T }) => void) => Promise<() => void> },
  cb: (payload: T) => void,
): () => void {
  const pending = channel.listen((e) => cb(e.payload));
  return () => void pending.then((un) => un()).catch(() => {});
}

const push: PushStreams = {
  subscribeStatus(cb) {
    return listen(events.statusChanged, (payload) => cb(payload));
  },
  subscribeSubApplied(cb) {
    return listen(events.subscriptionApplied, (payload) => cb(payload));
  },
};

export const tauriBridge: Bridge = createBridge(dispatch, push);
