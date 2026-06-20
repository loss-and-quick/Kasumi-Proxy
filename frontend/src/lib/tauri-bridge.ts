// ============================================================
// src/lib/tauri-bridge.ts
// The desktop Bridge: the typed Command/Response travels over native Tauri IPC
// (`invoke("dispatch", { cmd })`) and the status / subApplied pushes arrive as
// typed Tauri events. Everything is the generated binding surface
// (src/generated/bindings.ts); the shared dispatch-bridge does the rest.
// ============================================================

import type { Command, Response } from "../generated/bindings";
import { commands, events } from "../generated/bindings";
import type { Bridge } from "./bridge";
import { createBridge, type Dispatch, type PushStreams } from "./dispatch-bridge";

const dispatch: Dispatch = async (cmd: Command): Promise<Response> => {
  // The generated command typed-wraps its arg as the deserialize shape; the values
  // we build satisfy it structurally.
  const res = await commands.dispatch(cmd as Parameters<typeof commands.dispatch>[0]);
  if (res.status === "error") throw new Error(res.error);
  return res.data as Response;
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
