// ============================================================
// src/lib/ws-bridge.ts
// The Android Bridge: the typed Command/Response travels over the daemon's
// WebSocket (ws-rpc.ts); the shared dispatch-bridge does the rest. Two methods
// take the native KSU WebUI path over the daemon's: the labelled+iconed app list,
// and the runtime bridge-mode tag in capabilities.
// ============================================================

import type { Bridge } from "./bridge";
import { createBridge } from "./dispatch-bridge";
import { getRuntimeBridgeMode, hasKsuNativeApi, ksuListApps } from "./ksu-webui";
import { subscribeStatus, subscribeSubApplied, wsDispatch } from "./ws-rpc";

const base = createBridge(wsDispatch, { subscribeStatus, subscribeSubApplied });

export const wsBridge: Bridge = {
  ...base,
  async capabilities() {
    // The daemon reports its own bridge tag; the WebUI knows the real runtime (ksu).
    return { ...(await base.capabilities()), bridge: getRuntimeBridgeMode() };
  },
  async listApps() {
    // Prefer the native app list (labels + icons); fall back to the daemon's.
    if (hasKsuNativeApi()) return ksuListApps();
    return base.listApps();
  },
};
