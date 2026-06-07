// ============================================================
// src/lib/bridge-provider.ts
// Selects the bridge implementation based on the environment.
//  - Real device (KernelSU/APatch JS interface or token CGI) → ksuBridge
//  - Desktop/browser dev → mockBridge
// Override with VITE_BRIDGE_MODE = "ksu" | "mock".
// ============================================================
import type { Bridge } from "./bridge";
import { getRuntimeBridgeMode } from "./ksu-webui";

type BridgeMode = "ksu" | "mock";

let loadedBridge: Bridge | null = null;
let loadingBridge: Promise<Bridge> | null = null;

function pickMode(): BridgeMode {
  const mode = import.meta.env.VITE_BRIDGE_MODE;
  if (mode === "mock" || mode === "ksu") return mode;
  return getRuntimeBridgeMode() === "mock" ? "mock" : "ksu";
}

async function loadBridge(): Promise<Bridge> {
  if (loadedBridge) return loadedBridge;
  if (!loadingBridge) {
    loadingBridge =
      pickMode() === "ksu"
        ? import("./ksu-bridge").then((module) => module.ksuBridge)
        : import("./mock-bridge").then((module) => module.mockBridge);
    loadingBridge = loadingBridge.then((bridge) => {
      loadedBridge = bridge;
      return bridge;
    });
  }
  return loadingBridge;
}

export const bridge: Bridge = {
  async start(profileId) {
    return (await loadBridge()).start(profileId);
  },
  async stop() {
    return (await loadBridge()).stop();
  },
  async restart() {
    return (await loadBridge()).restart();
  },
  async status() {
    return (await loadBridge()).status();
  },
  onStatus(cb) {
    let unsubscribed = false;
    let dispose: (() => void) | null = null;

    void loadBridge().then((impl) => {
      if (unsubscribed) return;
      dispose = impl.onStatus(cb);
    });

    return () => {
      unsubscribed = true;
      dispose?.();
    };
  },
  async capabilities() {
    return (await loadBridge()).capabilities();
  },
  async ping(profileId) {
    return (await loadBridge()).ping(profileId);
  },
  async pingAll() {
    return (await loadBridge()).pingAll();
  },
  async realPing(profileId) {
    return (await loadBridge()).realPing(profileId);
  },
  async realPingAll() {
    return (await loadBridge()).realPingAll();
  },
  async speedTest(profileId) {
    return (await loadBridge()).speedTest(profileId);
  },
  async speedTestAll() {
    return (await loadBridge()).speedTestAll();
  },
  async log(input) {
    return (await loadBridge()).log(input);
  },
  async clearLogs() {
    return (await loadBridge()).clearLogs();
  },
  async readState() {
    return (await loadBridge()).readState();
  },
  async writeState(state) {
    return (await loadBridge()).writeState(state);
  },
  async fetchSubscription(url, opts) {
    return (await loadBridge()).fetchSubscription(url, opts);
  },
  async downloadAsset(filename, url, mode) {
    return (await loadBridge()).downloadAsset(filename, url, mode);
  },
  async listAssets() {
    return (await loadBridge()).listAssets();
  },
  async listApps() {
    return (await loadBridge()).listApps();
  },
  async reloadAppFilter() {
    return (await loadBridge()).reloadAppFilter();
  },
  async parseShareLinks(text) {
    return (await loadBridge()).parseShareLinks(text);
  },
  async buildShareLink(profile) {
    return (await loadBridge()).buildShareLink(profile);
  },
  async exportBackup() {
    return (await loadBridge()).exportBackup();
  },
  async importBackup(file, mode) {
    return (await loadBridge()).importBackup(file, mode);
  },
};
