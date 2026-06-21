// ============================================================
// src/lib/updater.ts
// Desktop auto-update — a thin wrapper over @tauri-apps/plugin-updater +
// @tauri-apps/plugin-process. Only the Tauri shell has these plugins; the
// Android module is updated by the root manager, so `updateSupported()` gates the
// whole UI. Plugins are lazy-imported so the Android/web bundle never pulls them.
// ============================================================

import type { Update } from "@tauri-apps/plugin-updater";

/** True only inside the Tauri desktop webview (the plugins exist there). */
export function updateSupported(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** The running app's version (from the backend), or null where unsupported. */
export async function currentVersion(): Promise<string | null> {
  if (!updateSupported()) return null;
  const { commands } = await import("../generated/bindings");
  return commands.appVersion();
}

/** Query the release endpoint; returns the pending update or null if up to date. */
export async function checkForUpdate(): Promise<Update | null> {
  if (!updateSupported()) return null;
  const { check } = await import("@tauri-apps/plugin-updater");
  return check();
}

export type DownloadProgress = { downloaded: number; total: number | null };

/** Download + install the update (signature verified against the bundled pubkey),
 * then relaunch into the new version. */
export async function installUpdate(
  update: Update,
  onProgress?: (p: DownloadProgress) => void,
): Promise<void> {
  let downloaded = 0;
  let total: number | null = null;
  await update.downloadAndInstall((e) => {
    if (e.event === "Started") {
      total = e.data.contentLength ?? null;
    } else if (e.event === "Progress") {
      downloaded += e.data.chunkLength;
      onProgress?.({ downloaded, total });
    }
  });
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
