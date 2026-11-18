// ============================================================
// src/lib/updater.ts
// Desktop version + auto-update — a thin wrapper over @tauri-apps/plugin-updater
// + @tauri-apps/plugin-process. Only the Tauri desktop shell exposes app version
// and update policy; in-app self-update is additionally restricted to builds
// whose `updatePolicy()` is `"selfUpdate"` (Linux AppImage and installed Windows
// builds). Externally managed packages (RPM, DEB, Nix) and portable zips never
// invoke the updater plugin. Plugins are lazy-imported so the Android/web bundle
// never pulls them.
// ============================================================

import type { Update } from "@tauri-apps/plugin-updater";
import type { UpdatePolicy } from "../generated/bindings";

export type { UpdatePolicy };

/** True only inside the Tauri desktop webview (the desktop commands exist there). */
export function updateSupported(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** The running app's version (from the backend), or null outside desktop. */
export async function currentVersion(): Promise<string | null> {
  if (!updateSupported()) return null;
  const { commands } = await import("../generated/bindings");
  return commands.appVersion();
}

/** Whether the running installation can self-update, or why the updater is off. */
export async function getUpdatePolicy(): Promise<UpdatePolicy | null> {
  if (!updateSupported()) return null;
  const { commands } = await import("../generated/bindings");
  return commands.updatePolicy();
}

/** Query the release endpoint; returns the pending update or null if up to date
 * or if the running installation does not support self-update. */
export async function checkForUpdate(): Promise<Update | null> {
  if ((await getUpdatePolicy()) !== "selfUpdate") return null;
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
