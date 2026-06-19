// ============================================================
// src/lib/autostart.ts
// "Launch on login" for the desktop app — a thin wrapper over
// @tauri-apps/plugin-autostart. This is OS-level autostart of the Tauri app
// itself (a LaunchAgent / XDG autostart entry), distinct from the proxy
// service's own `autoStart` setting. Only available in the Tauri shell; the
// Android WebUI has no equivalent, so `autostartSupported()` gates the UI.
// ============================================================

/** True only inside the Tauri desktop webview (the plugin exists there). */
export function autostartSupported(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Whether the app is registered to launch on login (false where unsupported). */
export async function isAutostartEnabled(): Promise<boolean> {
  if (!autostartSupported()) return false;
  const { isEnabled } = await import("@tauri-apps/plugin-autostart");
  return isEnabled();
}

/** Register/unregister the app to launch on login. No-op where unsupported. */
export async function setAutostartEnabled(on: boolean): Promise<void> {
  if (!autostartSupported()) return;
  const { enable, disable } = await import("@tauri-apps/plugin-autostart");
  await (on ? enable() : disable());
}
