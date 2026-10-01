// ============================================================
// src/lib/autostart.ts
// "Start with the system" for the desktop app — the shell's autostart
// commands. This is OS-level autostart of the Tauri app itself (an XDG
// autostart entry / Run key), started in the tray; distinct from the proxy
// service's own `autoStart` setting. Only available in the Tauri shell; the
// Android WebUI has no equivalent, so `autostartSupported()` gates the UI.
// ============================================================

/** True only inside the Tauri desktop webview (the commands exist there). */
export function autostartSupported(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Whether the app is registered to launch on login (false where unsupported). */
export async function isAutostartEnabled(): Promise<boolean> {
  if (!autostartSupported()) return false;
  const { commands } = await import("../generated/bindings");
  return commands.autostartEnabled();
}

/** Register/unregister the app to launch on login. No-op where unsupported. */
export async function setAutostartEnabled(on: boolean): Promise<void> {
  if (!autostartSupported()) return;
  const { commands } = await import("../generated/bindings");
  const res = await commands.setAutostart(on);
  if (res.status === "error") throw new Error(res.error);
}
