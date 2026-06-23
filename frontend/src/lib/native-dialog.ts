// ============================================================
// src/lib/native-dialog.ts
// Native Tauri file dialogs (open / save) for the desktop shell. Only the Tauri
// webview has these plugins; the Android module and the browser fall back to the
// web behavior at the call site, gated on `nativeDialogsAvailable()`. Plugins are
// lazy-imported so the Android/web bundle never pulls them.
// ============================================================

/** True only inside the Tauri desktop webview (the plugins exist there). */
export function nativeDialogsAvailable(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export type FileFilter = { name: string; extensions: string[] };

/** Native save dialog, then write the contents to the chosen path. Returns true
 * when a file was written, false when the user cancelled. */
export async function saveTextFile(opts: {
  contents: string;
  defaultName: string;
  filters?: FileFilter[];
}): Promise<boolean> {
  const { save } = await import("@tauri-apps/plugin-dialog");
  const path = await save({ defaultPath: opts.defaultName, filters: opts.filters });
  if (!path) return false;
  const { writeTextFile } = await import("@tauri-apps/plugin-fs");
  await writeTextFile(path, opts.contents);
  return true;
}

/** Native open dialog, then read the chosen file. Returns its text, or null when
 * the user cancelled. */
export async function openTextFile(opts?: { filters?: FileFilter[] }): Promise<string | null> {
  const { open } = await import("@tauri-apps/plugin-dialog");
  const path = await open({ multiple: false, directory: false, filters: opts?.filters });
  if (typeof path !== "string") return null;
  const { readTextFile } = await import("@tauri-apps/plugin-fs");
  return readTextFile(path);
}
