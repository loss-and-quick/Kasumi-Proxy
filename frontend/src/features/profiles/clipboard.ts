// ============================================================
// src/features/profiles/clipboard.ts
// Clipboard read/write. Uses the native Tauri clipboard under the desktop shell
// (more reliable than the WebView's navigator.clipboard), falling back to the web
// Clipboard API in the Android / browser shells. The plugin is lazy-imported so
// the non-Tauri bundle never pulls it.
// ============================================================

function nativeClipboard(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Write text to the clipboard. Returns true on success. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (nativeClipboard()) {
      const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
      await writeText(text);
      return true;
    }
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Read text from the clipboard, or null if unavailable / denied. */
export async function readText(): Promise<string | null> {
  try {
    if (nativeClipboard()) {
      const { readText: read } = await import("@tauri-apps/plugin-clipboard-manager");
      return await read();
    }
    return await navigator.clipboard.readText();
  } catch {
    return null;
  }
}
