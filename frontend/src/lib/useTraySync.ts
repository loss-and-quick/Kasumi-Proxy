// ============================================================
// src/lib/useTraySync.ts
// Keeps the native tray menu in sync with the UI: pushes the recent-profile
// quick-switch list + localized labels to Rust (`update_tray`), and routes menu
// clicks (`tray-action` events) back to the store. Desktop-only — a no-op in the
// Android / browser shells.
// ============================================================

import { useEffect } from "react";
import { commands, events } from "../generated/bindings";
import { useT } from "../i18n";
import { useAppStore } from "../store/useAppStore";

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function useTraySync(): void {
  const t = useT();
  const profiles = useAppStore((s) => s.profiles);
  const activeId = useAppStore((s) => s.activeId);
  const recentIds = useAppStore((s) => s.recentProfileIds);
  const setActive = useAppStore((s) => s.setActive);
  const restart = useAppStore((s) => s.restart);

  // Rebuild the menu whenever the quick-switch list, active profile, or language
  // changes.
  useEffect(() => {
    if (!isTauri()) return;
    const items = recentIds
      .map((id) => profiles.find((p) => p.meta.id === id))
      .filter((p): p is NonNullable<typeof p> => !!p)
      .map((p) => ({
        id: p.meta.id,
        name: p.meta.remarks || p.meta.id,
        active: p.meta.id === activeId,
      }));
    void commands.updateTray(items, {
      show: t("tray.show"),
      quit: t("tray.quit"),
      restart: t("overview.restart"),
      recent: t("tray.recent"),
    });
  }, [profiles, activeId, recentIds, t]);

  // Route native menu clicks back to the store.
  useEffect(() => {
    if (!isTauri()) return;
    const pending = events.trayAction.listen((e) => {
      const action = e.payload;
      if (action === "restart") void restart();
      else if (action.startsWith("activate:")) void setActive(action.slice("activate:".length));
    });
    return () => void pending.then((un) => un()).catch(() => {});
  }, [restart, setActive]);
}
