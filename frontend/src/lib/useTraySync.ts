// ============================================================
// src/lib/useTraySync.ts
// Keeps the native tray in sync with the UI. Pushes the recent-profile quick-switch
// list, the routing-mode radio state + localized labels to Rust (`update_tray`), and
// separately pushes a live tooltip + state icon (`set_tray_status`) on every status
// tick. Menu clicks come back as `tray-action` events and are routed to the store.
// Desktop-only — a no-op in the Android / browser shells.
// ============================================================

import { useEffect } from "react";
import { commands, events } from "../generated/bindings";
import { ROUTING_MODE_OPTS } from "../generated/defaults";
import { useT } from "../i18n";
import { isServiceUp } from "../lib/bridge";
import { formatRate } from "../lib/format";
import { useAppStore } from "../store/useAppStore";

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// service.state -> the same label key the Overview header shows.
function stateLabelKey(state: string) {
  switch (state) {
    case "connected":
      return "overview.running" as const;
    case "noInternet":
      return "overview.noInternet" as const;
    case "connecting":
      return "overview.connecting" as const;
    case "failed":
      return "overview.failed" as const;
    default:
      return "overview.stopped" as const;
  }
}

export function useTraySync(): void {
  const t = useT();
  const profiles = useAppStore((s) => s.profiles);
  const activeId = useAppStore((s) => s.activeId);
  const recentIds = useAppStore((s) => s.recentProfileIds);
  const service = useAppStore((s) => s.service);
  const uploadRate = useAppStore((s) => s.uploadRate);
  const downloadRate = useAppStore((s) => s.downloadRate);
  const testResults = useAppStore((s) => s.testResults);
  const routingMode = useAppStore((s) => s.settings.routingMode);
  const setActive = useAppStore((s) => s.setActive);
  const setSetting = useAppStore((s) => s.setSetting);
  const toggleService = useAppStore((s) => s.toggleService);
  const restart = useAppStore((s) => s.restart);

  const running = isServiceUp(service.state);
  const connected = service.state === "connected";

  // Rebuild the menu whenever the quick-switch list, active profile, per-profile
  // ping, routing mode, service state, or language changes.
  useEffect(() => {
    if (!isTauri()) return;
    const items = recentIds
      .map((id) => profiles.find((p) => p.meta.id === id))
      .filter((p): p is NonNullable<typeof p> => !!p)
      .map((p) => {
        const name = p.meta.remarks || p.meta.id;
        const ping = testResults[p.meta.id]?.ping;
        return {
          id: p.meta.id,
          name: ping != null && ping >= 0 ? `${name} · ${ping} ms` : name,
          active: p.meta.id === activeId,
        };
      });
    void commands.updateTray(
      items,
      {
        show: t("tray.show"),
        quit: t("tray.quit"),
        start: t("overview.start"),
        stop: t("overview.stop"),
        restart: t("overview.restart"),
        recent: t("tray.recent"),
        routing: t("settings.routingMode"),
        routingGlobal: t("settings.routingGlobal"),
        routingCustom: t("settings.routingCustom"),
        routingRules: t("settings.routingRulesEditor"),
      },
      running,
      connected,
      routingMode,
    );
  }, [profiles, activeId, recentIds, testResults, routingMode, running, connected, t]);

  // Push a live tooltip + state icon on every status tick (cheap — no menu rebuild).
  useEffect(() => {
    if (!isTauri()) return;
    const active = profiles.find((p) => p.meta.id === activeId);
    const activeName = active ? active.meta.remarks || active.meta.id : null;
    const stateLabel = t(stateLabelKey(service.state));
    let tooltip = `Kasumi Proxy — ${stateLabel}`;
    if (activeName) tooltip += ` · ${activeName}`;
    if (running) tooltip += `\n↓ ${formatRate(downloadRate)}  ↑ ${formatRate(uploadRate)}`;
    // The routing submenu writes a setting the running core won't pick up on its own,
    // so the tooltip carries the same restart cue the Overview banner shows.
    if (running && service.pendingRestart) tooltip += `\n${t("overview.pendingRestart")}`;
    void commands.setTrayStatus(tooltip, service.state);
  }, [service, uploadRate, downloadRate, activeId, profiles, running, t]);

  // Route native menu clicks back to the store.
  useEffect(() => {
    if (!isTauri()) return;
    const pending = events.trayAction.listen((e) => {
      const action = e.payload;
      if (action === "start" || action === "stop") void toggleService();
      else if (action === "restart") void restart();
      else if (action.startsWith("activate:")) void setActive(action.slice("activate:".length));
      else if (action.startsWith("routing:")) {
        const mode = ROUTING_MODE_OPTS.find((m) => m === action.slice("routing:".length));
        if (mode) void setSetting("routingMode", mode);
      }
    });
    return () => void pending.then((un) => un()).catch(() => {});
  }, [toggleService, restart, setActive, setSetting]);
}
