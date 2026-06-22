// ============================================================
// src/lib/sheetPresence.ts
// Tracks how many bottom sheets are currently open so chrome
// behind them (e.g. the desktop side rail) can step aside.
// A module-level counter keeps it independent of the app store
// and lets every <Sheet> register itself centrally.
// ============================================================
import { useSyncExternalStore } from "react";

let openCount = 0;
const listeners = new Set<() => void>();

function emit() {
  for (const notify of listeners) notify();
}

/** Mark a sheet as open; call the returned disposer when it closes. */
export function acquireSheet(): () => void {
  openCount += 1;
  emit();
  let released = false;
  return () => {
    if (released) return;
    released = true;
    openCount -= 1;
    emit();
  };
}

/** Reactive: true while at least one bottom sheet is open. */
export function useSheetOpen(): boolean {
  return useSyncExternalStore(
    (notify) => {
      listeners.add(notify);
      return () => listeners.delete(notify);
    },
    () => openCount > 0,
    () => false,
  );
}
