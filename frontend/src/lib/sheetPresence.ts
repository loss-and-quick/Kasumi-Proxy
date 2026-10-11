// ============================================================
// src/lib/sheetPresence.ts
// Tracks bottom sheets in a stack so:
// 1. Chrome behind them (e.g. desktop side rail) can step aside.
// 2. When multiple sheets are open at once, only the topmost one
//    is visible; background sheets are hidden without unmounting
//    (preserving form state, scroll position, etc.) and restore
//    automatically when the top sheet closes.
// ============================================================
import { useSyncExternalStore } from "react";

const stack: string[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function emit() {
  for (const notify of listeners) notify();
}

/** Register a sheet in the stack; returns an id and a cleanup disposer. */
export function registerSheet(): { id: string; release: () => void } {
  const id = `sheet-${nextId++}`;
  stack.push(id);
  emit();
  let released = false;
  return {
    id,
    release: () => {
      if (released) return;
      released = true;
      const idx = stack.indexOf(id);
      if (idx !== -1) stack.splice(idx, 1);
      emit();
    },
  };
}

/** Reactive: true while at least one bottom sheet is open. */
export function useSheetOpen(): boolean {
  return useSyncExternalStore(
    (notify) => {
      listeners.add(notify);
      return () => listeners.delete(notify);
    },
    () => stack.length > 0,
    () => false,
  );
}

/** Reactive: true if this sheet is currently the topmost in the stack. */
export function useIsTopSheet(id: string | null): boolean {
  return useSyncExternalStore(
    (notify) => {
      listeners.add(notify);
      return () => listeners.delete(notify);
    },
    () => id !== null && stack.length > 0 && stack[stack.length - 1] === id,
    () => false,
  );
}
