// ============================================================
// src/lib/useEscapeToClose.ts
// Close-on-Escape for overlays (sheets, dialogs). A shared LIFO
// stack makes a single Escape dismiss only the top-most overlay,
// so stacked sheets/dialogs peel off one at a time. Handlers that
// already consumed Escape (a dropdown menu, an inline rename) call
// preventDefault, and we skip those so the overlay stays open.
// ============================================================
import { useEffect, useRef } from "react";

const stack: Array<() => void> = [];

function onKeyDown(e: KeyboardEvent) {
  if (e.key !== "Escape" || e.defaultPrevented || stack.length === 0) return;
  e.preventDefault();
  stack[stack.length - 1]();
}

/** While `active`, register `onClose` so Escape dismisses this overlay first. */
export function useEscapeToClose(active: boolean, onClose: () => void): void {
  // Read the latest onClose without re-registering: keeps the stack entry
  // stable for the whole open lifetime, so its position reflects open order.
  const latest = useRef(onClose);
  latest.current = onClose;

  useEffect(() => {
    if (!active) return;
    const entry = () => latest.current();
    stack.push(entry);
    if (stack.length === 1) document.addEventListener("keydown", onKeyDown);
    return () => {
      const i = stack.lastIndexOf(entry);
      if (i !== -1) stack.splice(i, 1);
      if (stack.length === 0) document.removeEventListener("keydown", onKeyDown);
    };
  }, [active]);
}
