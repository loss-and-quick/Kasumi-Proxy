// ============================================================
// src/lib/useEscapeToClose.ts
// Close-on-Escape and close-on-Back for overlays (sheets, dialogs,
// full-screen pages). A shared LIFO stack makes a single Escape or
// Back dismiss only the top-most overlay, so stacked sheets/dialogs
// peel off one at a time. Handlers that already consumed Escape (a
// dropdown menu, an inline rename) call preventDefault, and we skip
// those so the overlay stays open.
//
// Back (Android's back button in the root manager's WebView, a mouse
// back button, Alt+←) only reaches the page as a history pop. So each
// overlay that opens pushes a history entry with the same URL; a pop
// closes the top overlay instead of leaving the screen, and an overlay
// closed any other way takes its entry back off.
// ============================================================
import { useEffect, useRef } from "react";

type Entry = { close: () => void; history: boolean };

const stack: Entry[] = [];
/** History entries pushed for open overlays and not popped yet. */
let tracked = 0;
/** Pops we caused ourselves with history.go(), not the user's Back. */
let ownPops = 0;
/** Entries to take off at the end of this tick, in one history.go(). */
let pendingPops = 0;
let listening = false;

const STATE_KEY = "kasumiOverlay";

// Several overlays can close in one render (a sheet and the sheet opened from
// it); one go(-n) takes all their entries off, where repeated back() calls
// may be merged into a single step.
function flushPops() {
  if (!pendingPops) return;
  const n = pendingPops;
  pendingPops = 0;
  ownPops += 1;
  window.history.go(-n);
}

/** Whether our newest entry is still the current one (none navigated on top). */
function ownsTopEntry(): boolean {
  const state = window.history.state as Record<string, unknown> | null;
  // history.state only moves once a queued go() lands, so count those in.
  return state?.[STATE_KEY] === tracked + pendingPops;
}

function onKeyDown(e: KeyboardEvent) {
  if (e.key !== "Escape" || e.defaultPrevented || stack.length === 0) return;
  e.preventDefault();
  stack[stack.length - 1].close();
}

function onPopState() {
  if (ownPops > 0) {
    ownPops -= 1;
    return;
  }
  // The pop went past our entries (a tab's hash, or an entry left from
  // before a reload): ordinary navigation.
  if (tracked === 0) return;
  // The browser already dropped the top overlay's entry. Put it back so
  // the history keeps matching what is open, then ask the overlay to
  // close the way its ✕ would; one that refuses (unsaved edits) stays,
  // and one that closes takes the entry off again.
  window.history.pushState({ [STATE_KEY]: tracked }, "");
  const top = [...stack].reverse().find((entry) => entry.history);
  top?.close();
}

/** Register an overlay as open; the returned function unregisters it. */
export function openOverlay(close: () => void, options: { history?: boolean } = {}) {
  const entry: Entry = { close, history: options.history ?? true };
  stack.push(entry);
  if (stack.length === 1) document.addEventListener("keydown", onKeyDown);
  // Kept for good: our own go() can land after the last overlay is gone.
  if (!listening) {
    listening = true;
    window.addEventListener("popstate", onPopState);
  }
  if (entry.history) {
    tracked += 1;
    // One overlay closing as another opens (Add → the editor) hands its
    // entry over, which already carries this depth, instead of a pop and a
    // push that the queued go() would then undo.
    if (pendingPops > 0) pendingPops -= 1;
    else window.history.pushState({ [STATE_KEY]: tracked }, "");
  }
  return () => {
    const i = stack.lastIndexOf(entry);
    if (i === -1) return;
    stack.splice(i, 1);
    if (entry.history && tracked > 0) {
      // Navigating elsewhere while open (a tab switch pushes a new hash)
      // leaves our entry under the new one; going back there would undo
      // that navigation, so only an entry still on top is taken off.
      if (ownsTopEntry()) {
        pendingPops += 1;
        if (pendingPops === 1) queueMicrotask(flushPops);
      }
      tracked -= 1;
    }
    if (stack.length === 0) document.removeEventListener("keydown", onKeyDown);
  };
}

/**
 * While `active`, register `onClose` so Escape and Back dismiss this overlay
 * first. `history: false` is for screens whose opening already moved the
 * location (the settings pages' `#settings/<id>`), so Back pops that instead.
 */
export function useEscapeToClose(
  active: boolean,
  onClose: () => void,
  options: { history?: boolean } = {},
): void {
  // Read the latest onClose without re-registering: keeps the stack entry
  // stable for the whole open lifetime, so its position reflects open order.
  const latest = useRef(onClose);
  latest.current = onClose;
  const history = options.history ?? true;

  useEffect(() => {
    if (!active) return;
    return openOverlay(() => latest.current(), { history });
  }, [active, history]);
}
