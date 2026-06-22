// ============================================================
// src/lib/useSwipeDownToDismiss.ts
// Drag-down-to-close gesture for bottom sheets. The sheet follows
// the pointer while a grab handle is dragged and dismisses once
// the drag passes a threshold, otherwise it snaps back.
//
// Move/up are tracked on `window` rather than via pointer capture:
// touch has implicit per-gesture capture, but a desktop mouse does
// not, so a header-only capture would drop the drag the moment the
// cursor leaves the (small) handle. Window listeners track it
// everywhere and avoid setPointerCapture quirks.
// ============================================================
import {
  type PointerEvent as ReactPointerEvent,
  type RefObject,
  useEffect,
  useRef,
  useState,
} from "react";

// Dismiss past whichever is smaller: a fixed pull or a share of the height.
const DISMISS_PX = 100;
const DISMISS_RATIO = 0.3;

export interface SwipeDownToDismiss {
  /** Downward offset to translate the sheet by while dragging, in px. */
  offset: number;
  /** True while a drag is in progress (so snap-back transitions can be disabled). */
  dragging: boolean;
  /** Spread onto the sheet's grab handle. */
  onPointerDown: (e: ReactPointerEvent) => void;
}

export function useSwipeDownToDismiss(
  sheetRef: RefObject<HTMLElement | null>,
  onDismiss: () => void,
): SwipeDownToDismiss {
  const [offset, setOffset] = useState(0);
  const [dragging, setDragging] = useState(false);
  const startY = useRef<number | null>(null);
  const offsetRef = useRef(0);
  const onDismissRef = useRef(onDismiss);
  onDismissRef.current = onDismiss;

  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: PointerEvent) => {
      if (startY.current === null) return;
      const next = Math.max(0, e.clientY - startY.current);
      offsetRef.current = next;
      setOffset(next);
    };
    const onUp = () => {
      const height = sheetRef.current?.offsetHeight ?? 0;
      const dismissed = offsetRef.current > Math.min(DISMISS_PX, height * DISMISS_RATIO);
      startY.current = null;
      offsetRef.current = 0;
      setDragging(false);
      setOffset(0);
      if (dismissed) onDismissRef.current();
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onUp);
    };
  }, [dragging, sheetRef]);

  return {
    offset,
    dragging,
    onPointerDown: (e) => {
      // Ignore grabs that begin on an interactive control (e.g. the close button).
      if ((e.target as HTMLElement).closest("button, a, input, textarea, select")) return;
      startY.current = e.clientY;
      setDragging(true);
    },
  };
}
