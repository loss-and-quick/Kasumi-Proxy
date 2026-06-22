// ============================================================
// src/lib/useSwipeDownToDismiss.ts
// Drag-down-to-close gesture for bottom sheets. The sheet follows
// the pointer while a grab handle is dragged and dismisses once
// the drag passes a threshold, otherwise it snaps back.
// ============================================================
import { type PointerEvent as ReactPointerEvent, type RefObject, useRef, useState } from "react";

// Dismiss past whichever is smaller: a fixed pull or a share of the height.
const DISMISS_PX = 100;
const DISMISS_RATIO = 0.3;

export interface SwipeDownToDismiss {
  /** Downward offset to translate the sheet by while dragging, in px. */
  offset: number;
  /** True while a drag is in progress (so snap-back transitions can be disabled). */
  dragging: boolean;
  /** Spread onto the sheet's grab handle. */
  handlers: {
    onPointerDown: (e: ReactPointerEvent) => void;
    onPointerMove: (e: ReactPointerEvent) => void;
    onPointerUp: (e: ReactPointerEvent) => void;
    onPointerCancel: (e: ReactPointerEvent) => void;
  };
}

export function useSwipeDownToDismiss(
  sheetRef: RefObject<HTMLElement | null>,
  onDismiss: () => void,
): SwipeDownToDismiss {
  const startY = useRef<number | null>(null);
  const [offset, setOffset] = useState(0);
  const [dragging, setDragging] = useState(false);

  const end = () => {
    if (startY.current === null) return;
    startY.current = null;
    setDragging(false);
    const height = sheetRef.current?.offsetHeight ?? 0;
    if (offset > Math.min(DISMISS_PX, height * DISMISS_RATIO)) onDismiss();
    setOffset(0);
  };

  return {
    offset,
    dragging,
    handlers: {
      onPointerDown: (e) => {
        // Ignore grabs that begin on an interactive control (e.g. the close button).
        if ((e.target as HTMLElement).closest("button, a, input, textarea, select")) return;
        startY.current = e.clientY;
        setDragging(true);
        e.currentTarget.setPointerCapture(e.pointerId);
      },
      onPointerMove: (e) => {
        if (startY.current === null) return;
        setOffset(Math.max(0, e.clientY - startY.current));
      },
      onPointerUp: end,
      onPointerCancel: end,
    },
  };
}
