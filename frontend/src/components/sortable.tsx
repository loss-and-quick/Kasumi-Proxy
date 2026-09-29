import {
  type DraggableAttributes,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
} from "@dnd-kit/core";
import { sortableKeyboardCoordinates, useSortable } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import type { CSSProperties, ReactNode } from "react";

export type SortableBindings = {
  setNodeRef: (el: HTMLElement | null) => void;
  style: CSSProperties;
  attributes: DraggableAttributes;
  listeners: ReturnType<typeof useSortable>["listeners"];
  isDragging: boolean;
};

// Render-prop wrapper so useSortable runs in a real (keyed) component instance,
// keeping the row JSX inline in the map.
export function Sortable({
  id,
  children,
}: {
  id: string;
  children: (b: SortableBindings) => ReactNode;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id,
  });
  return children({
    setNodeRef,
    // Translate only: CSS.Transform also appends scaleX/scaleY, which we never need
    // for a vertical reorder and which would scale the masked icons.
    style: { transform: CSS.Translate.toString(transform), transition },
    attributes,
    listeners,
    isDragging,
  });
}

/** Pointer drag after a few pixels (so taps still click), plus arrow-key reordering. */
export function useSortableSensors() {
  return useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }),
  );
}
