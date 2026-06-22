import { type ReactNode, useEffect, useRef } from "react";
import { acquireSheet } from "../lib/sheetPresence";
import { useSwipeDownToDismiss } from "../lib/useSwipeDownToDismiss";
import { Icon, IconBtn } from "./icons";

function Scrim({ onClose }: { onClose: () => void }) {
  return (
    <button
      type="button"
      className="scrim"
      aria-label="Close"
      onClick={onClose}
      style={{ appearance: "none", border: "none", padding: 0 }}
    />
  );
}

export const Sheet = ({
  open,
  title,
  onClose,
  children,
  headRight,
}: {
  open: boolean;
  title?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  headRight?: ReactNode;
}) => {
  const sheetRef = useRef<HTMLDivElement>(null);
  const swipe = useSwipeDownToDismiss(sheetRef, onClose);
  useEffect(() => {
    if (!open) return;
    return acquireSheet();
  }, [open]);
  if (!open) return null;
  return (
    <>
      <Scrim onClose={onClose} />
      <div
        ref={sheetRef}
        className="sheet"
        style={
          swipe.offset
            ? {
                transform: `translateY(${swipe.offset}px)`,
                transition: swipe.dragging ? "none" : undefined,
              }
            : undefined
        }
      >
        <div className="sheet-grab" onPointerDown={swipe.onPointerDown}>
          <div className="sheet-handle" />
          <div className="sheet-head">
            <div className="sheet-title">{title}</div>
            {headRight}
            <IconBtn name="close" sm onClick={onClose} />
          </div>
        </div>
        <div className="sheet-body">{children}</div>
      </div>
    </>
  );
};

export const Dialog = ({
  open,
  icon,
  iconColor,
  title,
  children,
  actions,
  onClose,
}: {
  open: boolean;
  icon?: string;
  iconColor?: { bg: string; fg: string };
  title: ReactNode;
  children: ReactNode;
  actions: ReactNode;
  onClose: () => void;
}) => {
  if (!open) return null;
  return (
    <>
      <Scrim onClose={onClose} />
      <div className="dialog">
        {icon && (
          <div
            className="dialog-icon"
            style={{
              background: iconColor?.bg || "var(--primary-container)",
              color: iconColor?.fg || "var(--on-primary-container)",
            }}
          >
            <Icon name={icon} />
          </div>
        )}
        <div className="dialog-title">{title}</div>
        <div className="dialog-text">{children}</div>
        <div className="dialog-actions">{actions}</div>
      </div>
    </>
  );
};

export const Toast = ({ msg }: { msg: string | null }) => {
  if (!msg) return null;
  return <div className="snackbar">{msg}</div>;
};
