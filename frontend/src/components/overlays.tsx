import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { acquireSheet } from "../lib/sheetPresence";
import { useSwipeDownToDismiss } from "../lib/useSwipeDownToDismiss";
import { Icon, IconBtn } from "./icons";

function Scrim({ onClose, leaving }: { onClose: () => void; leaving?: boolean }) {
  return (
    <button
      type="button"
      className={`scrim${leaving ? " leaving" : ""}`}
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
  // Play an exit animation before unmounting so every close path
  // (swipe, close button, scrim) slides out instead of popping.
  const [closing, setClosing] = useState(false);
  const requestClose = useCallback(() => setClosing(true), []);
  const swipe = useSwipeDownToDismiss(sheetRef, requestClose);

  // Register presence so the desktop side rail steps aside while open.
  useEffect(() => {
    if (!open) return;
    return acquireSheet();
  }, [open]);

  // Reset the closing flag whenever the sheet (re)opens.
  useEffect(() => {
    if (open) setClosing(false);
  }, [open]);

  const onTransitionEnd = (e: React.TransitionEvent) => {
    if (closing && e.target === e.currentTarget && e.propertyName === "transform") onClose();
  };

  if (!open) return null;
  return (
    <>
      <Scrim onClose={requestClose} leaving={closing} />
      <div
        ref={sheetRef}
        className={`sheet${closing ? " leaving" : ""}`}
        onTransitionEnd={onTransitionEnd}
        style={
          // `leaving` slides fully out; otherwise follow the drag. Disable the
          // transition only mid-drag so the gesture tracks the pointer 1:1.
          closing || swipe.offset
            ? {
                transform: `translateY(${closing ? "100%" : `${swipe.offset}px`})`,
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
            <IconBtn name="close" sm onClick={requestClose} />
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
