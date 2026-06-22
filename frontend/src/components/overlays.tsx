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
  // Keep the dialog mounted through its exit animation so every close
  // path (scrim, action buttons, parent state) fades out instead of
  // popping. Driven by `open` so parent-owned actions need no wiring.
  const [render, setRender] = useState(open);
  const [closing, setClosing] = useState(false);

  // Freeze the shown content while closing: parents often clear the source
  // (e.g. the selected item) on close, which would otherwise blank the body
  // mid-animation. Keep the last open content until the exit finishes.
  const shown = useRef({ icon, iconColor, title, children, actions });
  if (open) shown.current = { icon, iconColor, title, children, actions };
  const view = shown.current;

  useEffect(() => {
    if (open) {
      setRender(true);
      setClosing(false);
    } else {
      setClosing((wasClosing) => wasClosing || render);
    }
  }, [open, render]);

  const onAnimationEnd = (e: React.AnimationEvent) => {
    if (closing && e.target === e.currentTarget) {
      setRender(false);
      setClosing(false);
    }
  };

  if (!render) return null;
  return (
    <>
      <Scrim onClose={onClose} leaving={closing} />
      <div className={`dialog${closing ? " leaving" : ""}`} onAnimationEnd={onAnimationEnd}>
        {view.icon && (
          <div
            className="dialog-icon"
            style={{
              background: view.iconColor?.bg || "var(--primary-container)",
              color: view.iconColor?.fg || "var(--on-primary-container)",
            }}
          >
            <Icon name={view.icon} />
          </div>
        )}
        <div className="dialog-title">{view.title}</div>
        <div className="dialog-text">{view.children}</div>
        <div className="dialog-actions">{view.actions}</div>
      </div>
    </>
  );
};

export const Toast = ({ msg }: { msg: string | null }) => {
  if (!msg) return null;
  return <div className="snackbar">{msg}</div>;
};
