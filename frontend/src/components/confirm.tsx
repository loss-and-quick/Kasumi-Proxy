import { type ReactNode, useSyncExternalStore } from "react";
import { useT } from "../i18n";
import { Btn } from "./buttons";
import { Dialog } from "./overlays";

/** What a destructive action asks before it runs. */
export type ConfirmRequest = {
  title: ReactNode;
  body?: ReactNode;
  /** The confirming button; the action's own verb ("Delete", "Replace"). */
  confirmLabel: string;
  icon?: string;
};

type Pending = ConfirmRequest & { resolve: (ok: boolean) => void };

let pending: Pending | null = null;
const listeners = new Set<() => void>();
const emit = () => {
  for (const l of listeners) l();
};

/**
 * Ask before something that can't be undone. Resolves true when confirmed,
 * false on cancel / Escape / the scrim. One question at a time: a new one
 * cancels the one still open. Rendered by the single `<ConfirmHost />`.
 */
export function confirm(request: ConfirmRequest): Promise<boolean> {
  pending?.resolve(false);
  return new Promise((resolve) => {
    pending = { ...request, resolve };
    emit();
  });
}

function settle(ok: boolean) {
  const current = pending;
  pending = null;
  emit();
  current?.resolve(ok);
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** Mount once near the app root. */
export function ConfirmHost() {
  const t = useT();
  const request = useSyncExternalStore(subscribe, () => pending);
  return (
    <Dialog
      open={!!request}
      icon={request?.icon ?? "delete"}
      iconColor={{ bg: "var(--error-container)", fg: "oklch(0.92 0.04 25)" }}
      title={request?.title ?? ""}
      onClose={() => settle(false)}
      actions={
        <>
          <Btn variant="text" onClick={() => settle(false)}>
            {t("profiles.confirmDel.cancel")}
          </Btn>
          <Btn variant="error" onClick={() => settle(true)}>
            {request?.confirmLabel ?? ""}
          </Btn>
        </>
      }
    >
      {request?.body}
    </Dialog>
  );
}
