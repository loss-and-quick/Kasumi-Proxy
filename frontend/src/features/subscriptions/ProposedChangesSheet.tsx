// The review of what a provider proposes for one subscription. Nothing here changes
// state by itself: each answer is a `resolveSubChange` intent that Rust applies.
import { type CSSProperties, useLayoutEffect, useRef, useState } from "react";
import { Btn, Disclosure, Icon, Sheet } from "../../components";
import { type DictKey, useFormatters, useT } from "../../i18n";
import type { PendingChange, Subscription } from "../../lib/bridge";
import { BASE_GROUP_ID } from "../../lib/groups";
import { useIsWide } from "../../lib/useIsWide";
import { wasReported } from "../../store/errors";
import { useAppStore } from "../../store/useAppStore";
import {
  boolValue,
  domainMove,
  groupChanges,
  keyLabel,
  type ProposalGroup,
  safeDigests,
} from "./proposals";
import { RoutingImportCard } from "./RoutingImportCard";
import { displayTitle } from "./sub-display";

const GROUP_TEXT: Record<ProposalGroup, { title: DictKey; sub: DictKey; icon: string }> = {
  trust: { title: "subs.changes.group.trust", sub: "subs.changes.group.trustSub", icon: "policy" },
  tunnel: {
    title: "subs.changes.group.tunnel",
    sub: "subs.changes.group.tunnelSub",
    icon: "tune",
  },
  unsupported: {
    title: "subs.changes.group.unsupported",
    sub: "subs.changes.group.unsupportedSub",
    icon: "block",
  },
};

// A hint under the values for the changes whose effect is not obvious from them.
const HINT: Partial<Record<PendingChange["action"]["kind"], DictKey>> = {
  setFallbackUrl: "subs.changes.hint.fallback",
  setUserAgent: "subs.changes.hint.userAgent",
  lockUserAgent: "subs.changes.hint.lockUserAgent",
};

const valueText: CSSProperties = {
  fontSize: 12.5,
  lineHeight: 1.45,
  overflowWrap: "anywhere",
  unicodeBidi: "plaintext",
};

const CLAMP_LINES = 3;

/** A provider value: monospace, clamped to a few lines with a toggle to show it all. */
function Value({ text, mono, muted }: { text: string; mono: boolean; muted?: boolean }) {
  const t = useT();
  const ref = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [clamped, setClamped] = useState(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-measure when the text changes.
  useLayoutEffect(() => {
    const el = ref.current;
    if (el && !open) setClamped(el.scrollHeight > el.clientHeight + 1);
  }, [text, open]);
  return (
    <div style={{ minWidth: 0 }}>
      <div
        ref={ref}
        dir="auto"
        className={mono ? "mono" : undefined}
        style={{
          ...valueText,
          color: muted ? "var(--on-surface-variant)" : "var(--on-surface)",
          ...(open
            ? {}
            : {
                display: "-webkit-box",
                WebkitBoxOrient: "vertical",
                WebkitLineClamp: CLAMP_LINES,
                overflow: "hidden",
              }),
        }}
      >
        {text}
      </div>
      {(clamped || open) && (
        <button
          type="button"
          className="btn-reset"
          onClick={() => setOpen((o) => !o)}
          style={{ marginTop: 2, fontSize: 12, fontWeight: 500, color: "var(--primary)" }}
        >
          {open ? t("subs.provider.showLess") : t("subs.provider.showMore")}
        </button>
      )}
    </div>
  );
}

/** Now → proposed: side by side on a wide screen, stacked on a phone. */
function Values({ change, wide }: { change: PendingChange; wide: boolean }) {
  const t = useT();
  const on = boolValue(change.action);
  const shown = (v: string | null | undefined, isNew: boolean) => {
    if (on !== null) {
      // `previous` of an on/off change is the current state as `true`/`false`.
      const value = isNew ? on : v === "true";
      return { text: t(value ? "subs.changes.on" : "subs.changes.off"), mono: false };
    }
    return v ? { text: v, mono: true } : { text: t("subs.changes.notSet"), mono: false };
  };
  const prev = shown(change.previous, false);
  // The lock replaces the previous User-Agent; its value is just `true`. A new domain
  // is shown as the whole URL it makes, to compare with the current one.
  const action = change.action;
  const next =
    action.kind === "lockUserAgent"
      ? { text: t("subs.changes.on"), mono: false }
      : shown(action.kind === "replaceDomain" ? action.url : change.value, true);
  const label = (k: DictKey) => (
    <div style={{ fontSize: 11, fontWeight: 500, color: "var(--on-surface-faint)" }}>{t(k)}</div>
  );
  const unknownPrev = change.previous == null && on === null;
  if (wide) {
    return (
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) auto minmax(0, 1fr)",
          gap: "4px 12px",
          alignItems: "start",
          marginTop: 8,
        }}
      >
        {label("subs.changes.previous")}
        <span />
        {label("subs.changes.proposed")}
        <Value {...prev} muted />
        <Icon
          name="arrow_forward"
          style={{ fontSize: 16, color: "var(--on-surface-faint)", marginTop: 1 }}
        />
        <Value {...next} />
      </div>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
      {!unknownPrev && (
        <div>
          {label("subs.changes.previous")}
          <Value {...prev} muted />
        </div>
      )}
      <div>
        {label("subs.changes.proposed")}
        <Value {...next} />
      </div>
    </div>
  );
}

/** The host a URL change moves to, with a stronger warning when the domain differs.
 *  An encrypted link's host stays hidden. */
function DomainMoveCard({ from, to, other }: { from: string; to: string; other: boolean }) {
  const t = useT();
  return (
    <div
      role="note"
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        marginTop: 10,
        padding: "10px 12px",
        background: "var(--warn-container)",
        color: "var(--on-warn-container)",
        borderRadius: 12,
      }}
    >
      <Icon name="swap_horiz" style={{ fontSize: 20, color: "var(--warn)", flexShrink: 0 }} />
      <div style={{ minWidth: 0, fontSize: 13, lineHeight: 1.45 }}>
        <div className="mono" dir="ltr" style={{ fontWeight: 600, overflowWrap: "anywhere" }}>
          {t("subs.changes.domainMove", { from: from || "•••", to })}
        </div>
        <div style={{ marginTop: 2 }}>{t("subs.changes.domainMoveBody")}</div>
        {other && (
          <div style={{ marginTop: 4, fontWeight: 500 }}>{t("subs.changes.otherDomain")}</div>
        )}
      </div>
    </div>
  );
}

/** What allowing a provider's full Xray configs lets through, and what it doesn't. */
function ProviderConfigsCard() {
  const t = useT();
  return (
    <div
      role="note"
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        marginTop: 10,
        padding: "10px 12px",
        background: "var(--sc-high)",
        borderRadius: 12,
      }}
    >
      <Icon name="data_object" style={{ fontSize: 20, color: "var(--primary)", flexShrink: 0 }} />
      <div style={{ minWidth: 0, fontSize: 13, lineHeight: 1.45, color: "var(--on-surface)" }}>
        <div>{t("subs.changes.providerConfigs")}</div>
        <div style={{ marginTop: 4, color: "var(--on-surface-variant)" }}>
          {t("subs.changes.providerConfigsKept")}
        </div>
      </div>
    </div>
  );
}

function ChangeRow({
  sub,
  change,
  wide,
  busy,
  onAnswer,
}: {
  sub: Subscription;
  change: PendingChange;
  wide: boolean;
  busy: boolean;
  onAnswer: (accept: boolean, activate?: boolean) => void;
}) {
  const t = useT();
  const { formatDateTime } = useFormatters();
  const action = change.action;
  const [activate, setActivate] = useState(action.kind === "importRouting" && action.activate);
  const labelKey = keyLabel(change.key);
  const move = domainMove(action);
  const hint =
    action.kind === "setInsecure" && action.on ? "subs.changes.hint.insecure" : HINT[action.kind];
  const unsupported = action.kind === "unsupported";
  return (
    <div
      style={{
        padding: "12px 14px",
        background: "var(--sc)",
        borderRadius: 14,
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
        <div
          className={labelKey ? undefined : "mono"}
          style={{ flex: 1, minWidth: 0, fontSize: 14, fontWeight: 600, overflowWrap: "anywhere" }}
        >
          {labelKey ? t(labelKey) : change.key}
        </div>
        <span style={{ fontSize: 11, color: "var(--on-surface-faint)", flexShrink: 0 }}>
          {formatDateTime(new Date(change.seenAt), { timeStyle: undefined })}
        </span>
      </div>
      {move && <DomainMoveCard from={move.from} to={move.to} other={move.otherDomain} />}
      {action.kind === "importRouting" ? (
        <RoutingImportCard
          groupId={sub.groupId ?? BASE_GROUP_ID}
          ownerSubId={sub.id}
          routing={action.routing}
          activate={activate}
          onActivate={setActivate}
        />
      ) : action.kind === "allowProviderConfigs" ? (
        <ProviderConfigsCard />
      ) : (
        <Values change={change} wide={wide} />
      )}
      {hint && (
        <div className="hint" style={{ marginTop: 6 }}>
          {t(hint)}
        </div>
      )}
      <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 10 }}>
        {unsupported ? (
          <Btn variant="text" sm disabled={busy} onClick={() => onAnswer(false)}>
            {t("subs.changes.dismiss")}
          </Btn>
        ) : (
          <>
            <Btn variant="text" sm disabled={busy} onClick={() => onAnswer(false)}>
              {t("subs.changes.reject")}
            </Btn>
            <Btn
              variant="tonal"
              sm
              icon="check"
              disabled={busy}
              onClick={() => onAnswer(true, action.kind === "importRouting" ? activate : undefined)}
            >
              {action.kind === "importRouting"
                ? t("subs.changes.import")
                : t("subs.changes.accept")}
            </Btn>
          </>
        )}
      </div>
    </div>
  );
}

/** Every pending change of `sub`, grouped by how much it can affect. */
export function ProposedChangesSheet({
  sub,
  onClose,
}: {
  sub: Subscription | null;
  onClose: () => void;
}) {
  const t = useT();
  const wide = useIsWide();
  const resolve = useAppStore((s) => s.resolveSubChange);
  const notify = useAppStore((s) => s.notify);
  const [busy, setBusy] = useState(false);
  const changes = sub?.pendingChanges ?? [];
  const groups = groupChanges(changes);
  const safe = safeDigests(changes);

  const answer = async (digests: string[], accept: boolean, activate?: boolean) => {
    if (!sub || busy) return;
    setBusy(true);
    try {
      await resolve(sub.id, digests, accept, activate);
      notify(
        t(accept ? "subs.changes.accepted" : "subs.changes.rejected", { count: digests.length }),
      );
    } catch (e) {
      if (!wasReported(e)) notify(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet open={!!sub} title={t("subs.changes.title")} onClose={onClose}>
      {sub && (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div style={{ fontSize: 13, lineHeight: 1.5, color: "var(--on-surface-variant)" }}>
            {t("subs.changes.intro", { name: displayTitle(sub) })}
          </div>
          {groups.length === 0 && (
            <div style={{ fontSize: 13.5, color: "var(--on-surface-variant)" }}>
              {t("subs.changes.none")}
            </div>
          )}
          {groups.map(({ group, items }) => {
            const text = GROUP_TEXT[group];
            const rows = (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {items.map((c) => (
                  <ChangeRow
                    key={c.digest}
                    sub={sub}
                    change={c}
                    wide={wide}
                    busy={busy}
                    onAnswer={(accept, activate) => void answer([c.digest], accept, activate)}
                  />
                ))}
              </div>
            );
            const heading = (
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <Icon
                  name={text.icon}
                  style={{
                    fontSize: 20,
                    flexShrink: 0,
                    color: group === "trust" ? "var(--primary)" : "var(--on-surface-variant)",
                  }}
                />
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 14.5, fontWeight: 600 }}>
                    {t(text.title)} · {items.length}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--on-surface-variant)" }}>
                    {t(text.sub)}
                  </div>
                </div>
              </div>
            );
            return (
              <section key={group} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {group === "unsupported" ? (
                  <Disclosure label={heading}>{rows}</Disclosure>
                ) : (
                  <>
                    {heading}
                    {rows}
                  </>
                )}
              </section>
            );
          })}
          {changes.length > 0 && (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                justifyContent: "flex-end",
                gap: 8,
                paddingTop: 4,
              }}
            >
              <Btn
                variant="text"
                disabled={busy}
                onClick={() =>
                  void answer(
                    changes.map((c) => c.digest),
                    false,
                  )
                }
              >
                {t("subs.changes.rejectAll")}
              </Btn>
              {safe.length > 0 && (
                <Btn
                  variant="tonal"
                  icon="done_all"
                  disabled={busy}
                  onClick={() => void answer(safe, true)}
                >
                  {t("subs.changes.acceptSafe", { count: safe.length })}
                </Btn>
              )}
            </div>
          )}
        </div>
      )}
    </Sheet>
  );
}
