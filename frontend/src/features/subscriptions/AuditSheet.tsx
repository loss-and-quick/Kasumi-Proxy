import { Icon, Sheet } from "../../components";
import { type DictKey, useFormatters, useT } from "../../i18n";
import type { AuditOutcome, Subscription } from "../../lib/bridge";
import { keyLabel } from "./proposals";

// Outcomes in the app's semantic roles: accepted reads as done, ignored as a warning.
const OUTCOME: Record<AuditOutcome, { label: DictKey; icon: string; color: string }> = {
  autoApplied: { label: "subs.audit.autoApplied", icon: "autorenew", color: "var(--primary)" },
  offered: { label: "subs.audit.offered", icon: "policy", color: "var(--on-surface-variant)" },
  accepted: { label: "subs.audit.accepted", icon: "check_circle", color: "var(--running)" },
  rejected: { label: "subs.audit.rejected", icon: "block", color: "var(--on-surface-variant)" },
  ignored: { label: "subs.audit.ignored", icon: "warning", color: "var(--warn)" },
};

/** What the provider proposed for `sub` and what became of it, newest first. */
export function AuditSheet({ sub, onClose }: { sub: Subscription | null; onClose: () => void }) {
  const t = useT();
  const { formatDateTime } = useFormatters();
  const entries = sub?.audit ?? [];
  return (
    <Sheet open={!!sub} title={t("subs.audit.title")} onClose={onClose}>
      {entries.length === 0 ? (
        <div style={{ fontSize: 13.5, color: "var(--on-surface-variant)" }}>
          {t("subs.audit.empty")}
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column" }}>
          {entries.map((e, i) => {
            const o = OUTCOME[e.outcome];
            const label = keyLabel(e.key);
            return (
              <div
                // Entries have no id; one fetch or answer audits a key once.
                key={`${e.at}-${e.key}-${e.outcome}-${e.summary}`}
                style={{
                  display: "flex",
                  gap: 12,
                  alignItems: "flex-start",
                  padding: "10px 0",
                  borderTop: i ? "1px solid var(--hairline)" : undefined,
                }}
              >
                <Icon name={o.icon} style={{ fontSize: 20, color: o.color, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{ display: "flex", alignItems: "baseline", gap: 8, flexWrap: "wrap" }}
                  >
                    <span
                      className={label ? undefined : "mono"}
                      style={{ fontSize: 13.5, fontWeight: 600 }}
                    >
                      {label ? t(label) : e.key}
                    </span>
                    <span
                      className="chip"
                      style={{ height: 22, fontSize: 11, color: o.color, pointerEvents: "none" }}
                    >
                      {t(o.label)}
                    </span>
                  </div>
                  {e.summary && (
                    <div
                      className="mono"
                      dir="auto"
                      style={{
                        marginTop: 3,
                        fontSize: 11.5,
                        color: "var(--on-surface-variant)",
                        overflowWrap: "anywhere",
                        unicodeBidi: "plaintext",
                      }}
                    >
                      {e.summary}
                    </div>
                  )}
                  <div style={{ marginTop: 3, fontSize: 11, color: "var(--on-surface-faint)" }}>
                    {formatDateTime(new Date(e.at))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Sheet>
  );
}
