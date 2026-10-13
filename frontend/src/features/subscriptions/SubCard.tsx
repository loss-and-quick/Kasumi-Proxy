import { Btn, Card, Icon, IconBtn, Sheet, Switch } from "../../components";
import type { SubWarning } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import type { Subscription } from "../../lib/bridge";
import { minutesToClock } from "../../lib/utils";
import { ProviderBanners } from "./ProviderBanner";
import { keyLabel, proposalCount, tunnelKeys } from "./proposals";
import {
  daysLeft,
  displayTitle,
  errorKey,
  errorVars,
  expiryState,
  intervalLabel,
  warningKey,
} from "./sub-display";
import { TrafficBar } from "./TrafficBar";

const chipStyle = { height: 28, fontSize: 11.5, pointerEvents: "none" } as const;

export function SubCard({
  s,
  groupName,
  onOpenGroup,
  revealed,
  onReveal,
  onToggle,
  updating,
  onUpdate,
  onEdit,
  onMore,
  onOpenUrl,
  onShowWarnings,
  onShowChanges,
}: {
  s: Subscription;
  groupName: string;
  onOpenGroup: () => void;
  revealed: boolean;
  onReveal: () => void;
  onToggle: (enabled: boolean) => void;
  updating: boolean;
  onUpdate: () => void;
  onEdit: () => void;
  onMore: () => void;
  onOpenUrl: (url: string) => void;
  onShowWarnings: () => void;
  onShowChanges: () => void;
}) {
  const t = useT();
  const { formatDateTime } = useFormatters();
  const title = displayTitle(s);
  const provider = s.provider ?? null;
  const expire = provider?.traffic?.expire ?? null;
  const expiry = expiryState(expire, Date.now());
  const expired = !!provider && (provider.expired || expiry === "expired");
  const interval = intervalLabel(s);
  const warnings = s.warnings ?? [];
  const proposed = proposalCount(s.pendingChanges);
  const tunnel = tunnelKeys(s.pendingChanges);

  return (
    <Card style={{ padding: 14, opacity: s.enabled ? 1 : 0.6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div dir="auto" style={{ fontSize: 15.5, fontWeight: 600 }} className="truncate">
            {title}
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginTop: 4,
              fontSize: 11.5,
              color: "var(--on-surface-variant)",
            }}
          >
            <span className="mono">{t("subs.profilesCount", { n: s.count })}</span>
            <span>·</span>
            <span>
              {s.lastUpdated
                ? t("subs.updatedAt", { date: formatDateTime(new Date(s.lastUpdated)) })
                : t("subs.neverUpdated")}
            </span>
          </div>
        </div>
        <Switch on={s.enabled} onChange={onToggle} label={title} />
      </div>
      <button
        type="button"
        className="btn-reset sub-group-link"
        title={t("subs.openGroup")}
        onClick={onOpenGroup}
      >
        <Icon name="folder" style={{ fontSize: 15 }} />
        <span className="truncate">{groupName}</span>
      </button>

      {provider && (provider.traffic || provider.supportUrl || provider.webPageUrl) && (
        <div style={{ marginTop: 12 }}>
          {provider.traffic && <TrafficBar traffic={provider.traffic} />}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginTop: provider.traffic ? 6 : 0,
              minHeight: 32,
              flexWrap: "wrap",
            }}
          >
            {expire != null && (
              <span
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  fontSize: 11.5,
                  color: "var(--on-surface-variant)",
                }}
              >
                <Icon name="event" style={{ fontSize: 15 }} />
                {t("subs.provider.expires", {
                  date: formatDateTime(expire * 1000, { timeStyle: undefined }),
                })}
              </span>
            )}
            {expiry === "soon" && expire != null && (
              <span className="chip" style={{ ...chipStyle, color: "var(--warn)" }}>
                {t("subs.provider.expiresSoon", { days: daysLeft(expire, Date.now()) })}
              </span>
            )}
            {expiry === "expired" && (
              <span className="chip" style={{ ...chipStyle, color: "var(--error)" }}>
                {t("subs.provider.expired")}
              </span>
            )}
            <div style={{ flex: 1 }} />
            {provider.supportUrl && (
              <IconBtn
                sm
                name="support_agent"
                title={t("subs.provider.support")}
                onClick={() => provider.supportUrl && onOpenUrl(provider.supportUrl)}
              />
            )}
            {provider.webPageUrl && (
              <IconBtn
                sm
                name="open_in_new"
                title={t("subs.provider.webPage")}
                onClick={() => provider.webPageUrl && onOpenUrl(provider.webPageUrl)}
              />
            )}
          </div>
        </div>
      )}

      {provider && <ProviderBanners provider={provider} expired={expired} onOpen={onOpenUrl} />}

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginTop: 12,
          background: "var(--sc-lowest)",
          borderRadius: 9,
          padding: "8px 6px 8px 11px",
        }}
      >
        <span
          className="mono truncate"
          style={{ flex: 1, fontSize: 11.5, color: "var(--on-surface-variant)" }}
        >
          {revealed
            ? s.url
            : s.url.replace(/(token=|\/)([^/=&]{4})[^/=&]*/g, (_m, a, b) => `${a}${b}••••••`)}
        </span>
        <IconBtn
          sm
          name={revealed ? "visibility_off" : "visibility"}
          onClick={onReveal}
          title={t("subs.toggleUrl")}
        />
      </div>

      {/* The actions wrap as one group, so a long run of chips never splits them. */}
      <div
        style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12, flexWrap: "wrap" }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {proposed > 0 && (
            <button
              type="button"
              className="chip"
              style={{
                ...chipStyle,
                pointerEvents: undefined,
                background: "var(--primary)",
                color: "var(--on-primary)",
                borderColor: "transparent",
              }}
              onClick={onShowChanges}
            >
              <Icon name="policy" style={{ fontSize: 15 }} />{" "}
              {t("subs.changes.badge", { count: proposed })}
            </button>
          )}
          {tunnel.map((key) => {
            const label = keyLabel(key);
            return (
              <button
                key={key}
                type="button"
                className="chip"
                style={{ ...chipStyle, pointerEvents: undefined, color: "var(--warn)" }}
                title={t("subs.changes.group.tunnelSub")}
                onClick={onShowChanges}
              >
                <Icon name="tune" style={{ fontSize: 15 }} /> {label ? t(label) : key}
              </button>
            );
          })}
          {s.autoUpdate ? (
            <span className="chip active" style={chipStyle}>
              <Icon name="autorenew" style={{ fontSize: 15 }} />{" "}
              {interval.kind === "provider"
                ? t("subs.interval.provider", { hours: interval.hours })
                : t("subs.autoLabel", { interval: minutesToClock(interval.minutes) })}
            </span>
          ) : (
            <span className="chip" style={chipStyle}>
              <Icon name="schedule" style={{ fontSize: 15 }} /> {t("subs.manualLabel")}
            </span>
          )}
          {s.bodyEncrypted && (
            <span className="chip" style={chipStyle}>
              <Icon name="lock" style={{ fontSize: 15 }} /> {t("subs.provider.encrypted")}
            </span>
          )}
          {s.allowInsecure && (
            <span className="chip" style={{ ...chipStyle, color: "var(--warn)" }}>
              <Icon name="gpp_maybe" style={{ fontSize: 15 }} /> {t("subs.insecureLabel")}
            </span>
          )}
          {warnings.length > 0 && (
            <button
              type="button"
              className="chip"
              style={{ ...chipStyle, pointerEvents: undefined, color: "var(--warn)" }}
              onClick={onShowWarnings}
            >
              <Icon name="warning" style={{ fontSize: 15 }} />{" "}
              {t("subs.warnings.chip", { count: warnings.length })}
            </button>
          )}
          {s.lastError && (
            <span className="chip" style={{ ...chipStyle, color: "var(--error)" }}>
              <Icon name="error" style={{ fontSize: 15 }} /> {t("subs.errorLabel")}
            </span>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginLeft: "auto" }}>
          <IconBtn sm name="edit" onClick={onEdit} title={t("subs.editAction")} />
          <IconBtn sm name="more_vert" onClick={onMore} title={t("subs.menu.more")} />
          <Btn
            variant="tonal"
            sm
            icon={updating ? "autorenew" : "refresh"}
            onClick={onUpdate}
            disabled={updating}
            className={updating ? "btn-busy" : undefined}
          >
            {t("subs.updateBtn")}
          </Btn>
        </div>
      </div>
      {s.lastError && (
        <div className="hint error" style={{ marginTop: 8 }}>
          {s.lastErrorKind
            ? t(errorKey(s.lastErrorKind), errorVars(s.lastErrorKind, s.lastError))
            : s.lastError}
        </div>
      )}
    </Card>
  );
}

/** What the last update skipped, in the user's language. */
export function WarningsSheet({
  warnings,
  onClose,
}: {
  warnings: SubWarning[] | null;
  onClose: () => void;
}) {
  const t = useT();
  return (
    <Sheet open={!!warnings} title={t("subs.warnings.title")} onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {(warnings ?? []).map((w) => (
          <div key={w.kind} style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <Icon name="warning" style={{ fontSize: 20, color: "var(--warn)", flexShrink: 0 }} />
            <div style={{ minWidth: 0, fontSize: 13.5, lineHeight: 1.45 }}>
              {"count" in w
                ? t(warningKey(w), { count: w.count })
                : "host" in w
                  ? t(warningKey(w), { host: w.host })
                  : t(warningKey(w))}
              {w.kind === "skippedLines" && w.sample && (
                <div
                  className="mono"
                  dir="auto"
                  style={{
                    marginTop: 4,
                    fontSize: 11.5,
                    color: "var(--on-surface-variant)",
                    overflowWrap: "anywhere",
                  }}
                >
                  {w.sample}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </Sheet>
  );
}
