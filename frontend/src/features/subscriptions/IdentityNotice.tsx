import { Btn, Icon } from "../../components";
import { useT } from "../../i18n";
import { useAppStore } from "../../store/useAppStore";

/** Says once that fetches now identify like Happ, and where that is changed. */
export function IdentityNotice() {
  const t = useT();
  const dismissed = useAppStore((s) => s.settings.identityNoticeDismissed);
  const hasSubs = useAppStore((s) => s.subscriptions.length > 0);
  const setSetting = useAppStore((s) => s.setSetting);
  if (dismissed || !hasSubs) return null;
  return (
    <div
      role="note"
      style={{
        display: "flex",
        gap: 12,
        alignItems: "flex-start",
        padding: "12px 14px",
        marginBottom: 12,
        background: "var(--primary-container)",
        color: "var(--on-primary-container)",
        border: "1px solid transparent",
        borderRadius: "var(--card-radius)",
      }}
    >
      <Icon name="fingerprint" style={{ fontSize: 22, color: "var(--primary)", flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 14, fontWeight: 600 }}>{t("subs.identityNotice.title")}</div>
        <div style={{ fontSize: 13, lineHeight: 1.5, marginTop: 4 }}>
          {t("subs.identityNotice.body")}
        </div>
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 10 }}>
          <Btn
            variant="text"
            sm
            onClick={() => {
              window.location.hash = "settings/network";
            }}
          >
            {t("subs.identityNotice.settings")}
          </Btn>
          <Btn variant="tonal" sm onClick={() => void setSetting("identityNoticeDismissed", true)}>
            {t("subs.identityNotice.dismiss")}
          </Btn>
        </div>
      </div>
    </div>
  );
}
