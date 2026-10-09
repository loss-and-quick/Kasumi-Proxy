import { Btn, Card, Icon } from "../../components";
import { useT } from "../../i18n";
import { isServiceUp } from "../../lib/bridge";
import { useAppStore } from "../../store/useAppStore";

/**
 * "Restart to apply", where the change is made. Settings that only take effect
 * on the next start used to say so on Overview alone, so whoever changed DNS or
 * routing here had no sign the running proxy still used the old values.
 */
export function RestartBanner() {
  const t = useT();
  const service = useAppStore((s) => s.service);
  const busy = useAppStore((s) => s.busy);
  const restart = useAppStore((s) => s.restart);
  if (!isServiceUp(service.state) || !service.pendingRestart) return null;
  return (
    <Card
      className="flat"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "10px 12px",
        marginBottom: 12,
        border: "1px solid var(--warn)",
      }}
    >
      <Icon name="restart_alt" style={{ fontSize: 20, color: "var(--warn)" }} />
      <span style={{ flex: 1, minWidth: 0, fontSize: 13, color: "var(--warn)" }}>
        {t("overview.pendingRestart")}
      </span>
      <Btn variant="tonal" sm disabled={busy} onClick={() => void restart()}>
        {t("overview.restart")}
      </Btn>
    </Card>
  );
}
