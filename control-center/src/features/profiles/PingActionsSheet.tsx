import { Sheet, SheetAction } from "../../components";
import { useT } from "../../i18n";

export function PingActionsSheet({
  open,
  onClose,
  onTcping,
  onRealping,
  onSpeedTest,
  onDeleteUnreachable,
  onSelectBest,
  pinging,
  speedTesting,
}: {
  open: boolean;
  onClose: () => void;
  onTcping: () => void;
  onRealping: () => void;
  onSpeedTest: () => void;
  onDeleteUnreachable: () => void;
  onSelectBest: () => void;
  pinging: boolean;
  speedTesting: boolean;
}) {
  const t = useT();
  // Any test in progress spins up a core and contends for the exec channel, so
  // block every test action while one runs — not just the matching category.
  const busy = pinging || speedTesting;

  return (
    <Sheet open={open} title={t("profiles.pingSheet.title")} onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <SheetAction
          icon="lan"
          label={t("profiles.pingSheet.tcping")}
          sub={t("profiles.pingSheet.tcpingSub")}
          onClick={onTcping}
          disabled={busy}
        />
        <SheetAction
          icon="travel_explore"
          label={t("profiles.pingSheet.realping")}
          sub={t("profiles.pingSheet.realpingSub")}
          onClick={onRealping}
          disabled={busy}
        />
        <SheetAction
          icon="speed"
          label={t("profiles.pingSheet.speedtest")}
          sub={t("profiles.pingSheet.speedtestSub")}
          onClick={onSpeedTest}
          disabled={busy}
        />
        <div className="divider" />
        <SheetAction
          icon="wifi_off"
          label={t("profiles.pingSheet.deleteUnreachable")}
          sub={t("profiles.pingSheet.deleteUnreachableSub")}
          onClick={onDeleteUnreachable}
        />
        <SheetAction
          icon="stars"
          label={t("profiles.pingSheet.selectBest")}
          sub={t("profiles.pingSheet.selectBestSub")}
          onClick={onSelectBest}
        />
      </div>
    </Sheet>
  );
}
