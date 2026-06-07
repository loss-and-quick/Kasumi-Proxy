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
}: {
  open: boolean;
  onClose: () => void;
  onTcping: () => void;
  onRealping: () => void;
  onSpeedTest: () => void;
  onDeleteUnreachable: () => void;
  onSelectBest: () => void;
}) {
  const t = useT();

  return (
    <Sheet open={open} title={t("profiles.pingSheet.title")} onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <SheetAction
          icon="lan"
          label={t("profiles.pingSheet.tcping")}
          sub={t("profiles.pingSheet.tcpingSub")}
          onClick={onTcping}
        />
        <SheetAction
          icon="travel_explore"
          label={t("profiles.pingSheet.realping")}
          sub={t("profiles.pingSheet.realpingSub")}
          onClick={onRealping}
        />
        <SheetAction
          icon="speed"
          label={t("profiles.pingSheet.speedtest")}
          sub={t("profiles.pingSheet.speedtestSub")}
          onClick={onSpeedTest}
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
