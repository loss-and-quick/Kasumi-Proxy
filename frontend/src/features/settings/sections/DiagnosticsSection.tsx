import { Card, ListRow, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";

export function DiagnosticsSection({
  bridgeMode,
  core,
  xrayVersion,
  singboxVersion,
  tun,
  profilesCount,
  subscriptionsCount,
  activeId,
}: {
  bridgeMode: string;
  core: string;
  xrayVersion: string;
  singboxVersion: string;
  tun: boolean;
  profilesCount: number;
  subscriptionsCount: number;
  activeId: string | null;
}) {
  const t = useT();
  const notInstalled = t("common.notInstalled");

  return (
    <>
      <SectionLabel>{t("settings.diagnostics")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <ListRow icon="link" title={t("settings.bridge")} sub={bridgeMode} />
        <ListRow icon="memory" title={t("settings.core")} sub={core || t("common.xrayCore")} />
        <ListRow icon="bolt" title={t("settings.xrayVersion")} sub={xrayVersion || notInstalled} />
        <ListRow
          icon="bolt"
          title={t("settings.singboxVersion")}
          sub={singboxVersion || notInstalled}
        />
        <ListRow
          icon="vpn_lock"
          title={t("settings.tun")}
          sub={tun ? t("common.available") : t("common.unavailable")}
        />
        <ListRow icon="dns" title={t("settings.profiles")} sub={`${profilesCount}`} />
        <ListRow
          icon="cloud_sync"
          title={t("settings.subscriptions")}
          sub={`${subscriptionsCount}`}
        />
        <ListRow
          icon="bookmark"
          title={t("settings.activeProfile")}
          sub={activeId ? t("settings.activeSelected") : t("settings.activeNone")}
        />
      </Card>
    </>
  );
}
