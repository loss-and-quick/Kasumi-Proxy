import { Card, ListRow, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";

export function DiagnosticsSection({
  bridgeMode,
  core,
  profilesCount,
  subscriptionsCount,
  activeId,
}: {
  bridgeMode: string;
  core: string;
  profilesCount: number;
  subscriptionsCount: number;
  activeId: string | null;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.diagnostics")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <ListRow icon="link" title={t("settings.bridge")} sub={bridgeMode} />
        <ListRow icon="memory" title={t("settings.core")} sub={core || t("common.xrayCore")} />
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
