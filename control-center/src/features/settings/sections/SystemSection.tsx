import { Card, Icon, ListRow, RowToggle, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

export function SystemSection({
  settings,
  set,
  onOpenBackup,
  onOpenLogs,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
  onOpenBackup: () => void;
  onOpenLogs: () => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.system")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <RowToggle
          icon="autorenew"
          title={t("settings.autoStart")}
          sub={t("settings.autoStartSub")}
          on={settings.autoStart ?? true}
          onChange={(value) => set("autoStart", value)}
        />
        <ListRow
          icon="backup"
          title={t("settings.backup")}
          sub={t("settings.backupSub")}
          onClick={onOpenBackup}
          right={<Icon name="chevron_right" style={{ color: "var(--on-surface-faint)" }} />}
        />
        <ListRow
          icon="description"
          title={t("settings.connectionLog")}
          sub={t("settings.connectionLogSub")}
          onClick={onOpenLogs}
          right={<Icon name="chevron_right" style={{ color: "var(--on-surface-faint)" }} />}
        />
        <div style={{ padding: "12px 0 4px" }}>
          <div className="field-label">{t("settings.logLevel")}</div>
          <select
            className="select-box"
            value={settings.logLevel ?? "warning"}
            onChange={(e) =>
              set("logLevel", e.target.value as NonNullable<AdvancedSettings["logLevel"]>)
            }
          >
            <option value="debug">{t("settings.logLevel.debug")}</option>
            <option value="info">{t("settings.logLevel.info")}</option>
            <option value="warning">{t("settings.logLevel.warning")}</option>
            <option value="error">{t("settings.logLevel.error")}</option>
            <option value="none">{t("settings.logLevel.none")}</option>
          </select>
        </div>
        <div style={{ padding: "12px 0 4px" }}>
          <div className="field-label">{t("settings.logRotateMaxKb")}</div>
          <input
            type="number"
            className="input"
            min={64}
            value={settings.logRotateMaxKb ?? 512}
            onChange={(e) => set("logRotateMaxKb", Number(e.target.value))}
          />
        </div>
      </Card>
    </>
  );
}
