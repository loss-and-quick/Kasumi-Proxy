import { useEffect, useState } from "react";
import { Card, Field, Icon, ListRow, RowToggle, SectionLabel, Select } from "../../../components";
import { DEFAULT_LOG_ROTATE_KB } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import {
  autostartSupported,
  isAutostartEnabled,
  setAutostartEnabled,
} from "../../../lib/autostart";
import type { AdvancedSettings } from "../../../lib/bridge";

/** Desktop-only "launch the app on login" toggle (OS-level, via the autostart
 * plugin). Renders nothing where unsupported (the Android WebUI). */
function LaunchOnLoginRow() {
  const t = useT();
  const [on, setOn] = useState(false);

  useEffect(() => {
    let alive = true;
    void isAutostartEnabled().then((v) => {
      if (alive) setOn(v);
    });
    return () => {
      alive = false;
    };
  }, []);

  if (!autostartSupported()) return null;

  return (
    <RowToggle
      icon="autorenew"
      title={t("settings.launchOnLogin")}
      sub={t("settings.launchOnLoginSub")}
      on={on}
      onChange={(value) => {
        setOn(value); // optimistic; revert if the plugin call fails
        void setAutostartEnabled(value).catch(() => setOn(!value));
      }}
    />
  );
}

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
        <LaunchOnLoginRow />
        <RowToggle
          icon="content_cut"
          title={t("settings.dedupOnUpdate")}
          sub={t("settings.dedupOnUpdateSub")}
          on={settings.dedupOnUpdate ?? false}
          onChange={(value) => set("dedupOnUpdate", value)}
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
          <Select
            label={t("settings.logLevel")}
            value={settings.logLevel ?? "warning"}
            onChange={(v) => set("logLevel", v as NonNullable<AdvancedSettings["logLevel"]>)}
            options={[
              { value: "debug", label: t("settings.logLevel.debug") },
              { value: "info", label: t("settings.logLevel.info") },
              { value: "warning", label: t("settings.logLevel.warning") },
              { value: "error", label: t("settings.logLevel.error") },
              { value: "none", label: t("settings.logLevel.none") },
            ]}
          />
        </div>
        <div style={{ padding: "12px 0 4px" }}>
          <Field
            label={t("settings.logRotateMaxKb")}
            type="number"
            min={64}
            value={settings.logRotateMaxKb ?? DEFAULT_LOG_ROTATE_KB}
            onChange={(v) => set("logRotateMaxKb", Number(v))}
          />
        </div>
      </Card>
    </>
  );
}
