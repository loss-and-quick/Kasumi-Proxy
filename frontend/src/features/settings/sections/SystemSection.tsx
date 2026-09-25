import { useEffect, useState } from "react";
import {
  Card,
  Field,
  NavRow,
  RowToggle,
  SectionLabel,
  Select,
  SettingRow,
} from "../../../components";
import { DEFAULT_LOG_ROTATE_KB } from "../../../generated/defaults";
import { type Lang, LOCALES, useLang, useT } from "../../../i18n";
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
  const { lang, setLang } = useLang();

  return (
    <>
      <SectionLabel>{t("settings.system")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <SettingRow title={t("settings.language")}>
          <Select
            style={{ width: 170 }}
            value={lang}
            onChange={(v) => setLang(v as Lang)}
            options={Object.entries(LOCALES).map(([code, { label }]) => ({
              value: code,
              label,
            }))}
          />
        </SettingRow>
        <RowToggle
          icon="autorenew"
          title={t("settings.autoStart")}
          sub={t("settings.autoStartSub")}
          on={settings.autoStart ?? true}
          onChange={(value) => set("autoStart", value)}
        />
        <LaunchOnLoginRow />
        <RowToggle
          icon="content_copy"
          title={t("settings.dedupOnUpdate")}
          sub={t("settings.dedupOnUpdateSub")}
          on={settings.dedupOnUpdate ?? false}
          onChange={(value) => set("dedupOnUpdate", value)}
        />
        <NavRow
          icon="backup"
          title={t("settings.backup")}
          sub={t("settings.backupSub")}
          onClick={onOpenBackup}
        />
      </Card>

      <SectionLabel>{t("settings.logs")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <NavRow
          icon="description"
          title={t("settings.connectionLog")}
          sub={t("settings.connectionLogSub")}
          onClick={onOpenLogs}
        />
        <SettingRow title={t("settings.logLevel")}>
          <Select
            style={{ width: 150 }}
            value={settings.logLevel ?? "warning"}
            onChange={(v) => set("logLevel", v)}
            options={[
              { value: "debug", label: t("settings.logLevel.debug") },
              { value: "info", label: t("settings.logLevel.info") },
              { value: "warning", label: t("settings.logLevel.warning") },
              { value: "error", label: t("settings.logLevel.error") },
              { value: "none", label: t("settings.logLevel.none") },
            ]}
          />
        </SettingRow>
        <div style={{ padding: "8px 0 0" }}>
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
