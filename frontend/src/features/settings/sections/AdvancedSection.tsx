import { Card, Field, RowToggle, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

export function AdvancedSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.advanced")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <RowToggle
          icon="speed"
          title={t("settings.connectivityCheck")}
          sub={t("settings.connectivityCheckSub")}
          on={settings.connectivityCheck ?? true}
          onChange={(value) => set("connectivityCheck", value)}
        />
      </Card>
      <Card style={{ padding: 14, marginTop: 12 }}>
        <Field
          commitOnBlur
          label={t("settings.delayTestUrl")}
          mono={false}
          value={settings.delayTestUrl ?? ""}
          placeholder={t("settings.delayTestUrlPh")}
          onChange={(value) => set("delayTestUrl", value)}
        />
        <Field
          commitOnBlur
          label={t("settings.pingConcurrency")}
          hint={t("settings.pingConcurrencySub")}
          value={settings.pingConcurrency ?? 3}
          type="number"
          onChange={(value) => set("pingConcurrency", Math.min(20, Math.max(1, Number(value))))}
        />
        <Field
          commitOnBlur
          label={t("settings.connectivityCheckTimeout")}
          hint={t("settings.connectivityCheckTimeoutSub")}
          value={settings.connectivityCheckTimeoutMs ?? 8000}
          type="number"
          onChange={(value) =>
            set("connectivityCheckTimeoutMs", Math.min(60000, Math.max(1000, Number(value))))
          }
        />
        <Field
          commitOnBlur
          label={t("settings.speedTestUrl")}
          mono={false}
          value={settings.speedTestUrl ?? ""}
          placeholder={t("settings.speedTestUrlPh")}
          onChange={(value) => set("speedTestUrl", value)}
        />
        <Field
          commitOnBlur
          label={t("settings.speedConcurrency")}
          hint={t("settings.speedConcurrencySub")}
          value={settings.speedConcurrency ?? 1}
          type="number"
          onChange={(value) => set("speedConcurrency", Math.min(5, Math.max(1, Number(value))))}
        />
        <Field
          commitOnBlur
          label={t("settings.speedTestTimeout")}
          hint={t("settings.speedTestTimeoutSub")}
          value={settings.speedTestTimeoutMs ?? 15000}
          type="number"
          onChange={(value) =>
            set("speedTestTimeoutMs", Math.min(120000, Math.max(5000, Number(value))))
          }
        />
      </Card>
    </>
  );
}
