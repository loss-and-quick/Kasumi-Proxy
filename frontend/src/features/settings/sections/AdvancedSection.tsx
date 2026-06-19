import { Card, Field, SectionLabel } from "../../../components";
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
      <Card style={{ padding: 14 }}>
        <Field
          label={t("settings.delayTestUrl")}
          mono={false}
          value={settings.delayTestUrl ?? ""}
          placeholder={t("settings.delayTestUrlPh")}
          onChange={(value) => set("delayTestUrl", value)}
        />
        <Field
          label={t("settings.pingConcurrency")}
          hint={t("settings.pingConcurrencySub")}
          value={settings.pingConcurrency ?? 3}
          type="number"
          onChange={(value) => set("pingConcurrency", Math.min(20, Math.max(1, Number(value))))}
        />
        <Field
          label={t("settings.speedTestUrl")}
          mono={false}
          value={settings.speedTestUrl ?? ""}
          placeholder={t("settings.speedTestUrlPh")}
          onChange={(value) => set("speedTestUrl", value)}
        />
        <Field
          label={t("settings.speedConcurrency")}
          hint={t("settings.speedConcurrencySub")}
          value={settings.speedConcurrency ?? 1}
          type="number"
          onChange={(value) => set("speedConcurrency", Math.min(5, Math.max(1, Number(value))))}
        />
      </Card>
    </>
  );
}
