import { Card, Field, RowToggle, SectionLabel } from "../../../components";
import {
  DEFAULT_CONNECTIVITY_CHECK_TIMEOUT_MS,
  DEFAULT_SPEED_TEST_TIMEOUT_MS,
  MAX_CONNECTIVITY_CHECK_TIMEOUT_MS,
  MAX_SPEED_TEST_TIMEOUT_MS,
  MIN_CONNECTIVITY_CHECK_TIMEOUT_MS,
  MIN_SPEED_TEST_TIMEOUT_MS,
} from "../../../generated/defaults";
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
          value={settings.connectivityCheckTimeoutMs ?? DEFAULT_CONNECTIVITY_CHECK_TIMEOUT_MS}
          type="number"
          onChange={(value) =>
            set(
              "connectivityCheckTimeoutMs",
              Math.min(
                MAX_CONNECTIVITY_CHECK_TIMEOUT_MS,
                Math.max(MIN_CONNECTIVITY_CHECK_TIMEOUT_MS, Number(value)),
              ),
            )
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
          value={settings.speedTestTimeoutMs ?? DEFAULT_SPEED_TEST_TIMEOUT_MS}
          type="number"
          onChange={(value) =>
            set(
              "speedTestTimeoutMs",
              Math.min(
                MAX_SPEED_TEST_TIMEOUT_MS,
                Math.max(MIN_SPEED_TEST_TIMEOUT_MS, Number(value)),
              ),
            )
          }
        />
      </Card>
    </>
  );
}
