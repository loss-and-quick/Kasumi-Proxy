import { Card, Field, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

export function LocalPortsSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.localPorts")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <div className="input-row" style={{ marginBottom: 14 }}>
          <Field
            label={t("settings.socks")}
            value={settings.localSocksPort ?? 10808}
            type="number"
            onChange={(value) => set("localSocksPort", Number(value))}
          />
          <Field
            label={t("settings.http")}
            value={settings.localHttpPort ?? 10809}
            type="number"
            onChange={(value) => set("localHttpPort", Number(value))}
          />
        </div>
      </Card>
    </>
  );
}
