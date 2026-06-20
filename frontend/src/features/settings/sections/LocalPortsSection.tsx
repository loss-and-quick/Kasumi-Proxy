import { Card, Field, RowToggle, SectionLabel } from "../../../components";
import { DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT } from "../../../generated/defaults";
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
            value={settings.localSocksPort ?? DEFAULT_LOCAL_SOCKS_PORT}
            type="number"
            onChange={(value) => set("localSocksPort", Number(value))}
          />
          <Field
            label={t("settings.http")}
            value={settings.localHttpPort ?? DEFAULT_LOCAL_HTTP_PORT}
            type="number"
            onChange={(value) => set("localHttpPort", Number(value))}
          />
        </div>
        <RowToggle
          icon="language"
          title={t("settings.allowNonLocalhost")}
          sub={t("settings.allowNonLocalhostSub")}
          on={settings.allowNonLocalhost ?? false}
          onChange={(value) => set("allowNonLocalhost", value)}
        />
      </Card>
    </>
  );
}
