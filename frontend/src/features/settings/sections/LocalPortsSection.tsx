import { useState } from "react";
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
  // Auth is "on" when either credential is set; the toggle reveals the fields and
  // clears both when turned off. Both must be filled for the backend to enforce it.
  const [authOpen, setAuthOpen] = useState(
    Boolean(settings.socksUsername || settings.socksPassword),
  );
  const toggleAuth = (on: boolean) => {
    setAuthOpen(on);
    if (!on) {
      set("socksUsername", undefined);
      set("socksPassword", undefined);
    }
  };

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
        <div className="field-label" style={{ marginTop: 8 }}>
          {t("settings.security")}
        </div>
        <RowToggle
          icon="lock"
          title={t("settings.socksAuth")}
          on={authOpen}
          onChange={toggleAuth}
        />
        {authOpen && (
          <div className="input-row" style={{ marginTop: 10 }}>
            <Field
              label={t("settings.socksUser")}
              value={settings.socksUsername ?? ""}
              onChange={(value) => set("socksUsername", value || undefined)}
            />
            <Field
              label={t("settings.socksPass")}
              value={settings.socksPassword ?? ""}
              type="password"
              onChange={(value) => set("socksPassword", value || undefined)}
            />
          </div>
        )}
      </Card>
    </>
  );
}
