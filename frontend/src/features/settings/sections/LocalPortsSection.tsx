import { useState } from "react";
import { Card, Field, RowToggle, SectionLabel } from "../../../components";
import {
  DEFAULT_LOCAL_HTTP_PORT,
  DEFAULT_LOCAL_PAC_PORT,
  DEFAULT_LOCAL_SOCKS_PORT,
} from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { AdvancedSettings, PortCollision } from "../../../lib/bridge";
import { bridge } from "../../../lib/bridge-provider";
import { getRuntimeBridgeMode } from "../../../lib/ksu-webui";

const PORT_LABEL = {
  socks: "settings.socks",
  http: "settings.http",
  pac: "settings.pac",
  force: "settings.portForce",
} as const;

type PortKey = "localSocksPort" | "localHttpPort" | "localPacPort";

export function LocalPortsSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();
  // The PAC port only applies to the desktop `pac` proxy mode.
  const isDesktop = getRuntimeBridgeMode() === "tauri";
  // Auth is "on" when either credential is set; the toggle reveals the fields and
  // clears both when turned off. Both must be filled for the backend to enforce it.
  const [authOpen, setAuthOpen] = useState(
    Boolean(settings.socksUsername || settings.socksPassword),
  );
  // A port that would clash with another listener is not saved; the backend
  // decides, since it knows which listeners this platform runs.
  const [clash, setClash] = useState<PortCollision | null>(null);
  const setPort = async (key: PortKey, value: number) => {
    const found = await bridge.checkLocalPorts({ ...settings, [key]: value }).catch(() => null);
    setClash(found);
    if (!found) set(key, value);
  };
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
            commitOnBlur
            label={t("settings.socks")}
            value={settings.localSocksPort ?? DEFAULT_LOCAL_SOCKS_PORT}
            type="number"
            onChange={(value) => void setPort("localSocksPort", Number(value))}
          />
          <Field
            commitOnBlur
            label={t("settings.http")}
            value={settings.localHttpPort ?? DEFAULT_LOCAL_HTTP_PORT}
            type="number"
            onChange={(value) => void setPort("localHttpPort", Number(value))}
          />
          {isDesktop && (
            <Field
              commitOnBlur
              label={t("settings.pac")}
              value={settings.localPacPort ?? DEFAULT_LOCAL_PAC_PORT}
              type="number"
              onChange={(value) => void setPort("localPacPort", Number(value))}
            />
          )}
        </div>
        {clash && (
          <div className="hint error" style={{ marginTop: -6, marginBottom: 12 }}>
            {t("settings.portCollision", {
              port: clash.port,
              first: t(PORT_LABEL[clash.first]),
              second: t(PORT_LABEL[clash.second]),
            })}
          </div>
        )}
        <RowToggle
          icon="lan"
          title={t("settings.allowNonLocalhost")}
          sub={t("settings.allowNonLocalhostSub")}
          on={settings.allowNonLocalhost ?? false}
          onChange={(value) => set("allowNonLocalhost", value)}
        />
        <div className="field-label" style={{ marginTop: 8 }}>
          {t("settings.security")}
        </div>
        <RowToggle
          icon="shield_moon"
          title={t("settings.socksAuth")}
          on={authOpen}
          onChange={toggleAuth}
        />
        {authOpen && (
          <div className="input-row" style={{ marginTop: 10 }}>
            <Field
              commitOnBlur
              label={t("settings.socksUser")}
              value={settings.socksUsername ?? ""}
              onChange={(value) => set("socksUsername", value || undefined)}
            />
            <Field
              commitOnBlur
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
