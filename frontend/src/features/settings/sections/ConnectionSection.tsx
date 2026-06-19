import { Card, Field, RowToggle, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

export function ConnectionSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.connection")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <RowToggle
          icon="alt_route"
          title={t("settings.mux")}
          sub={t("settings.muxSub")}
          on={settings.mux}
          onChange={(value) => set("mux", value)}
        />
        {settings.mux && (
          <div style={{ padding: "0 4px 12px 54px" }}>
            <Field
              label={t("settings.muxConcurrency")}
              value={settings.muxConcurrency}
              type="number"
              onChange={(value) => set("muxConcurrency", Number(value))}
            />
            <Field
              label={t("settings.xudpConcurrency")}
              value={settings.muxXudpConcurrency ?? ""}
              type="number"
              placeholder="8"
              onChange={(value) => set("muxXudpConcurrency", Number(value))}
            />
            <div className="field-label">{t("settings.quicInMux")}</div>
            <select
              className="select-box"
              value={settings.muxXudp443 ?? "reject"}
              onChange={(e) =>
                set("muxXudp443", e.target.value as NonNullable<AdvancedSettings["muxXudp443"]>)
              }
            >
              <option value="reject">{t("settings.quicReject")}</option>
              <option value="proxy">{t("settings.quicProxy")}</option>
            </select>
          </div>
        )}
        <RowToggle
          icon="shield_moon"
          title={t("settings.fragment")}
          sub={t("settings.fragmentSub")}
          on={settings.fragment}
          onChange={(value) => set("fragment", value)}
        />
        {settings.fragment && (
          <div style={{ padding: "0 4px 12px 54px" }}>
            <div className="field-label">{t("settings.fragmentPackets")}</div>
            <select
              className="select-box"
              value={settings.fragmentPackets}
              onChange={(e) => set("fragmentPackets", e.target.value)}
            >
              <option value="tlshello">{t("settings.fragmentPackets.tlshello")}</option>
              <option value="1-3">{t("settings.fragmentPackets.1-3")}</option>
              <option value="1-2">{t("settings.fragmentPackets.1-2")}</option>
            </select>
            <Field
              label={t("settings.fragmentLength")}
              value={settings.fragmentLength ?? "50-100"}
              onChange={(value) => set("fragmentLength", value)}
              mono={false}
            />
            <Field
              label={t("settings.fragmentDelay")}
              value={settings.fragmentDelay ?? "10-20"}
              onChange={(value) => set("fragmentDelay", value)}
              mono={false}
            />
          </div>
        )}
        <div style={{ padding: "8px 4px 12px" }}>
          <Field
            label={t("settings.tunMtu")}
            value={settings.mtu}
            type="number"
            onChange={(value) => set("mtu", Number(value))}
          />
        </div>
      </Card>
    </>
  );
}
