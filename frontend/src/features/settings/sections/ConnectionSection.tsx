import {
  Card,
  Field,
  RowToggle,
  SectionLabel,
  Segmented,
  SettingGroup,
  SettingRow,
} from "../../../components";
import type { SingboxFragment } from "../../../generated/bindings";
import { SINGBOX_FRAGMENT_OPTS } from "../../../generated/defaults";
import { type DictKey, useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

// Labels for the sing-box fragment methods; the methods themselves come from Rust.
const SINGBOX_FRAGMENT_LABEL: Record<SingboxFragment, DictKey> = {
  record: "settings.singboxFragment.record",
  segment: "settings.singboxFragment.segment",
  both: "settings.singboxFragment.both",
};

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
          <SettingGroup>
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
            <SettingRow title={t("settings.quicInMux")}>
              <Segmented
                size="sm"
                ariaLabel={t("settings.quicInMux")}
                value={settings.muxXudp443 ?? "reject"}
                onChange={(v) => set("muxXudp443", v)}
                options={[
                  { value: "reject", label: t("settings.quicReject") },
                  { value: "proxy", label: t("settings.quicProxy") },
                ]}
              />
            </SettingRow>
          </SettingGroup>
        )}
        <RowToggle
          icon="shield_moon"
          title={t("settings.fragment")}
          sub={t("settings.fragmentSub")}
          on={settings.fragment}
          onChange={(value) => set("fragment", value)}
        />
        {settings.fragment && (
          <SettingGroup>
            <SettingRow title={t("settings.fragmentPackets")}>
              <Segmented
                size="sm"
                ariaLabel={t("settings.fragmentPackets")}
                value={settings.fragmentPackets}
                onChange={(v) => set("fragmentPackets", v)}
                options={[
                  { value: "tlshello", label: t("settings.fragmentPackets.tlshello") },
                  { value: "1-3", label: t("settings.fragmentPackets.1-3") },
                  { value: "1-2", label: t("settings.fragmentPackets.1-2") },
                ]}
              />
            </SettingRow>
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
            <SettingRow
              title={t("settings.singboxFragment")}
              hint={t("settings.singboxFragmentSub")}
            >
              <Segmented
                size="sm"
                ariaLabel={t("settings.singboxFragment")}
                value={settings.singboxFragment}
                onChange={(v) => set("singboxFragment", v)}
                options={SINGBOX_FRAGMENT_OPTS.map((value) => ({
                  value,
                  label: t(SINGBOX_FRAGMENT_LABEL[value]),
                }))}
              />
            </SettingRow>
          </SettingGroup>
        )}
      </Card>
    </>
  );
}
