import { Card, Field, RowToggle, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

export function DnsSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.dns")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <RowToggle
          icon="dns"
          title={t("settings.dnsViaProxy")}
          sub={t("settings.dnsViaProxySub")}
          on={settings.dnsViaProxy}
          onChange={(value) => set("dnsViaProxy", value)}
        />
        <RowToggle
          icon="smart_toy"
          title={t("settings.fakeDns")}
          sub={t("settings.fakeDnsSub")}
          on={settings.fakeDns}
          onChange={(value) => set("fakeDns", value)}
        />
        <RowToggle
          icon="public"
          title={t("settings.ipv6")}
          sub={t("settings.ipv6Sub")}
          on={!!settings.ipv6Enabled}
          onChange={(value) => set("ipv6Enabled", value)}
        />
        <RowToggle
          icon="swap_vert"
          title={t("settings.preferIpv6")}
          sub={t("settings.preferIpv6Sub")}
          on={settings.preferIpv6}
          onChange={(value) => set("preferIpv6", value)}
        />
        <div style={{ padding: "8px 4px 4px" }}>
          <Field
            label={t("settings.dnsRemote")}
            value={settings.remoteDns ?? ""}
            placeholder={t("settings.dnsRemotePh")}
            mono={false}
            onChange={(value) => set("remoteDns", value)}
          />
          <Field
            label={t("settings.dnsDomestic")}
            value={settings.domesticDns ?? ""}
            placeholder={t("settings.dnsDomesticPh")}
            mono={false}
            onChange={(value) => set("domesticDns", value)}
          />
          <Field
            area
            label={t("settings.dnsHosts")}
            value={settings.dnsHosts ?? ""}
            placeholder={t("settings.dnsHostsPh")}
            hint={t("settings.dnsHostsHint")}
            onChange={(value) => set("dnsHosts", value)}
          />
        </div>
      </Card>
    </>
  );
}
