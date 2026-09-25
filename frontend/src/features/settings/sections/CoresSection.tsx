import { useState } from "react";
import { Card, SectionLabel, Segmented, SettingRow } from "../../../components";
import type { CoreEngine, Protocol } from "../../../generated/bindings";
import { CORE_ENGINE_OPTS, PROTOCOL_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import {
  applyCoresPreset,
  type CoresPreset,
  coresPreset,
  LOCKED_CORE_PROTOCOLS,
  protocolLabel,
} from "../helpers";

type CoreMap = Partial<Record<Protocol, CoreEngine>>;

export function CoresSection({
  coreByProtocol,
  coreFor,
  setCoreFor,
  setCoreMap,
}: {
  coreByProtocol: CoreMap | undefined;
  coreFor: (protocol: Protocol) => CoreEngine;
  setCoreFor: (protocol: Protocol, value: CoreEngine) => void;
  setCoreMap: (map: CoreMap) => void;
}) {
  const t = useT();
  const stored = coresPreset(coreByProtocol);
  // "Custom" only opens the table; nothing is written until a row is changed.
  const [customOpen, setCustomOpen] = useState(stored === "custom");
  const preset: CoresPreset = customOpen ? "custom" : stored;

  const choose = (next: CoresPreset) => {
    if (next === "custom") {
      setCustomOpen(true);
      return;
    }
    setCustomOpen(false);
    setCoreMap(applyCoresPreset(next));
  };

  return (
    <>
      <SectionLabel>{t("settings.cores")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <SettingRow stacked title={t("settings.coresPreset")} hint={t("settings.coresHint")}>
          <Segmented
            ariaLabel={t("settings.coresPreset")}
            value={preset}
            onChange={choose}
            options={[
              { value: "default", label: t("settings.coresPreset.default") },
              { value: "xray", label: "xray" },
              { value: "sing-box", label: "sing-box" },
              { value: "custom", label: t("settings.coresPreset.custom") },
            ]}
          />
        </SettingRow>
        {preset === "custom" &&
          PROTOCOL_OPTS.map((protocol) => {
            const locked = LOCKED_CORE_PROTOCOLS.includes(protocol);
            return (
              <SettingRow
                key={protocol}
                title={protocolLabel(t, protocol)}
                hint={
                  protocol === "hysteria2" || protocol === "tuic"
                    ? t("settings.coreLockedSingbox")
                    : undefined
                }
              >
                <Segmented
                  size="sm"
                  ariaLabel={protocolLabel(t, protocol)}
                  value={coreFor(protocol)}
                  disabled={locked}
                  onChange={(v) => setCoreFor(protocol, v)}
                  options={[...CORE_ENGINE_OPTS]}
                />
              </SettingRow>
            );
          })}
      </Card>
    </>
  );
}
