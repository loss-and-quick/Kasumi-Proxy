import { Card, SectionLabel } from "../../../components";
import type { CoreEngine, Protocol } from "../../../generated/bindings";
import { CORE_ENGINE_OPTS, PROTOCOL_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import { protocolLabel } from "../helpers";

export function CoresSection({
  coreFor,
  setCoreFor,
}: {
  coreFor: (protocol: Protocol) => CoreEngine;
  setCoreFor: (protocol: Protocol, value: CoreEngine) => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.cores")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginBottom: 10 }}>
          {t("settings.coresHint")}
        </div>
        {PROTOCOL_OPTS.map((protocol) => (
          <div
            key={protocol}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              padding: "5px 0",
            }}
          >
            <span style={{ fontSize: 13.5, color: "var(--on-surface)" }}>
              {protocolLabel(t, protocol)}
            </span>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {(protocol === "hysteria2" || protocol === "tuic") && (
                <span style={{ fontSize: 11, color: "var(--on-surface-faint)" }}>
                  {t("settings.coreLockedSingbox")}
                </span>
              )}
              <select
                className="select-box"
                style={{ width: 130, flex: "0 0 auto" }}
                value={coreFor(protocol)}
                disabled={protocol === "hysteria2" || protocol === "tuic" || protocol === "custom"}
                onChange={(e) => setCoreFor(protocol, e.target.value as CoreEngine)}
              >
                {CORE_ENGINE_OPTS.map((core) => (
                  <option key={core} value={core}>
                    {core}
                  </option>
                ))}
              </select>
            </div>
          </div>
        ))}
      </Card>
    </>
  );
}
