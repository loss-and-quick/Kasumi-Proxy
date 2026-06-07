import { Card, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import { CoreEngine, type CoreEngineT, PROTOCOLS, type Protocol } from "../../../lib/schema";
import { protocolLabel } from "../helpers";

export function CoresSection({
  coreFor,
  setCoreFor,
}: {
  coreFor: (protocol: Protocol) => CoreEngineT;
  setCoreFor: (protocol: Protocol, value: CoreEngineT) => void;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("settings.cores")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginBottom: 10 }}>
          {t("settings.coresHint")}
        </div>
        {PROTOCOLS.map((protocol) => (
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
            <select
              className="select-box"
              style={{ width: 130, flex: "0 0 auto" }}
              value={coreFor(protocol)}
              disabled={protocol === "hysteria2" || protocol === "tuic" || protocol === "custom"}
              onChange={(e) => setCoreFor(protocol, e.target.value as CoreEngineT)}
            >
              {CoreEngine.options.map((core) => (
                <option key={core} value={core}>
                  {core}
                </option>
              ))}
            </select>
          </div>
        ))}
      </Card>
    </>
  );
}
