import { Field, SectionLabel, Select, Switch } from "../../../components";
import type { HeaderType, Transport } from "../../../generated/bindings";
import { HEADER_TYPE_OPTS, NETWORK_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { FieldErrors, TransportSetter } from "../types";

const headersToText = (h?: Record<string, string>) =>
  Object.entries(h ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
const textToHeaders = (s: string): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const line of s.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
};

export function TransportSection({
  transport,
  setTransport,
  mux,
  setMux,
  errors,
  needsHostPath,
}: {
  transport: Transport;
  setTransport: TransportSetter;
  mux: boolean;
  setMux: (value: boolean) => void;
  errors: FieldErrors;
  needsHostPath: boolean;
}) {
  const t = useT();
  // Merge a field patch into the current transport variant (keeps `kind`).
  const patch = (p: object) => setTransport({ ...transport, ...p } as Transport);
  const kind = transport.kind;
  const headerType = "headerType" in transport ? transport.headerType : undefined;
  const host = "host" in transport ? (transport.host ?? "") : "";
  const path = "path" in transport ? (transport.path ?? "") : "";

  return (
    <>
      <SectionLabel>{t("editor.transport")}</SectionLabel>
      <Select
        label={t("editor.network")}
        value={kind}
        options={NETWORK_OPTS}
        // The tagged union shares no fields, so switching network starts a fresh
        // variant (defaults filled by serde on save).
        onChange={(value) => setTransport({ kind: value } as Transport)}
      />
      {(kind === "tcp" || kind === "kcp") && (
        <Select
          label={t("editor.headerType")}
          value={headerType ?? "none"}
          options={HEADER_TYPE_OPTS}
          onChange={(value) => patch({ headerType: value as HeaderType })}
        />
      )}
      {transport.kind === "kcp" && (
        <>
          <Field
            label={t("editor.seed")}
            value={transport.seed ?? ""}
            onChange={(value) => patch({ seed: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.kcpMtu")}
              type="number"
              value={transport.mtu ?? 0}
              onChange={(value) => patch({ mtu: Number(value) || 0 })}
            />
            <Field
              label={t("editor.kcpTti")}
              type="number"
              value={transport.tti ?? 0}
              onChange={(value) => patch({ tti: Number(value) || 0 })}
            />
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.kcpUplink")}
              type="number"
              value={transport.uplink ?? 0}
              onChange={(value) => patch({ uplink: Number(value) || 0 })}
            />
            <Field
              label={t("editor.kcpDownlink")}
              type="number"
              value={transport.downlink ?? 0}
              onChange={(value) => patch({ downlink: Number(value) || 0 })}
            />
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.kcpCwndMultiplier")}
              type="number"
              value={transport.cwndMultiplier ?? 0}
              onChange={(value) => patch({ cwndMultiplier: Number(value) || 0 })}
            />
            <Field
              label={t("editor.kcpMaxSendingWindow")}
              type="number"
              value={transport.maxSendingWindow ?? 0}
              onChange={(value) => patch({ maxSendingWindow: Number(value) || 0 })}
            />
          </div>
        </>
      )}
      {transport.kind === "grpc" ? (
        <>
          <Field
            label={t("editor.authority")}
            value={transport.authority ?? ""}
            onChange={(value) => patch({ authority: value })}
          />
          <Field
            label={t("editor.serviceName")}
            value={transport.serviceName ?? ""}
            onChange={(value) => patch({ serviceName: value })}
            error={errors.serviceName}
          />
          <Select
            label={t("editor.grpcMode")}
            value={transport.mode ?? ""}
            options={[
              { value: "", label: "gun (single)" },
              { value: "multi", label: "multi" },
            ]}
            onChange={(value) => patch({ mode: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.grpcIdleTimeout")}
              type="number"
              value={transport.idleTimeout ?? 0}
              onChange={(value) => patch({ idleTimeout: Number(value) || 0 })}
            />
            <Field
              label={t("editor.grpcHealthCheckTimeout")}
              type="number"
              value={transport.healthCheckTimeout ?? 0}
              onChange={(value) => patch({ healthCheckTimeout: Number(value) || 0 })}
            />
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.grpcPingTimeout")}
              type="number"
              value={transport.pingTimeout ?? 0}
              onChange={(value) => patch({ pingTimeout: Number(value) || 0 })}
            />
            <Field
              label={t("editor.grpcInitialWindow")}
              type="number"
              value={transport.initialWindowSize ?? 0}
              onChange={(value) => patch({ initialWindowSize: Number(value) || 0 })}
            />
          </div>
          <Field
            label={t("editor.userAgent")}
            mono={false}
            value={transport.userAgent ?? ""}
            onChange={(value) => patch({ userAgent: value })}
          />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.grpcPermitWithoutStream")}
            </span>
            <Switch
              on={!!transport.permitWithoutStream}
              onChange={(value) => patch({ permitWithoutStream: value })}
            />
          </div>
        </>
      ) : needsHostPath || headerType === "http" ? (
        <>
          <Field
            label={t("editor.host")}
            value={host}
            onChange={(value) => patch({ host: value })}
          />
          <Field
            label={t("editor.path")}
            value={path}
            onChange={(value) => patch({ path: value })}
            error={errors.path}
          />
          {transport.kind === "ws" && (
            <>
              <div className="input-row" style={{ marginBottom: 14 }}>
                <Field
                  label={t("editor.wsEarlyData")}
                  type="number"
                  value={transport.earlyData ?? 0}
                  onChange={(value) => patch({ earlyData: Number(value) || 0 })}
                />
                <Field
                  label={t("editor.wsEarlyDataHeader")}
                  mono={false}
                  value={transport.earlyDataHeader ?? ""}
                  onChange={(value) => patch({ earlyDataHeader: value })}
                />
              </div>
              <Field
                label={t("editor.wsHeartbeatPeriod")}
                type="number"
                value={transport.heartbeatPeriod ?? 0}
                onChange={(value) => patch({ heartbeatPeriod: Number(value) || 0 })}
              />
              <Field
                area
                label={t("editor.wsHeaders")}
                value={headersToText(transport.headers)}
                onChange={(value) => patch({ headers: textToHeaders(value) })}
              />
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "8px 0",
                }}
              >
                <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
                  {t("editor.acceptProxyProtocol")}
                </span>
                <Switch
                  on={!!transport.acceptProxyProtocol}
                  onChange={(value) => patch({ acceptProxyProtocol: value })}
                />
              </div>
            </>
          )}
          {transport.kind === "xhttp" && (
            <>
              <Select
                label={t("editor.xhttpMode")}
                value={transport.mode ?? ""}
                options={["", "auto", "packet-up", "stream-up", "stream-one"]}
                onChange={(value) => patch({ mode: value })}
              />
              <Field
                area
                label={t("editor.xhttpExtra")}
                value={transport.extra ?? ""}
                onChange={(value) => patch({ extra: value })}
              />
            </>
          )}
        </>
      ) : null}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "8px 0",
        }}
      >
        <span style={{ fontSize: 14, color: "var(--on-surface)" }}>{t("editor.muxEnabled")}</span>
        <Switch on={mux} onChange={setMux} />
      </div>
    </>
  );
}
