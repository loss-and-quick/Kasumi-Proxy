import { Field, SectionLabel, Select, Switch } from "../../../components";
import { useT } from "../../../i18n";
import { HeaderType, Network } from "../../../lib/schema";
import type { FieldErrors, ProfileSetter, ProfileView } from "../types";

export function TransportSection({
  v,
  set,
  errors,
  needsHostPath,
}: {
  v: ProfileView;
  set: ProfileSetter;
  errors: FieldErrors;
  needsHostPath: boolean;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.transport")}</SectionLabel>
      <Select
        label={t("editor.network")}
        value={v.network ?? "tcp"}
        options={Network.options}
        onChange={(value) => set({ network: value })}
      />
      {(v.network === "tcp" || v.network === "kcp") && (
        <Select
          label={t("editor.headerType")}
          value={v.headerType ?? "none"}
          options={HeaderType.options}
          onChange={(value) => set({ headerType: value })}
        />
      )}
      {v.network === "kcp" && (
        <>
          <Field
            label={t("editor.seed")}
            value={v.kcpSeed ?? ""}
            onChange={(value) => set({ kcpSeed: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.kcpMtu")}
              type="number"
              value={v.kcpMtu ?? 0}
              onChange={(value) => set({ kcpMtu: Number(value) || 0 })}
            />
            <Field
              label={t("editor.kcpTti")}
              type="number"
              value={v.kcpTti ?? 0}
              onChange={(value) => set({ kcpTti: Number(value) || 0 })}
            />
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.kcpUplink")}
              type="number"
              value={v.kcpUplink ?? 0}
              onChange={(value) => set({ kcpUplink: Number(value) || 0 })}
            />
            <Field
              label={t("editor.kcpDownlink")}
              type="number"
              value={v.kcpDownlink ?? 0}
              onChange={(value) => set({ kcpDownlink: Number(value) || 0 })}
            />
          </div>
        </>
      )}
      {v.network === "grpc" ? (
        <>
          <Field
            label={t("editor.authority")}
            value={v.authority ?? ""}
            onChange={(value) => set({ authority: value })}
          />
          <Field
            label={t("editor.serviceName")}
            value={v.serviceName ?? ""}
            onChange={(value) => set({ serviceName: value })}
            error={errors.serviceName}
          />
          <Select
            label={t("editor.grpcMode")}
            value={v.grpcMode ?? ""}
            options={[
              { value: "", label: "gun (single)" },
              { value: "multi", label: "multi" },
            ]}
            onChange={(value) => set({ grpcMode: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.grpcIdleTimeout")}
              type="number"
              value={v.grpcIdleTimeout ?? 0}
              onChange={(value) => set({ grpcIdleTimeout: Number(value) || 0 })}
            />
            <Field
              label={t("editor.grpcHealthCheckTimeout")}
              type="number"
              value={v.grpcHealthCheckTimeout ?? 0}
              onChange={(value) => set({ grpcHealthCheckTimeout: Number(value) || 0 })}
            />
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.grpcPingTimeout")}
              type="number"
              value={v.grpcPingTimeout ?? 0}
              onChange={(value) => set({ grpcPingTimeout: Number(value) || 0 })}
            />
            <Field
              label={t("editor.grpcInitialWindow")}
              type="number"
              value={v.grpcInitialWindowsSize ?? 0}
              onChange={(value) => set({ grpcInitialWindowsSize: Number(value) || 0 })}
            />
          </div>
          <Field
            label={t("editor.userAgent")}
            mono={false}
            value={v.userAgent ?? ""}
            onChange={(value) => set({ userAgent: value })}
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
              on={!!v.grpcPermitWithoutStream}
              onChange={(value) => set({ grpcPermitWithoutStream: value })}
            />
          </div>
        </>
      ) : needsHostPath || v.headerType === "http" ? (
        <>
          <Field
            label={t("editor.host")}
            value={v.host ?? ""}
            onChange={(value) => set({ host: value })}
          />
          <Field
            label={t("editor.path")}
            value={v.path ?? ""}
            onChange={(value) => set({ path: value })}
            error={errors.path}
          />
          {v.network === "ws" && (
            <>
              <div className="input-row" style={{ marginBottom: 14 }}>
                <Field
                  label={t("editor.wsEarlyData")}
                  type="number"
                  value={v.wsEarlyData ?? 0}
                  onChange={(value) => set({ wsEarlyData: Number(value) || 0 })}
                />
                <Field
                  label={t("editor.wsEarlyDataHeader")}
                  mono={false}
                  value={v.wsEarlyDataHeader ?? ""}
                  onChange={(value) => set({ wsEarlyDataHeader: value })}
                />
              </div>
              <Field
                label={t("editor.wsHeartbeatPeriod")}
                type="number"
                value={v.wsHeartbeatPeriod ?? 0}
                onChange={(value) => set({ wsHeartbeatPeriod: Number(value) || 0 })}
              />
            </>
          )}
          {v.network === "xhttp" && (
            <>
              <Select
                label={t("editor.xhttpMode")}
                value={v.xhttpMode ?? ""}
                options={["", "auto", "packet-up", "stream-up", "stream-one"]}
                onChange={(value) => set({ xhttpMode: value })}
              />
              <Field
                area
                label={t("editor.xhttpExtra")}
                value={v.xhttpExtra ?? ""}
                onChange={(value) => set({ xhttpExtra: value })}
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
        <Switch on={!!v.muxEnabled} onChange={(value) => set({ muxEnabled: value })} />
      </div>
    </>
  );
}
