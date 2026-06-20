import { Field, Select, Switch } from "../../../components";
import type { Profile } from "../../../generated/bindings";
import {
  CONGESTION_OPTS,
  FLOW_OPTS,
  HYSTERIA2_OBFS_OPTS,
  PACKET_ENCODING_OPTS,
  SS_METHOD_OPTS,
  VMESS_ENC_OPTS,
} from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { FieldErrors, RootSetter } from "../types";

const reservedToText = (reserved?: number[]) => (reserved ?? []).join(", ");
const textToReserved = (s: string) =>
  s
    .split(/[\s,]+/)
    .filter(Boolean)
    .map(Number)
    .filter((n) => Number.isFinite(n));

export function CredentialsSection({
  draft,
  setRoot,
  errors,
}: {
  draft: Profile;
  setRoot: RootSetter;
  errors: FieldErrors;
}) {
  const t = useT();

  return (
    <>
      {(draft.protocol === "vless" || draft.protocol === "vmess") && (
        <Field
          label={t("editor.userId")}
          value={draft.uuid ?? ""}
          onChange={(value) => setRoot({ uuid: value })}
          error={errors.uuid}
        />
      )}
      {draft.protocol === "vless" && (
        <>
          <Select
            label={t("editor.flow")}
            value={draft.flow ?? ""}
            options={FLOW_OPTS}
            onChange={(value) => setRoot({ flow: value })}
          />
          <Select
            label={t("editor.packetEncoding")}
            value={draft.packetEncoding ?? ""}
            options={PACKET_ENCODING_OPTS}
            onChange={(value) => setRoot({ packetEncoding: value })}
          />
          <Field
            label={t("editor.encryption")}
            value={draft.encryption ?? "none"}
            onChange={(value) => setRoot({ encryption: value })}
          />
        </>
      )}
      {draft.protocol === "vmess" && (
        <>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Select
              label={t("editor.encryption")}
              value={draft.encryption ?? "auto"}
              options={VMESS_ENC_OPTS}
              onChange={(value) => setRoot({ encryption: value })}
            />
            <div style={{ width: 96, flex: "0 0 auto" }}>
              <Field
                label={t("editor.alterId")}
                type="number"
                value={draft.alterId ?? 0}
                onChange={(value) => setRoot({ alterId: Number(value) })}
              />
            </div>
          </div>
          <Select
            label={t("editor.packetEncoding")}
            value={draft.packetEncoding ?? ""}
            options={PACKET_ENCODING_OPTS}
            onChange={(value) => setRoot({ packetEncoding: value })}
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
              {t("editor.vmessGlobalPadding")}
            </span>
            <Switch
              on={!!draft.vmessGlobalPadding}
              onChange={(value) => setRoot({ vmessGlobalPadding: value })}
            />
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.vmessAuthenticatedLength")}
            </span>
            <Switch
              on={!!draft.vmessAuthenticatedLength}
              onChange={(value) => setRoot({ vmessAuthenticatedLength: value })}
            />
          </div>
        </>
      )}
      {draft.protocol === "trojan" && (
        <>
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.flow")}
            value={draft.flow ?? ""}
            options={FLOW_OPTS}
            onChange={(value) => setRoot({ flow: value })}
          />
        </>
      )}
      {draft.protocol === "shadowsocks" && (
        <>
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.method")}
            value={draft.method ?? "aes-256-gcm"}
            options={SS_METHOD_OPTS}
            onChange={(value) => setRoot({ method: value })}
          />
        </>
      )}
      {(draft.protocol === "socks" || draft.protocol === "http") && (
        <div className="input-row" style={{ marginBottom: 14 }}>
          <Field
            label={t("editor.username")}
            mono={false}
            value={draft.username ?? ""}
            onChange={(value) => setRoot({ username: value })}
          />
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
          />
        </div>
      )}

      {draft.protocol === "wireguard" && (
        <>
          <Field
            label={t("editor.privateKey")}
            value={draft.secretKey ?? ""}
            onChange={(value) => setRoot({ secretKey: value })}
            error={errors.secretKey}
          />
          <Field
            label={t("editor.peerPublicKey")}
            value={draft.peerPublicKey ?? ""}
            onChange={(value) => setRoot({ peerPublicKey: value })}
            error={errors.peerPublicKey}
          />
          <Field
            label={t("editor.preSharedKey")}
            value={draft.preSharedKey ?? ""}
            onChange={(value) => setRoot({ preSharedKey: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.localAddress")}
              mono={false}
              value={draft.localAddress ?? ""}
              onChange={(value) => setRoot({ localAddress: value })}
            />
            <div style={{ width: 110, flex: "0 0 auto" }}>
              <Field
                label={t("editor.reserved")}
                value={reservedToText(draft.reserved)}
                onChange={(value) => setRoot({ reserved: textToReserved(value) })}
              />
            </div>
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.mtu")}
              type="number"
              value={draft.mtu ?? 1420}
              onChange={(value) => setRoot({ mtu: Number(value) })}
            />
            <Field
              label={t("editor.wgWorkers")}
              type="number"
              value={draft.workers ?? 0}
              onChange={(value) => setRoot({ workers: Number(value) || 0 })}
            />
          </div>
          <Field
            label={t("editor.wgPersistentKeepalive")}
            type="number"
            value={draft.persistentKeepalive ?? 0}
            onChange={(value) => setRoot({ persistentKeepalive: Number(value) || 0 })}
          />
        </>
      )}

      {draft.protocol === "hysteria2" && (
        <>
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.obfsType")}
            value={draft.obfsType ?? ""}
            options={HYSTERIA2_OBFS_OPTS}
            onChange={(value) => setRoot({ obfsType: value })}
          />
          {draft.obfsType === "salamander" && (
            <Field
              label={t("editor.obfsPassword")}
              value={draft.obfsPassword ?? ""}
              onChange={(value) => setRoot({ obfsPassword: value })}
            />
          )}
          <Field
            label={t("editor.ports")}
            value={draft.ports ?? ""}
            placeholder="20000-50000"
            onChange={(value) => setRoot({ ports: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.hopInterval")}
              type="number"
              value={draft.hopInterval ?? ""}
              placeholder="30"
              onChange={(value) => setRoot({ hopInterval: value })}
            />
            <Field
              label={t("editor.upMbps")}
              type="number"
              value={draft.upMbps ?? 0}
              onChange={(value) => setRoot({ upMbps: Number(value) })}
            />
            <Field
              label={t("editor.downMbps")}
              type="number"
              value={draft.downMbps ?? 0}
              onChange={(value) => setRoot({ downMbps: Number(value) })}
            />
          </div>
          <Field
            label={t("editor.pinSha256")}
            value={draft.pinSha256 ?? ""}
            onChange={(value) => setRoot({ pinSha256: value })}
          />
        </>
      )}
      {draft.protocol === "tuic" && (
        <>
          <Field
            label={t("editor.userId")}
            value={draft.uuid ?? ""}
            onChange={(value) => setRoot({ uuid: value })}
            error={errors.uuid}
          />
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.congestion")}
            value={draft.congestionControl ?? "bbr"}
            options={CONGESTION_OPTS}
            onChange={(value) => setRoot({ congestionControl: value })}
          />
          <Select
            label={t("editor.tuicUdpRelayMode")}
            value={draft.udpRelayMode ?? ""}
            options={["", "native", "quic"]}
            onChange={(value) => setRoot({ udpRelayMode: value })}
          />
          <Select
            label={t("editor.tuicZeroRtt")}
            value={draft.zeroRtt ? "on" : "off"}
            options={[
              { value: "off", label: "off" },
              { value: "on", label: "on" },
            ]}
            onChange={(value) => setRoot({ zeroRtt: value === "on" })}
          />
          <Select
            label={t("editor.tuicUdpOverStream")}
            value={draft.udpOverStream ? "on" : "off"}
            options={[
              { value: "off", label: "off" },
              { value: "on", label: "on" },
            ]}
            onChange={(value) => setRoot({ udpOverStream: value === "on" })}
          />
          <Field
            label={t("editor.tuicHeartbeat")}
            value={draft.heartbeat ?? ""}
            placeholder="10s"
            onChange={(value) => setRoot({ heartbeat: value })}
          />
        </>
      )}

      {draft.protocol === "anytls" && (
        <>
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
            error={errors.password}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.anytlsIdleCheckInterval")}
              value={draft.idleSessionCheckInterval ?? ""}
              placeholder="1m"
              onChange={(value) => setRoot({ idleSessionCheckInterval: value })}
            />
            <Field
              label={t("editor.anytlsIdleTimeout")}
              value={draft.idleSessionTimeout ?? ""}
              placeholder="30s"
              onChange={(value) => setRoot({ idleSessionTimeout: value })}
            />
          </div>
          <Field
            label={t("editor.anytlsMinIdle")}
            type="number"
            value={draft.minIdleSession ?? 0}
            onChange={(value) => setRoot({ minIdleSession: Number(value) || 0 })}
          />
        </>
      )}

      {draft.protocol === "naive" && (
        <>
          <Field
            label={t("editor.username")}
            mono={false}
            value={draft.username ?? ""}
            onChange={(value) => setRoot({ username: value })}
          />
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.congestion")}
            value={draft.congestionControl ?? "bbr"}
            options={CONGESTION_OPTS}
            onChange={(value) => setRoot({ congestionControl: value })}
          />
          <Select
            label={t("editor.naiveTransport")}
            value={draft.naiveQuic ? "quic" : "https"}
            options={[
              { value: "https", label: t("editor.naiveTransportHttps") },
              { value: "quic", label: t("editor.naiveTransportQuic") },
            ]}
            onChange={(value) => setRoot({ naiveQuic: value === "quic" })}
          />
          <Field
            label={t("editor.naiveInsecureConcurrency")}
            type="number"
            value={draft.insecureConcurrency ?? 0}
            onChange={(value) => setRoot({ insecureConcurrency: Number(value) })}
          />
        </>
      )}

      {draft.protocol === "shadowtls" && (
        <>
          <Field
            label={t("editor.password")}
            value={draft.password ?? ""}
            onChange={(value) => setRoot({ password: value })}
          />
          <Field
            label={t("editor.shadowtlsVersion")}
            type="number"
            value={draft.version ?? 3}
            onChange={(value) => setRoot({ version: Number(value) })}
          />
        </>
      )}
    </>
  );
}
