import { Field, Select } from "../../../components";
import { useT } from "../../../i18n";
import {
  CongestionControl,
  Flow,
  Hysteria2Obfs,
  PacketEncoding,
  type Protocol,
  SsMethod,
  VmessEnc,
} from "../../../lib/schema";
import type { FieldErrors, ProfileSetter, ProfileView } from "../types";

export function CredentialsSection({
  proto,
  v,
  set,
  errors,
}: {
  proto: Protocol;
  v: ProfileView;
  set: ProfileSetter;
  errors: FieldErrors;
}) {
  const t = useT();

  return (
    <>
      {(proto === "vless" || proto === "vmess") && (
        <Field
          label={t("editor.userId")}
          value={v.uuid ?? ""}
          onChange={(value) => set({ uuid: value })}
          error={errors.uuid}
        />
      )}
      {proto === "vless" && (
        <>
          <Select
            label={t("editor.flow")}
            value={v.flow ?? ""}
            options={Flow.options}
            onChange={(value) => set({ flow: value })}
          />
          <Select
            label={t("editor.packetEncoding")}
            value={v.packetEncoding ?? ""}
            options={PacketEncoding.options}
            onChange={(value) => set({ packetEncoding: value })}
          />
          <Field
            label={t("editor.encryption")}
            value={v.encryption ?? "none"}
            onChange={(value) => set({ encryption: value })}
          />
        </>
      )}
      {proto === "vmess" && (
        <>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Select
              label={t("editor.encryption")}
              value={v.encryption ?? "auto"}
              options={VmessEnc.options}
              onChange={(value) => set({ encryption: value })}
            />
            <div style={{ width: 96, flex: "0 0 auto" }}>
              <Field
                label={t("editor.alterId")}
                type="number"
                value={v.alterId ?? 0}
                onChange={(value) => set({ alterId: Number(value) })}
              />
            </div>
          </div>
          <Select
            label={t("editor.packetEncoding")}
            value={v.packetEncoding ?? ""}
            options={PacketEncoding.options}
            onChange={(value) => set({ packetEncoding: value })}
          />
        </>
      )}
      {proto === "trojan" && (
        <>
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.flow")}
            value={v.flow ?? ""}
            options={Flow.options}
            onChange={(value) => set({ flow: value })}
          />
        </>
      )}
      {proto === "shadowsocks" && (
        <>
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.method")}
            value={v.method ?? "aes-256-gcm"}
            options={SsMethod.options}
            onChange={(value) => set({ method: value })}
          />
        </>
      )}
      {(proto === "socks" || proto === "http") && (
        <div className="input-row" style={{ marginBottom: 14 }}>
          <Field
            label={t("editor.username")}
            mono={false}
            value={v.username ?? ""}
            onChange={(value) => set({ username: value })}
          />
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
          />
        </div>
      )}

      {proto === "wireguard" && (
        <>
          <Field
            label={t("editor.privateKey")}
            value={v.secretKey ?? ""}
            onChange={(value) => set({ secretKey: value })}
            error={errors.secretKey}
          />
          <Field
            label={t("editor.peerPublicKey")}
            value={v.peerPublicKey ?? ""}
            onChange={(value) => set({ peerPublicKey: value })}
            error={errors.peerPublicKey}
          />
          <Field
            label={t("editor.preSharedKey")}
            value={v.preSharedKey ?? ""}
            onChange={(value) => set({ preSharedKey: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.localAddress")}
              mono={false}
              value={v.localAddress ?? ""}
              onChange={(value) => set({ localAddress: value })}
            />
            <div style={{ width: 110, flex: "0 0 auto" }}>
              <Field
                label={t("editor.reserved")}
                value={v.reserved ?? ""}
                onChange={(value) => set({ reserved: value })}
              />
            </div>
          </div>
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.mtu")}
              type="number"
              value={v.mtu ?? 1420}
              onChange={(value) => set({ mtu: Number(value) })}
            />
            <Field
              label={t("editor.wgWorkers")}
              type="number"
              value={v.workers ?? 0}
              onChange={(value) => set({ workers: Number(value) || 0 })}
            />
          </div>
          <Field
            label={t("editor.wgPersistentKeepalive")}
            type="number"
            value={v.persistentKeepalive ?? 0}
            onChange={(value) => set({ persistentKeepalive: Number(value) || 0 })}
          />
        </>
      )}

      {proto === "hysteria2" && (
        <>
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.obfsType")}
            value={v.obfsType ?? ""}
            options={Hysteria2Obfs.options}
            onChange={(value) => set({ obfsType: value })}
          />
          {v.obfsType === "salamander" && (
            <Field
              label={t("editor.obfsPassword")}
              value={v.obfsPassword ?? ""}
              onChange={(value) => set({ obfsPassword: value })}
            />
          )}
          <Field
            label={t("editor.ports")}
            value={v.ports ?? ""}
            placeholder="20000-50000"
            onChange={(value) => set({ ports: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.hopInterval")}
              type="number"
              value={v.hopInterval ?? ""}
              placeholder="30"
              onChange={(value) => set({ hopInterval: value })}
            />
            <Field
              label={t("editor.upMbps")}
              type="number"
              value={v.upMbps ?? 0}
              onChange={(value) => set({ upMbps: Number(value) })}
            />
            <Field
              label={t("editor.downMbps")}
              type="number"
              value={v.downMbps ?? 0}
              onChange={(value) => set({ downMbps: Number(value) })}
            />
          </div>
          <Field
            label={t("editor.pinSha256")}
            value={v.pinSha256 ?? ""}
            onChange={(value) => set({ pinSha256: value })}
          />
        </>
      )}
      {proto === "tuic" && (
        <>
          <Field
            label={t("editor.userId")}
            value={v.uuid ?? ""}
            onChange={(value) => set({ uuid: value })}
            error={errors.uuid}
          />
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.congestion")}
            value={v.congestionControl ?? "bbr"}
            options={CongestionControl.options}
            onChange={(value) => set({ congestionControl: value })}
          />
          <Select
            label={t("editor.tuicUdpRelayMode")}
            value={v.udpRelayMode ?? ""}
            options={["", "native", "quic"]}
            onChange={(value) => set({ udpRelayMode: value })}
          />
          <Select
            label={t("editor.tuicZeroRtt")}
            value={v.zeroRtt ? "on" : "off"}
            options={[
              { value: "off", label: "off" },
              { value: "on", label: "on" },
            ]}
            onChange={(value) => set({ zeroRtt: value === "on" })}
          />
          <Select
            label={t("editor.tuicUdpOverStream")}
            value={v.udpOverStream ? "on" : "off"}
            options={[
              { value: "off", label: "off" },
              { value: "on", label: "on" },
            ]}
            onChange={(value) => set({ udpOverStream: value === "on" })}
          />
          <Field
            label={t("editor.tuicHeartbeat")}
            value={v.heartbeat ?? ""}
            placeholder="10s"
            onChange={(value) => set({ heartbeat: value })}
          />
        </>
      )}

      {proto === "anytls" && (
        <>
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
            error={errors.password}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.anytlsIdleCheckInterval")}
              value={v.idleSessionCheckInterval ?? ""}
              placeholder="1m"
              onChange={(value) => set({ idleSessionCheckInterval: value })}
            />
            <Field
              label={t("editor.anytlsIdleTimeout")}
              value={v.idleSessionTimeout ?? ""}
              placeholder="30s"
              onChange={(value) => set({ idleSessionTimeout: value })}
            />
          </div>
          <Field
            label={t("editor.anytlsMinIdle")}
            type="number"
            value={v.minIdleSession ?? 0}
            onChange={(value) => set({ minIdleSession: Number(value) || 0 })}
          />
        </>
      )}

      {proto === "naive" && (
        <>
          <Field
            label={t("editor.username")}
            mono={false}
            value={v.username ?? ""}
            onChange={(value) => set({ username: value })}
          />
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
            error={errors.password}
          />
          <Select
            label={t("editor.congestion")}
            value={v.congestionControl ?? "bbr"}
            options={CongestionControl.options}
            onChange={(value) => set({ congestionControl: value })}
          />
          <Select
            label={t("editor.naiveTransport")}
            value={v.naiveQuic ? "quic" : "https"}
            options={[
              { value: "https", label: t("editor.naiveTransportHttps") },
              { value: "quic", label: t("editor.naiveTransportQuic") },
            ]}
            onChange={(value) => set({ naiveQuic: value === "quic" })}
          />
          <Field
            label={t("editor.naiveInsecureConcurrency")}
            type="number"
            value={v.insecureConcurrency ?? 0}
            onChange={(value) => set({ insecureConcurrency: Number(value) })}
          />
        </>
      )}

      {proto === "shadowtls" && (
        <>
          <Field
            label={t("editor.password")}
            value={v.password ?? ""}
            onChange={(value) => set({ password: value })}
          />
          <Field
            label={t("editor.shadowtlsVersion")}
            type="number"
            value={v.version ?? 3}
            onChange={(value) => set({ version: Number(value) })}
          />
        </>
      )}
    </>
  );
}
