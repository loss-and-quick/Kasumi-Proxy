import { Field, SectionLabel, Select } from "../../../components";
import { useT } from "../../../i18n";
import { type CoreEngineT, CoreSel, PROTOCOLS, type Protocol } from "../../../lib/schema";
import type { FieldErrors, ProfileSetter, ProfileView } from "../types";

const PROTOCOL_LABELS: Record<Protocol, string> = {
  vless: "VLESS",
  vmess: "VMess",
  trojan: "Trojan",
  shadowsocks: "Shadowsocks",
  socks: "SOCKS",
  http: "HTTP",
  wireguard: "WireGuard",
  hysteria2: "Hysteria2",
  tuic: "TUIC",
  anytls: "AnyTLS",
  naive: "Naive",
  shadowtls: "ShadowTLS",
  custom: "Custom config",
};

export function BasicsSection({
  proto,
  v,
  set,
  errors,
  groupOpts,
  changeProtocol,
  engineForced,
  engineHint,
}: {
  proto: Protocol;
  v: ProfileView;
  set: ProfileSetter;
  errors: FieldErrors;
  groupOpts: Array<{ value: string; label: string }>;
  changeProtocol: (proto: Protocol) => void;
  engineForced: CoreEngineT | null;
  engineHint: string;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.basics")}</SectionLabel>
      <Select
        label={t("editor.protocol")}
        value={proto}
        options={PROTOCOLS.map((protocol) => ({
          value: protocol,
          label: PROTOCOL_LABELS[protocol],
        }))}
        onChange={(value) => changeProtocol(value as Protocol)}
      />
      <Field
        label={t("editor.remarks")}
        mono={false}
        value={v.remarks}
        onChange={(value) => set({ remarks: value })}
        error={errors.remarks}
      />

      {proto !== "custom" && (
        <div className="input-row" style={{ marginBottom: 14 }}>
          <Field
            label={t("editor.address")}
            value={v.address ?? ""}
            onChange={(value) => set({ address: value })}
            error={errors.address}
          />
          <div style={{ width: 96, flex: "0 0 auto" }}>
            <Field
              label={t("editor.port")}
              type="number"
              value={v.port ?? 443}
              onChange={(value) => set({ port: Number(value) })}
              error={errors.port}
            />
          </div>
        </div>
      )}

      <Select
        label={t("editor.group")}
        value={v.groupId}
        options={groupOpts}
        onChange={(value) => set({ groupId: value })}
      />

      {/* When the profile is forced onto one engine, pin the selector to that
          engine (not "global" or a stale stored choice) and disable it. */}
      <Select
        label={t("editor.engine")}
        value={engineForced ?? v.coreType ?? "global"}
        disabled={engineForced != null}
        options={CoreSel.options.map((option) => ({
          value: option,
          label: option === "global" ? t("editor.engineGlobal") : option,
        }))}
        onChange={(value) => set({ coreType: value })}
        hint={engineHint}
      />
    </>
  );
}
