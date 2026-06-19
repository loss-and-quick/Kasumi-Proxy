import { Field, SectionLabel, Select } from "../../../components";
import type { CoreEngine, Profile, Protocol } from "../../../generated/bindings";
import { CORE_ENGINE_OPTS, PROTOCOL_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { EndpointSetter, FieldErrors, MetaSetter } from "../types";

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

// UI sentinel for "resolve by protocol/global settings" (nested `coreType` is null).
const CORE_SEL = ["global", ...CORE_ENGINE_OPTS] as const;

export function BasicsSection({
  draft,
  setMeta,
  setEndpoint,
  errors,
  groupOpts,
  changeProtocol,
  engineForced,
  engineHint,
}: {
  draft: Profile;
  setMeta: MetaSetter;
  setEndpoint: EndpointSetter;
  errors: FieldErrors;
  groupOpts: Array<{ value: string; label: string }>;
  changeProtocol: (proto: Protocol) => void;
  engineForced: CoreEngine | null;
  engineHint: string;
}) {
  const t = useT();
  const coreValue: (typeof CORE_SEL)[number] = engineForced ?? draft.meta.coreType ?? "global";

  return (
    <>
      <SectionLabel>{t("editor.basics")}</SectionLabel>
      <Select
        label={t("editor.protocol")}
        value={draft.protocol}
        options={PROTOCOL_OPTS.map((protocol) => ({
          value: protocol,
          label: PROTOCOL_LABELS[protocol],
        }))}
        onChange={(value) => changeProtocol(value as Protocol)}
      />
      <Field
        label={t("editor.remarks")}
        mono={false}
        value={draft.meta.remarks}
        onChange={(value) => setMeta({ remarks: value })}
        error={errors.remarks}
      />

      {draft.protocol !== "custom" && (
        <div className="input-row" style={{ marginBottom: 14 }}>
          <Field
            label={t("editor.address")}
            value={draft.endpoint.address}
            onChange={(value) => setEndpoint({ address: value })}
            error={errors.address}
          />
          <div style={{ width: 96, flex: "0 0 auto" }}>
            <Field
              label={t("editor.port")}
              type="number"
              value={draft.endpoint.port}
              onChange={(value) => setEndpoint({ port: Number(value) })}
              error={errors.port}
            />
          </div>
        </div>
      )}

      <Select
        label={t("editor.group")}
        value={draft.meta.groupId}
        options={groupOpts}
        onChange={(value) => setMeta({ groupId: value })}
      />

      {/* When the profile is forced onto one engine, pin the selector to that
          engine (not "global" or a stale stored choice) and disable it. */}
      <Select
        label={t("editor.engine")}
        value={coreValue}
        disabled={engineForced != null}
        options={CORE_SEL.map((option) => ({
          value: option,
          label: option === "global" ? t("editor.engineGlobal") : option,
        }))}
        onChange={(value) =>
          setMeta({ coreType: value === "global" ? null : (value as CoreEngine) })
        }
        hint={engineHint}
      />
    </>
  );
}
