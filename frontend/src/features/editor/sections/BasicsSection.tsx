import { Field, GroupPicker, SectionLabel, Segmented, Select } from "../../../components";
import type { CoreEngine, Group, Profile, Protocol } from "../../../generated/bindings";
import { CORE_ENGINE_OPTS, PROTOCOL_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { GroupChoice } from "../../../lib/groups";
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

// UI sentinel for "connect directly" (nested `via` is null).
const VIA_DIRECT = "";

export function BasicsSection({
  draft,
  setMeta,
  setEndpoint,
  errors,
  groups,
  group,
  setGroup,
  viaOpts,
  changeProtocol,
  engineForced,
  engineHint,
  route,
  routeOpts,
  setRoute,
}: {
  draft: Profile;
  setMeta: MetaSetter;
  setEndpoint: EndpointSetter;
  errors: FieldErrors;
  groups: Group[];
  group: GroupChoice;
  setGroup: (value: GroupChoice) => void;
  viaOpts: Array<{ value: string; label: string }>;
  changeProtocol: (proto: Protocol) => void;
  engineForced: CoreEngine | null;
  engineHint: string;
  /** The route listing this profile; "" follows its group. */
  route: string;
  /** Empty while there is only the default route: nothing to choose. */
  routeOpts: Array<{ value: string; label: string }>;
  setRoute: (id: string) => void;
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

      <GroupPicker label={t("editor.group")} groups={groups} value={group} onChange={setGroup} />
      {errors.group && (
        <div className="hint error" style={{ marginTop: -8, marginBottom: 10 }}>
          {errors.group}
        </div>
      )}

      {draft.protocol !== "custom" && (
        <Select
          label={t("editor.via")}
          value={draft.meta.via ?? VIA_DIRECT}
          options={[{ value: VIA_DIRECT, label: t("editor.viaDirect") }, ...viaOpts]}
          onChange={(value) => setMeta({ via: value === VIA_DIRECT ? null : value })}
          hint={t("editor.viaHint")}
        />
      )}

      {routeOpts.length > 0 && (
        <Select
          label={t("editor.route")}
          value={route}
          options={routeOpts}
          onChange={setRoute}
          hint={t("editor.routeHint")}
        />
      )}

      {/* When the profile is forced onto one engine, pin the selector to that
          engine (not "global" or a stale stored choice) and disable it. */}
      <Segmented
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
