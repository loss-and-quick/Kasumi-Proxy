import {
  Card,
  Disclosure,
  Field,
  RowToggle,
  SectionLabel,
  Segmented,
  SettingRow,
} from "../../../components";
import type { CoreEngine, TunEngine } from "../../../generated/bindings";
import { CORE_ENGINE_OPTS, TUN_BY_CORE, TUN_TUNING_ENGINES } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

// Display labels for the TUN engines. Presentation only; the selectable engines,
// per-core defaults and validity all come from the generated `TUN_BY_CORE`
// (single-sourced from Rust `resolve_tun`/`default_tun_for`), so a new engine
// variant surfaces here as a missing-key type error rather than silent omission.
const ENGINE_LABEL: Record<TunEngine, string> = {
  "singbox-tun": "sing-box TUN",
  tun2socks: "tun2socks",
  hev: "hev",
};

export function TunEngineSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();

  const tunFor = (core: CoreEngine): TunEngine =>
    settings.tunByCore?.[core] ?? TUN_BY_CORE[core].default;
  const setTunFor = (core: CoreEngine, value: TunEngine) =>
    set("tunByCore", { ...(settings.tunByCore ?? {}), [core]: value });

  // Which engines expose the tuning knobs below is a Rust fact (TUN_TUNING_ENGINES);
  // only surface the block when at least one core uses such an engine.
  const showTuning = CORE_ENGINE_OPTS.some((core) => TUN_TUNING_ENGINES.includes(tunFor(core)));
  // The stack choice only matters when sing-box's own TUN inbound is in use.
  const singboxTun = CORE_ENGINE_OPTS.some((core) => tunFor(core) === "singbox-tun");

  return (
    <>
      <SectionLabel>{t("settings.tunEngine")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        {CORE_ENGINE_OPTS.map((core) => {
          const engines = TUN_BY_CORE[core].valid;
          return (
            <SettingRow
              key={core}
              stacked
              title={t("settings.tunEngineFor", { core })}
              hint={core === CORE_ENGINE_OPTS[0] ? t("settings.tunEngineHint") : undefined}
            >
              <Segmented
                ariaLabel={t("settings.tunEngineFor", { core })}
                value={tunFor(core)}
                disabled={engines.length < 2}
                onChange={(v) => setTunFor(core, v)}
                options={engines.map((e) => ({ value: e, label: ENGINE_LABEL[e] }))}
              />
            </SettingRow>
          );
        })}
        {singboxTun && (
          <SettingRow title={t("settings.singboxStack")}>
            <Segmented
              size="sm"
              ariaLabel={t("settings.singboxStack")}
              value={settings.singboxStack}
              onChange={(value) => set("singboxStack", value)}
              options={[
                { value: "gvisor", label: "gVisor" },
                { value: "system", label: "System" },
              ]}
            />
          </SettingRow>
        )}
      </Card>
      <Card style={{ padding: "4px 14px", marginTop: 12 }}>
        <RowToggle
          icon="gpp_maybe"
          title={t("settings.strictRoute")}
          sub={t("settings.strictRouteSub")}
          on={settings.strictRoute}
          onChange={(value) => set("strictRoute", value)}
        />
        <div style={{ padding: "8px 4px 0" }}>
          <Field
            label={t("settings.tunMtu")}
            value={settings.tunMtu}
            type="number"
            onChange={(value) => set("tunMtu", Number(value))}
          />
          <Field
            area
            label={t("settings.tunExclude")}
            value={settings.tunExcludeAddresses ?? ""}
            placeholder={t("settings.tunExcludePh")}
            hint={t("settings.tunExcludeHint")}
            onChange={(value) => set("tunExcludeAddresses", value)}
          />
        </div>
        {showTuning && (
          <Disclosure label={t("settings.tunHevTuning")}>
            <div style={{ padding: "0 4px 8px" }}>
              <Field
                label={t("settings.tunConnectTimeout")}
                value={settings.tunConnectTimeoutMs}
                type="number"
                onChange={(value) => set("tunConnectTimeoutMs", Number(value))}
              />
              <Field
                label={t("settings.tunTcpRwTimeout")}
                value={settings.tunTcpRwTimeoutMs}
                type="number"
                onChange={(value) => set("tunTcpRwTimeoutMs", Number(value))}
              />
              <Field
                label={t("settings.tunUdpRwTimeout")}
                value={settings.tunUdpRwTimeoutMs}
                type="number"
                onChange={(value) => set("tunUdpRwTimeoutMs", Number(value))}
              />
              <Field
                label={t("settings.tunTcpBuffer")}
                value={settings.tunTcpBufferSize}
                type="number"
                onChange={(value) => set("tunTcpBufferSize", Number(value))}
              />
              <Field
                label={t("settings.tunUdpRecvBuffer")}
                value={settings.tunUdpRecvBufferSize}
                type="number"
                onChange={(value) => set("tunUdpRecvBufferSize", Number(value))}
              />
            </div>
          </Disclosure>
        )}
      </Card>
    </>
  );
}
