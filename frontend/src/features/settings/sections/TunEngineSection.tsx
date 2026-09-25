import {
  blurOnWheel,
  Card,
  Disclosure,
  Field,
  SectionLabel,
  Segmented,
  SettingRow,
  Switch,
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

// Every engine any core can use, in first-seen order: the matrix columns.
const ENGINES: TunEngine[] = [...new Set(CORE_ENGINE_OPTS.flatMap((c) => TUN_BY_CORE[c].valid))];

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
  const excludeCount = (settings.tunExcludeAddresses ?? "").split(/[\s,]+/).filter(Boolean).length;

  return (
    <>
      <SectionLabel>{t("settings.tunEngine")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <div
          className="tun-matrix"
          style={{ gridTemplateColumns: `minmax(72px, auto) repeat(${ENGINES.length}, 1fr)` }}
        >
          <span />
          {ENGINES.map((engine) => (
            <span key={engine} className="tm-head">
              {ENGINE_LABEL[engine]}
            </span>
          ))}
          {CORE_ENGINE_OPTS.map((core) => (
            <div key={core} style={{ display: "contents" }}>
              <span className="tm-core">{core}</span>
              {ENGINES.map((engine) => (
                <span key={engine} className="tm-cell">
                  <button
                    type="button"
                    className="radio"
                    aria-pressed={tunFor(core) === engine}
                    aria-label={`${t("settings.tunEngineFor", { core })}: ${ENGINE_LABEL[engine]}`}
                    disabled={!TUN_BY_CORE[core].valid.includes(engine)}
                    onClick={() => setTunFor(core, engine)}
                  />
                </span>
              ))}
            </div>
          ))}
        </div>
        <div className="hint" style={{ paddingBottom: 10 }}>
          {t("settings.tunEngineHint")}
        </div>
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
        <SettingRow title={t("settings.strictRoute")} hint={t("settings.strictRouteSub")}>
          <Switch on={settings.strictRoute} onChange={(value) => set("strictRoute", value)} />
        </SettingRow>
        <SettingRow title={t("settings.tunMtu")}>
          <input
            className="input compact"
            type="number"
            inputMode="numeric"
            aria-label={t("settings.tunMtu")}
            value={settings.tunMtu}
            onWheel={blurOnWheel}
            onChange={(e) => set("tunMtu", Number(e.target.value))}
          />
        </SettingRow>
        <div className="setting-row" style={{ display: "block", padding: 0 }}>
          <Disclosure
            label={
              excludeCount > 0
                ? `${t("settings.tunExclude")} · ${excludeCount}`
                : t("settings.tunExclude")
            }
          >
            <Field
              area
              value={settings.tunExcludeAddresses ?? ""}
              placeholder={t("settings.tunExcludePh")}
              hint={t("settings.tunExcludeHint")}
              onChange={(value) => set("tunExcludeAddresses", value)}
            />
          </Disclosure>
        </div>
        {showTuning && (
          <div className="setting-row" style={{ display: "block", padding: 0 }}>
            <Disclosure label={t("settings.tunHevTuning")}>
              <HevTuning settings={settings} set={set} />
            </Disclosure>
          </div>
        )}
      </Card>
    </>
  );
}

/** hev's buffer/timeout knobs as compact number rows instead of full-width fields. */
function HevTuning({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();
  const rows = [
    ["tunConnectTimeoutMs", t("settings.tunConnectTimeout")],
    ["tunTcpRwTimeoutMs", t("settings.tunTcpRwTimeout")],
    ["tunUdpRwTimeoutMs", t("settings.tunUdpRwTimeout")],
    ["tunTcpBufferSize", t("settings.tunTcpBuffer")],
    ["tunUdpRecvBufferSize", t("settings.tunUdpRecvBuffer")],
  ] as const;
  return (
    <div style={{ paddingBottom: 6 }}>
      {rows.map(([key, label]) => (
        <SettingRow key={key} title={label}>
          <input
            className="input compact"
            type="number"
            inputMode="numeric"
            aria-label={label}
            value={settings[key]}
            onWheel={blurOnWheel}
            onChange={(e) => set(key, Number(e.target.value))}
          />
        </SettingRow>
      ))}
    </div>
  );
}
