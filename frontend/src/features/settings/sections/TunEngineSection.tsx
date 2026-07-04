import { Card, Field, SectionLabel, Select } from "../../../components";
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

  return (
    <>
      <SectionLabel>{t("settings.tunEngine")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginBottom: 10 }}>
          {t("settings.tunEngineHint")}
        </div>
        {CORE_ENGINE_OPTS.map((core) => {
          const engines = TUN_BY_CORE[core].valid;
          return (
            <div
              key={core}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                padding: "5px 0",
              }}
            >
              <span style={{ fontSize: 13.5, color: "var(--on-surface)" }}>{core}</span>
              <Select
                style={{ width: 150, flex: "0 0 auto" }}
                value={tunFor(core)}
                disabled={engines.length < 2}
                onChange={(v) => setTunFor(core, v as TunEngine)}
                options={engines.map((e) => ({ value: e, label: ENGINE_LABEL[e] }))}
              />
            </div>
          );
        })}

        {showTuning && (
          <div
            style={{ marginTop: 12, borderTop: "1px solid var(--outline-faint)", paddingTop: 12 }}
          >
            <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginBottom: 10 }}>
              {t("settings.tunHevTuning")}
            </div>
            <div style={{ padding: "0 4px" }}>
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
          </div>
        )}
      </Card>
    </>
  );
}
