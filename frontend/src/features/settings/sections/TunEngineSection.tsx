import { Card, SectionLabel, Select } from "../../../components";
import type { CoreEngine, TunEngine } from "../../../generated/bindings";
import { CORE_ENGINE_OPTS, TUN_BY_CORE } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

// Display labels for the TUN engines. Presentation only; the selectable engines,
// per-core defaults and validity all come from the generated `TUN_BY_CORE`
// (single-sourced from Rust `resolve_tun`/`default_tun_for`), so a new engine
// variant surfaces here as a missing-key type error rather than silent omission.
const ENGINE_LABEL: Record<TunEngine, string> = {
  "singbox-tun": "sing-box TUN",
  tun2socks: "tun2socks",
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
      </Card>
    </>
  );
}
