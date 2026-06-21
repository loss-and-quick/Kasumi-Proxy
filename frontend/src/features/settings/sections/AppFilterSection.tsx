import { Card, ListRow, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";

export function AppFilterSection({
  settings,
  onOpenAppFilter,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
  onOpenAppFilter: () => void;
}) {
  const t = useT();
  const count = Object.keys(settings.appFilter ?? {}).length;
  const mode = settings.appCaptureMode ?? "all";

  return (
    <>
      <SectionLabel>{t("appFilter.title")}</SectionLabel>
      <Card>
        <ListRow
          icon="smart_toy"
          title={t("appFilter.openPage")}
          sub={t("appFilter.openPageSub")}
          onClick={onOpenAppFilter}
          right={
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 12, color: "var(--on-surface-faint)" }}>
                {count > 0
                  ? t("appFilter.subtitle", { n: count })
                  : mode === "none"
                    ? t("appFilter.captureNone")
                    : t("appFilter.captureAll")}
              </span>
              <span style={{ fontSize: 20, color: "var(--on-surface-variant)", paddingRight: 4 }}>
                ›
              </span>
            </div>
          }
        />
      </Card>
    </>
  );
}
