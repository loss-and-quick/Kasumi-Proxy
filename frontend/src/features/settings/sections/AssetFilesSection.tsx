import { Btn, Card, IconBtn, ListRow, RowToggle, SectionLabel, Select } from "../../../components";
import type { AssetFile } from "../../../generated/bindings";
import { useFormatters, useT } from "../../../i18n";
import type { AdvancedSettings, ResourceUpdateMode } from "../../../lib/bridge";
import { formatUpdatedAt } from "../helpers";
import { RESOURCE_LINKS } from "../resource-links";

// Asset auto-update interval presets (minutes). Geo data changes slowly, so the
// useful range is hours-to-weeks — a select avoids the 24h limit of a time input.
const INTERVAL_PRESETS = [360, 720, 1440, 4320, 10080];

export function AssetFilesSection({
  assetFiles,
  busyAssetSet,
  runAssetDownload,
  updateAllAssets,
  openNewAsset,
  onEditAsset,
  settings,
  set,
  addResourceLink,
  removeAssetFile,
}: {
  assetFiles: AssetFile[];
  busyAssetSet: Set<string>;
  runAssetDownload: (id: string) => Promise<void>;
  updateAllAssets: () => Promise<void>;
  openNewAsset: () => void;
  onEditAsset: (asset: AssetFile) => void;
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
  addResourceLink: (remarks: string, url: string) => void;
  removeAssetFile: (id: string) => void;
}) {
  const t = useT();
  const formatters = useFormatters();

  const intervalLabel = (minutes: number) => {
    const hours = Math.round(minutes / 60);
    return hours % 24 === 0
      ? t("settings.assetIntervalDays", { count: hours / 24 })
      : t("settings.assetIntervalHours", { count: hours });
  };

  return (
    <>
      <SectionLabel>{t("settings.assetFiles")}</SectionLabel>
      <Card style={{ padding: 14 }}>
        <div style={{ fontSize: 12, color: "var(--on-surface-faint)", marginBottom: 10 }}>
          {t("settings.assetHint")}
        </div>
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 8,
            marginBottom: 10,
            alignItems: "center",
          }}
        >
          <Btn variant="tonal" sm icon="download" onClick={() => void updateAllAssets()}>
            {t("settings.assetUpdateAll")}
          </Btn>
          <Btn variant="tonal" sm icon="add" onClick={openNewAsset}>
            {t("settings.assetAdd")}
          </Btn>
        </div>
        <div style={{ marginBottom: 12 }}>
          <Select
            label={t("common.updateMode")}
            value={settings.assetUpdateMode}
            onChange={(v) => set("assetUpdateMode", v as ResourceUpdateMode)}
            options={[
              { value: "auto", label: t("common.mode.auto") },
              { value: "proxy", label: t("common.mode.proxy") },
              { value: "direct", label: t("common.mode.direct") },
            ]}
          />
        </div>
        <RowToggle
          icon="autorenew"
          title={t("settings.assetAutoUpdate")}
          sub={t("settings.assetAutoUpdateSub")}
          on={settings.assetAutoUpdate}
          onChange={(value) => set("assetAutoUpdate", value)}
        />
        {settings.assetAutoUpdate && (
          <div style={{ paddingLeft: 54, marginBottom: 12 }}>
            <Select
              label={t("settings.assetUpdateInterval")}
              value={String(settings.assetUpdateInterval)}
              onChange={(v) => set("assetUpdateInterval", Number(v))}
              options={INTERVAL_PRESETS.map((minutes) => ({
                value: String(minutes),
                label: intervalLabel(minutes),
              }))}
            />
            <div style={{ fontSize: 12, color: "var(--warn)", marginTop: 8, lineHeight: 1.5 }}>
              {t("settings.assetAutoUpdateWarning")}
            </div>
          </div>
        )}
        {assetFiles.map((asset) => (
          <ListRow
            key={asset.id}
            icon="folder_zip"
            title={asset.remarks}
            sub={`${formatUpdatedAt(asset.lastUpdated, t, formatters)} · ${asset.url}`}
            onClick={() => onEditAsset(asset)}
            right={
              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {(!asset.lastUpdated || busyAssetSet.has(asset.id)) && (
                  <IconBtn
                    name={busyAssetSet.has(asset.id) ? "hourglass_top" : "download"}
                    sm
                    title={t("settings.assetDownload")}
                    onClick={() => void runAssetDownload(asset.id)}
                  />
                )}
                {!asset.locked && (
                  <IconBtn
                    name="delete"
                    sm
                    title={t("settings.assetDelete")}
                    onClick={() => removeAssetFile(asset.id)}
                  />
                )}
              </div>
            }
          />
        ))}
        <div style={{ height: 10 }} />
        <div style={{ fontSize: 12, color: "var(--on-surface-faint)", marginBottom: 8 }}>
          {t("settings.assetLinks")}
        </div>
        {RESOURCE_LINKS.filter(
          (link) => !assetFiles.some((a) => a.remarks === link.remarks && a.url === link.url),
        ).map((link) => (
          <ListRow
            key={link.id}
            icon="link"
            title={t(link.labelKey)}
            sub={`${t(link.noteKey)} · ${link.url}`}
            right={
              <Btn variant="outline" sm onClick={() => addResourceLink(link.remarks, link.url)}>
                {t("settings.assetUse")}
              </Btn>
            }
          />
        ))}
      </Card>
    </>
  );
}
