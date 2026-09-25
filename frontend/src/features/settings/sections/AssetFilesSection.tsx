import {
  Btn,
  Card,
  Disclosure,
  IconBtn,
  ListRow,
  RowToggle,
  SectionLabel,
  Segmented,
  SettingGroup,
  UpdateModeControl,
} from "../../../components";
import type { AssetFile } from "../../../generated/bindings";
import { useFormatters, useT } from "../../../i18n";
import type { AdvancedSettings } from "../../../lib/bridge";
import { formatUpdatedAt } from "../helpers";
import { RESOURCE_LINKS } from "../resource-links";

// Auto-update interval presets (minutes). Geo data changes slowly and each fetch is
// multi-megabyte, so the useful range is hours-to-weeks; the smallest preset is the
// floor the backend clamps to (MIN_ASSET_UPDATE_INTERVAL).
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
  const suggested = RESOURCE_LINKS.filter(
    (link) => !assetFiles.some((a) => a.remarks === link.remarks && a.url === link.url),
  );

  // Presets are whole hours, so a multiple of 24 reads better as days.
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
        <div className="hint" style={{ marginBottom: 10 }}>
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
        <UpdateModeControl
          value={settings.assetUpdateMode}
          onChange={(v) => set("assetUpdateMode", v)}
        />
        <RowToggle
          icon="autorenew"
          title={t("settings.assetAutoUpdate")}
          sub={t("settings.assetAutoUpdateSub")}
          on={settings.assetAutoUpdate}
          onChange={(value) => set("assetAutoUpdate", value)}
        />
        {settings.assetAutoUpdate && (
          <SettingGroup>
            <div className="field-label">{t("settings.assetUpdateInterval")}</div>
            <Segmented
              ariaLabel={t("settings.assetUpdateInterval")}
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
          </SettingGroup>
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
      </Card>
      {suggested.length > 0 && (
        <Card style={{ padding: "0 14px", marginTop: 12 }}>
          {/* Open by default only while nothing is set up yet — that's when the links help. */}
          <Disclosure label={t("settings.assetLinks")} defaultOpen={assetFiles.length === 0}>
            {suggested.map((link) => (
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
          </Disclosure>
        </Card>
      )}
    </>
  );
}
