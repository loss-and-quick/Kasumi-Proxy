import { Btn, Card, IconBtn, ListRow, SectionLabel, Select } from "../../../components";
import type { AssetFile } from "../../../generated/bindings";
import { useFormatters, useT } from "../../../i18n";
import type { ResourceUpdateMode } from "../../../lib/bridge";
import { formatUpdatedAt } from "../helpers";
import { RESOURCE_LINKS } from "../resource-links";

export function AssetFilesSection({
  assetFiles,
  busyAssetSet,
  runAssetDownload,
  updateAllAssets,
  openNewAsset,
  onEditAsset,
  resourceUpdateMode,
  setResourceUpdateMode,
  addResourceLink,
  removeAssetFile,
}: {
  assetFiles: AssetFile[];
  busyAssetSet: Set<string>;
  runAssetDownload: (id: string) => Promise<void>;
  updateAllAssets: () => Promise<void>;
  openNewAsset: () => void;
  onEditAsset: (asset: AssetFile) => void;
  resourceUpdateMode: ResourceUpdateMode;
  setResourceUpdateMode: (mode: ResourceUpdateMode) => void;
  addResourceLink: (remarks: string, url: string) => void;
  removeAssetFile: (id: string) => void;
}) {
  const t = useT();
  const formatters = useFormatters();

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
            value={resourceUpdateMode}
            onChange={(v) => setResourceUpdateMode(v as ResourceUpdateMode)}
            options={[
              { value: "auto", label: t("common.mode.auto") },
              { value: "proxy", label: t("common.mode.proxy") },
              { value: "direct", label: t("common.mode.direct") },
            ]}
          />
        </div>
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
