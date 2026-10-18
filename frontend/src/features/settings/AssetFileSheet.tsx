import { useEffect, useState } from "react";
import { Btn, Field, Sheet } from "../../components";
import type { AssetFile } from "../../generated/bindings";
import { useT } from "../../i18n";
import { bridge } from "../../lib/bridge-provider";
import { uid } from "../../lib/utils";
import { confirmAssetDelete } from "./confirmations";
import { type AssetDraft as Draft, issuesToAssetErrors } from "./helpers";

function makeDraft(asset?: AssetFile | null): Draft {
  return {
    remarks: asset?.remarks ?? "",
    url: asset?.url ?? "",
  };
}

type Errors = ReturnType<typeof issuesToAssetErrors>;

export function AssetFileSheet({
  open,
  asset,
  takenNames,
  onClose,
  onSave,
  onDelete,
}: {
  open: boolean;
  asset: AssetFile | null;
  /** File names the other entries already use. */
  takenNames: string[];
  onClose: () => void;
  onSave: (asset: AssetFile) => void;
  onDelete: (id: string) => void;
}) {
  const [draft, setDraft] = useState<Draft>(makeDraft(asset));
  // Errors show once Save was pressed, then follow the typing.
  const [tried, setTried] = useState(false);
  const [errors, setErrors] = useState<Errors>({});
  const t = useT();

  useEffect(() => {
    if (open) {
      setDraft(makeDraft(asset));
      setTried(false);
      setErrors({});
    }
  }, [open, asset]);

  // The draft's problems are the backend's answer (the same rules the downloader
  // applies to a file name), re-asked on every edit like the editor's previews.
  useEffect(() => {
    let alive = true;
    bridge
      .validateAssetDraft({ remarks: draft.remarks, url: draft.url }, takenNames)
      .then((issues) => alive && setErrors(issuesToAssetErrors(issues, t)))
      .catch(() => alive && setErrors({}));
    return () => {
      alive = false;
    };
  }, [draft.remarks, draft.url, takenNames, t]);

  const shown = tried ? errors : {};

  const save = async () => {
    setTried(true);
    const issues = await bridge.validateAssetDraft(
      { remarks: draft.remarks, url: draft.url },
      takenNames,
    );
    const currentErrors = issuesToAssetErrors(issues, t);
    setErrors(currentErrors);
    if (Object.keys(currentErrors).length > 0) return;
    const name = draft.remarks.trim();
    const url = draft.url.trim();
    onSave({
      id: asset?.id ?? uid(),
      remarks: name,
      url,
      lastUpdated: asset?.lastUpdated ?? null,
      locked: asset?.locked ?? false,
    });
    onClose();
  };

  return (
    <Sheet
      open={open}
      title={asset ? t("assetSheet.editTitle") : t("assetSheet.addTitle")}
      onClose={onClose}
      headRight={
        <Btn variant="filled" sm icon="check" onClick={() => void save()}>
          {t("assetSheet.save")}
        </Btn>
      }
    >
      <Field
        label={t("assetSheet.filename")}
        value={draft.remarks}
        onChange={(value) => setDraft((current) => ({ ...current, remarks: value }))}
        placeholder={t("assetSheet.filenamePh")}
        error={shown.remarks}
        mono={false}
      />
      <Field
        label={t("assetSheet.url")}
        value={draft.url}
        onChange={(value) => setDraft((current) => ({ ...current, url: value }))}
        placeholder={t("assetSheet.urlPh")}
        error={shown.url}
        mono={false}
      />
      {asset && !asset.locked && (
        <div style={{ marginTop: 16 }}>
          <Btn
            variant="error"
            icon="delete"
            onClick={async () => {
              if (!(await confirmAssetDelete(asset.remarks))) return;
              onDelete(asset.id);
              onClose();
            }}
          >
            {t("assetSheet.delete")}
          </Btn>
        </div>
      )}
    </Sheet>
  );
}
