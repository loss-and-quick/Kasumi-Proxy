import { useEffect, useState } from "react";
import { Btn, Field, Sheet } from "../../components";
import type { AssetFile } from "../../generated/bindings";
import { useT } from "../../i18n";
import { uid } from "../../lib/utils";
import { confirmAssetDelete } from "./confirmations";
import { assetDraftErrors, type AssetDraft as Draft } from "./helpers";

function makeDraft(asset?: AssetFile | null): Draft {
  return {
    remarks: asset?.remarks ?? "",
    url: asset?.url ?? "",
  };
}

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
  const t = useT();

  useEffect(() => {
    if (open) {
      setDraft(makeDraft(asset));
      setTried(false);
    }
  }, [open, asset]);

  const errors = assetDraftErrors(draft, takenNames, t);
  const shown = tried ? errors : {};

  const save = () => {
    setTried(true);
    if (Object.keys(errors).length) return;
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
        <Btn variant="filled" sm icon="check" onClick={save}>
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
