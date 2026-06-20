import { useEffect, useState } from "react";
import { Btn, Field, Sheet } from "../../components";
import type { AssetFile } from "../../generated/bindings";
import { useT } from "../../i18n";
import { uid } from "../../lib/utils";

type Draft = {
  remarks: string;
  url: string;
};

function makeDraft(asset?: AssetFile | null): Draft {
  return {
    remarks: asset?.remarks ?? "",
    url: asset?.url ?? "",
  };
}

export function AssetFileSheet({
  open,
  asset,
  onClose,
  onSave,
  onDelete,
}: {
  open: boolean;
  asset: AssetFile | null;
  onClose: () => void;
  onSave: (asset: AssetFile) => void;
  onDelete: (id: string) => void;
}) {
  const [draft, setDraft] = useState<Draft>(makeDraft(asset));
  const t = useT();

  useEffect(() => {
    if (open) setDraft(makeDraft(asset));
  }, [open, asset]);

  const save = () => {
    const name = draft.remarks.trim();
    const url = draft.url.trim();
    if (!name || !url) return;
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
        mono={false}
      />
      <Field
        label={t("assetSheet.url")}
        value={draft.url}
        onChange={(value) => setDraft((current) => ({ ...current, url: value }))}
        placeholder={t("assetSheet.urlPh")}
        mono={false}
      />
      {asset && !asset.locked && (
        <div style={{ marginTop: 16 }}>
          <Btn
            variant="error"
            icon="delete"
            onClick={() => {
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
