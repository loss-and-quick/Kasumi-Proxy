import { Btn, Field, Sheet } from "../../components";
import { useT } from "../../i18n";
import type { Group } from "../../lib/schema";

export function ImportProfilesSheet({
  open,
  onClose,
  importText,
  setImportText,
  importGroup,
  setImportGroup,
  groups,
  onImport,
  onScanQr,
}: {
  open: boolean;
  onClose: () => void;
  importText: string;
  setImportText: (value: string) => void;
  importGroup: string;
  setImportGroup: (value: string) => void;
  groups: Group[];
  onImport: () => void;
  onScanQr: () => void;
}) {
  const t = useT();

  return (
    <Sheet open={open} title={t("profiles.import.title")} onClose={onClose}>
      <Field
        label={t("profiles.import.linksLabel")}
        value={importText}
        onChange={setImportText}
        area
        mono={false}
        hint={t("profiles.import.linksHint")}
      />
      <div className="field-label">{t("profiles.import.targetGroup")}</div>
      <select
        className="select-box"
        value={importGroup}
        onChange={(e) => setImportGroup(e.target.value)}
      >
        {groups.map((group) => (
          <option key={group.id} value={group.id}>
            {group.name}
          </option>
        ))}
      </select>
      <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
        <Btn variant="outline" icon="qr_code_scanner" onClick={onScanQr}>
          {t("profiles.import.scanQr")}
        </Btn>
        <Btn variant="text" onClick={onClose}>
          {t("profiles.import.cancel")}
        </Btn>
        <Btn variant="filled" onClick={onImport} disabled={!importText.trim()}>
          {t("profiles.import.import")}
        </Btn>
      </div>
    </Sheet>
  );
}
