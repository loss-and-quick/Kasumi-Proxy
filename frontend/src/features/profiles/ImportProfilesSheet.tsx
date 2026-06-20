import { useEffect, useRef } from "react";
import { Btn, Field, Sheet } from "../../components";
import type { Group } from "../../generated/bindings";
import { useT } from "../../i18n";

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
  const prevOpen = useRef(open);

  // Auto-read clipboard every time the sheet opens.
  // The UI is served over http://127.0.0.1 (a secure context), so the Clipboard
  // API is available in both the browser and the WebKitGTK/Neutralino window.
  useEffect(() => {
    if (!prevOpen.current && open) {
      navigator.clipboard
        .readText()
        .then((text) => {
          const trimmed = text.trim();
          if (trimmed) setImportText(trimmed);
        })
        .catch(() => {
          // clipboard unavailable / permission denied — leave the field as is
        });
    }
    prevOpen.current = open;
  }, [open, setImportText]);

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
