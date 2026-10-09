import { useEffect, useRef } from "react";
import { Btn, Field, GroupPicker, Sheet } from "../../components";
import type { Group } from "../../generated/bindings";
import { useT } from "../../i18n";
import type { GroupChoice } from "../../lib/groups";
import { readText } from "./clipboard";

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
  importGroup: GroupChoice;
  setImportGroup: (value: GroupChoice) => void;
  groups: Group[];
  onImport: () => void;
  onScanQr: () => void;
}) {
  const t = useT();
  // Starts closed: the sheet is mounted already open, and that opening counts.
  const prevOpen = useRef(false);
  const importTextRef = useRef(importText);
  importTextRef.current = importText;

  // Auto-read the clipboard every time the sheet opens, unless something is
  // already typed there. Uses the native clipboard under Tauri, the web Clipboard
  // API otherwise; leaves the field as-is when the clipboard is empty or
  // unreadable (permission denied / no clipboard access).
  useEffect(() => {
    if (!prevOpen.current && open) {
      readText().then((text) => {
        const trimmed = text?.trim();
        if (trimmed && !importTextRef.current.trim()) setImportText(trimmed);
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
      <GroupPicker
        label={t("profiles.import.targetGroup")}
        groups={groups}
        value={importGroup}
        onChange={setImportGroup}
      />
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
