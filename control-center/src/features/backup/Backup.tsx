// ============================================================
// features/backup/Backup.tsx
// Canonical AppState backup / restore.
// ============================================================
import { lazy, Suspense, useMemo, useState } from "react";
import { Btn, Field, SectionLabel, Sheet } from "../../components";
import { useT } from "../../i18n";
import { AppStateSchema } from "../../lib/schema";
import { useAppStore } from "../../store/useAppStore";

const QrCodeSheet = lazy(() =>
  import("../../components/QrCodeSheet").then((module) => ({ default: module.QrCodeSheet })),
);
const QrScannerSheet = lazy(() =>
  import("../../components/QrScannerSheet").then((module) => ({ default: module.QrScannerSheet })),
);

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export default function Backup({ onClose }: { onClose: () => void }) {
  const groups = useAppStore((s) => s.groups);
  const subscriptions = useAppStore((s) => s.subscriptions);
  const settings = useAppStore((s) => s.settings);
  const activeId = useAppStore((s) => s.activeId);
  const importBackup = useAppStore((s) => s.importBackup);
  const notify = useAppStore((s) => s.notify);
  const t = useT();

  const backupJson = useMemo(
    () => JSON.stringify({ groups, subscriptions, settings, activeId }, null, 2),
    [groups, subscriptions, settings, activeId],
  );
  const [importText, setImportText] = useState("");
  const [qrOpen, setQrOpen] = useState(false);
  const [scannerOpen, setScannerOpen] = useState(false);

  const importValidation = useMemo(() => {
    try {
      const data = JSON.parse(importText || "{}");
      const parsed = AppStateSchema.safeParse(data);
      return parsed.success
        ? {
            ok: true as const,
            hint: t("backup.summary", {
              groups: data.groups?.length ?? 0,
              profiles: data.profiles?.length ?? 0,
              subscriptions: data.subscriptions?.length ?? 0,
            }),
          }
        : { ok: false as const, hint: t("backup.invalidStructure") };
    } catch {
      return { ok: false as const, hint: t("backup.invalidJson") };
    }
  }, [importText, t]);

  return (
    <Sheet open title={t("backup.title")} onClose={onClose}>
      <SectionLabel>{t("backup.export")}</SectionLabel>
      <Field
        label={t("backup.exportLabel")}
        value={backupJson}
        onChange={() => {}}
        area
        mono
        hint={t("backup.summary", {
          groups: groups.length,
          subscriptions: subscriptions.length,
        })}
      />
      <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <Btn
          variant="tonal"
          onClick={async () =>
            notify((await copyText(backupJson)) ? t("backup.copied") : t("backup.copyFailed"))
          }
        >
          {t("backup.copyJson")}
        </Btn>
        <Btn variant="outline" icon="qr_code_2" onClick={() => setQrOpen(true)}>
          {t("backup.showQr")}
        </Btn>
        <Btn
          variant="outline"
          onClick={() => {
            const blob = new Blob([backupJson], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `kasumi-proxy-backup-${new Date().toISOString().slice(0, 10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
          }}
        >
          {t("backup.download")}
        </Btn>
      </div>

      <SectionLabel>{t("backup.import")}</SectionLabel>
      <Field
        label={t("backup.importLabel")}
        value={importText}
        onChange={setImportText}
        area
        mono={false}
        hint={importValidation.hint}
      />
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        <Btn variant="outline" icon="qr_code_scanner" onClick={() => setScannerOpen(true)}>
          {t("backup.scanQr")}
        </Btn>
        <Btn
          variant="outline"
          disabled={!importText.trim() || !importValidation.ok}
          onClick={() => void importBackup(importText, "merge")}
        >
          {t("backup.merge")}
        </Btn>
        <Btn
          variant="error"
          disabled={!importText.trim() || !importValidation.ok}
          onClick={() => void importBackup(importText, "replace")}
        >
          {t("backup.replace")}
        </Btn>
      </div>
      <div
        style={{
          marginTop: 10,
          fontSize: 12.5,
          color: "var(--on-surface-variant)",
          lineHeight: 1.5,
        }}
      >
        {t("backup.mergeHint")}
      </div>

      {scannerOpen && (
        <Suspense fallback={null}>
          <QrScannerSheet
            open={scannerOpen}
            title={t("qr.scan.title")}
            onClose={() => setScannerOpen(false)}
            onResult={(text) => {
              setImportText(text);
            }}
          />
        </Suspense>
      )}

      {qrOpen && (
        <Suspense fallback={null}>
          <QrCodeSheet
            open={qrOpen}
            title={t("backup.qrTitle")}
            text={backupJson}
            onClose={() => setQrOpen(false)}
          />
        </Suspense>
      )}
    </Sheet>
  );
}
