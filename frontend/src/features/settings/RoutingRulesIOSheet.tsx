// ============================================================
// features/settings/RoutingRulesIOSheet.tsx
// Import / export of routing rules (JSON), modelled on the Backup sheet:
// copy / QR / download to export, paste / scan QR with merge / replace to import.
// ============================================================

import { lazy, Suspense, useMemo, useState } from "react";
import { Btn, Field, SectionLabel, Sheet } from "../../components";
import type { RoutingRule } from "../../generated/bindings";
import { useT } from "../../i18n";
import { nativeDialogsAvailable, openTextFile, saveTextFile } from "../../lib/native-dialog";
import { useAppStore } from "../../store/useAppStore";
import { copyText } from "../profiles/clipboard";
import { parseRoutingRulesJson } from "./helpers";

const JSON_FILTER = [{ name: "JSON", extensions: ["json"] }];

const QrCodeSheet = lazy(() =>
  import("../../components/QrCodeSheet").then((module) => ({ default: module.QrCodeSheet })),
);
const QrScannerSheet = lazy(() =>
  import("../../components/QrScannerSheet").then((module) => ({ default: module.QrScannerSheet })),
);

export function RoutingRulesIOSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const routingRules = useAppStore((s) => s.routingRules);
  const importRoutingRules = useAppStore((s) => s.importRoutingRules);
  const notify = useAppStore((s) => s.notify);
  const t = useT();

  const exportJson = useMemo(() => JSON.stringify(routingRules, null, 2), [routingRules]);
  const [importText, setImportText] = useState("");
  const [qrOpen, setQrOpen] = useState(false);
  const [scannerOpen, setScannerOpen] = useState(false);
  const hasRules = routingRules.length > 0;

  const parsed = useMemo(() => {
    if (!importText.trim()) {
      return { ok: false as const, rules: [] as RoutingRule[], hint: t("rulesIo.importLabel") };
    }
    const { ok, rules } = parseRoutingRulesJson(importText);
    if (ok)
      return { ok: true as const, rules, hint: t("rulesIo.summary", { count: rules.length }) };
    return { ok: false as const, rules: [] as RoutingRule[], hint: t("rulesIo.invalid") };
  }, [importText, t]);

  const doImport = (mode: "merge" | "replace") => {
    importRoutingRules(parsed.rules, mode);
    notify(t("rulesIo.summary", { count: parsed.rules.length }));
    onClose();
  };

  return (
    <Sheet open={open} title={t("rulesIo.title")} onClose={onClose}>
      <SectionLabel>{t("rulesIo.export")}</SectionLabel>
      <Field
        label={t("rulesIo.exportLabel")}
        value={exportJson}
        onChange={() => {}}
        area
        mono
        hint={t("rulesIo.summary", { count: routingRules.length })}
      />
      <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <Btn
          variant="tonal"
          disabled={!hasRules}
          onClick={async () =>
            notify((await copyText(exportJson)) ? t("rulesIo.copied") : t("backup.copyFailed"))
          }
        >
          {t("backup.copyJson")}
        </Btn>
        <Btn
          variant="outline"
          icon="qr_code_2"
          disabled={!hasRules}
          onClick={() => setQrOpen(true)}
        >
          {t("backup.showQr")}
        </Btn>
        <Btn
          variant="outline"
          icon="download"
          disabled={!hasRules}
          onClick={async () => {
            const name = `kasumi-proxy-routing-${new Date().toISOString().slice(0, 10)}.json`;
            if (nativeDialogsAvailable()) {
              try {
                await saveTextFile({
                  contents: exportJson,
                  defaultName: name,
                  filters: JSON_FILTER,
                });
              } catch (e) {
                notify(e instanceof Error ? e.message : String(e));
              }
              return;
            }
            const blob = new Blob([exportJson], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = name;
            a.click();
            URL.revokeObjectURL(url);
          }}
        >
          {t("backup.download")}
        </Btn>
      </div>

      <SectionLabel>{t("rulesIo.import")}</SectionLabel>
      <Field
        label={t("rulesIo.importLabel")}
        value={importText}
        onChange={setImportText}
        area
        mono={false}
        hint={parsed.hint}
      />
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {nativeDialogsAvailable() && (
          <Btn
            variant="outline"
            icon="folder_open"
            onClick={async () => {
              try {
                const text = await openTextFile({ filters: JSON_FILTER });
                if (text !== null) setImportText(text);
              } catch (e) {
                notify(e instanceof Error ? e.message : String(e));
              }
            }}
          >
            {t("common.openFile")}
          </Btn>
        )}
        <Btn variant="outline" icon="qr_code_scanner" onClick={() => setScannerOpen(true)}>
          {t("backup.scanQr")}
        </Btn>
        <Btn variant="outline" disabled={!parsed.ok} onClick={() => doImport("merge")}>
          {t("backup.merge")}
        </Btn>
        <Btn variant="error" disabled={!parsed.ok} onClick={() => doImport("replace")}>
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
        {t("rulesIo.mergeHint")}
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
            title={t("rulesIo.qrTitle")}
            text={exportJson}
            onClose={() => setQrOpen(false)}
          />
        </Suspense>
      )}
    </Sheet>
  );
}
