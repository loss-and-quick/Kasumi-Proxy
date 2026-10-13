// ============================================================
// features/routes/RouteShareSheet.tsx
// Share a route with its blocks, or take one in. A route travels without the
// profiles it applies to (they don't exist on the other side); "as one list"
// gives the flat rule array other clients and the Custom mode take. A Happ
// `happ://routing` link comes in the same way, as a route of its own.
// ============================================================

import { lazy, Suspense, useMemo, useState } from "react";
import { Btn, Field, SectionLabel, Segmented, Sheet } from "../../components";
import type { Route } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import { linkInputText } from "../../lib/add-input";
import { nativeDialogsAvailable, openTextFile, saveTextFile } from "../../lib/native-dialog";
import {
  exportRoutePackage,
  flattenRoute,
  parseRoutePackage,
  routeNamesProfiles,
} from "../../lib/routes";
import { errorMessage } from "../../store/errors";
import { useAppStore } from "../../store/useAppStore";
import { useLinkInput } from "../add/useLinkInput";
import { copyText } from "../profiles/clipboard";
import { RoutingImportCard } from "../subscriptions/RoutingImportCard";
import { routeName } from "./labels";

const JSON_FILTER = [{ name: "JSON", extensions: ["json"] }];

const QrCodeSheet = lazy(() =>
  import("../../components/QrCodeSheet").then((module) => ({ default: module.QrCodeSheet })),
);
const QrScannerSheet = lazy(() =>
  import("../../components/QrScannerSheet").then((module) => ({ default: module.QrScannerSheet })),
);

export function RouteShareSheet({
  route,
  onClose,
  onImported,
}: {
  route: Route;
  onClose: () => void;
  onImported: (routeId: string) => void;
}) {
  const t = useT();
  const { formatList } = useFormatters();
  const ruleBlocks = useAppStore((s) => s.ruleBlocks);
  const notify = useAppStore((s) => s.notify);
  const importRoutePackage = useAppStore((s) => s.importRoutePackage);
  const importRoutingRoute = useAppStore((s) => s.importRoutingRoute);
  const [format, setFormat] = useState<"route" | "flat">("route");
  const [importText, setImportText] = useState("");
  const [qrOpen, setQrOpen] = useState(false);
  const [scannerOpen, setScannerOpen] = useState(false);

  const exportJson = useMemo(
    () =>
      format === "route" ? exportRoutePackage(route, ruleBlocks) : flattenRoute(route, ruleBlocks),
    [format, route, ruleBlocks],
  );
  const pkg = useMemo(() => parseRoutePackage(importText), [importText]);
  const link = useLinkInput(importText);
  const happRoutes = link?.kind === "routing" ? link.routing : [];
  const importHint = !importText.trim()
    ? t("routes.share.importHint")
    : pkg
      ? `${pkg.name} · ${t("routes.share.blocks", { count: pkg.blocks.length })}`
      : happRoutes.length
        ? t("routes.share.happRouting", { count: happRoutes.length })
        : link
          ? t(linkInputText(link))
          : link === null
            ? t("routes.share.invalid")
            : "";

  const addRoute = async () => {
    if (pkg) {
      const id = await importRoutePackage(pkg);
      notify(t("routes.share.imported", { name: pkg.name }));
      onImported(id);
    } else if (happRoutes.length) {
      const ids: string[] = [];
      for (const routing of happRoutes) ids.push(await importRoutingRoute(routing));
      notify(t("routes.share.imported", { name: formatList(happRoutes.map((r) => r.name)) }));
      onImported(ids[0]);
    } else return;
    onClose();
  };

  const download = async () => {
    const name = `kasumi-route-${route.name.replace(/[^\p{L}\p{N}_-]+/gu, "-")}.json`;
    if (nativeDialogsAvailable()) {
      try {
        await saveTextFile({ contents: exportJson, defaultName: name, filters: JSON_FILTER });
      } catch (e) {
        notify(t("common.saveFileFailed", { error: errorMessage(e) }));
      }
      return;
    }
    const url = URL.createObjectURL(new Blob([exportJson], { type: "application/json" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <Sheet open title={t("routes.share.title")} onClose={onClose}>
        <SectionLabel>{t("routes.share.export", { route: routeName(route, t) })}</SectionLabel>
        <Segmented
          ariaLabel={t("routes.share.format")}
          value={format}
          onChange={setFormat}
          options={[
            { value: "route", label: t("routes.share.asRoute") },
            { value: "flat", label: t("routes.share.asList") },
          ]}
        />
        <div className="hint" style={{ margin: "6px 0 8px" }}>
          {t(format === "route" ? "routes.share.asRouteHint" : "routes.share.asListHint")}
          {routeNamesProfiles(route, ruleBlocks) && ` ${t("routes.share.profilesNote")}`}
        </div>
        <Field
          label={t("routes.share.exportLabel")}
          value={exportJson}
          onChange={() => {}}
          area
          mono
        />
        <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
          <Btn
            variant="tonal"
            onClick={async () =>
              notify((await copyText(exportJson)) ? t("rulesIo.copied") : t("backup.copyFailed"))
            }
          >
            {t("backup.copyJson")}
          </Btn>
          <Btn variant="outline" icon="qr_code_2" onClick={() => setQrOpen(true)}>
            {t("backup.showQr")}
          </Btn>
          <Btn variant="outline" icon="download" onClick={download}>
            {t("backup.download")}
          </Btn>
        </div>

        <SectionLabel>{t("routes.share.import")}</SectionLabel>
        <Field
          label={t("routes.share.importLabel")}
          value={importText}
          onChange={setImportText}
          area
          mono={false}
          hint={importHint}
        />
        {happRoutes.map((routing, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: the same profile may be pasted twice.
          <RoutingImportCard key={i} routing={routing} />
        ))}
        <div
          style={{
            display: "flex",
            gap: 10,
            flexWrap: "wrap",
            marginTop: happRoutes.length ? 12 : 0,
          }}
        >
          {nativeDialogsAvailable() && (
            <Btn
              variant="outline"
              icon="folder_open"
              onClick={async () => {
                try {
                  const text = await openTextFile({ filters: JSON_FILTER });
                  if (text !== null) setImportText(text);
                } catch (e) {
                  notify(t("common.openFileFailed", { error: errorMessage(e) }));
                }
              }}
            >
              {t("common.openFile")}
            </Btn>
          )}
          <Btn variant="outline" icon="qr_code_scanner" onClick={() => setScannerOpen(true)}>
            {t("backup.scanQr")}
          </Btn>
          <Btn icon="add" disabled={!pkg && !happRoutes.length} onClick={() => void addRoute()}>
            {t("routes.share.add")}
          </Btn>
        </div>
        <div className="hint" style={{ marginTop: 10 }}>
          {t("routes.share.importNote")}
        </div>
      </Sheet>

      <Suspense fallback={null}>
        {scannerOpen && (
          <QrScannerSheet
            open
            title={t("qr.scan.title")}
            onClose={() => setScannerOpen(false)}
            onResult={(text) => {
              setImportText(text);
            }}
          />
        )}
        {qrOpen && (
          <QrCodeSheet
            open
            title={routeName(route, t)}
            text={exportJson}
            onClose={() => setQrOpen(false)}
          />
        )}
      </Suspense>
    </>
  );
}
