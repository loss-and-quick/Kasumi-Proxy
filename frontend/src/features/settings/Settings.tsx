// ============================================================
// features/settings/Settings.tsx
// Engine and UI settings.
// ============================================================

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { AppBar, Card, IconBtn, NavRow } from "../../components";
import type { AssetFile, CoreEngine, Protocol, RoutingRule } from "../../generated/bindings";
import { DEFAULT_CORE_BY_PROTOCOL } from "../../generated/defaults";
import { LOCALES, useLang, useT } from "../../i18n";
import { isServiceUp } from "../../lib/bridge";
import { getRuntimeBridgeMode } from "../../lib/ksu-webui";
import { useEscapeToClose } from "../../lib/useEscapeToClose";
import { useIsWide } from "../../lib/useIsWide";
import { uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { coresPreset } from "./helpers";
import { pageFromHash, SETTINGS_PAGES, type SettingsPage } from "./pages";
import { AboutSection } from "./sections/AboutSection";
import { AdvancedSection } from "./sections/AdvancedSection";
import { AssetFilesSection } from "./sections/AssetFilesSection";
import { ConnectionSection } from "./sections/ConnectionSection";
import { CoresSection } from "./sections/CoresSection";
import { DiagnosticsSection } from "./sections/DiagnosticsSection";
import { DnsSection } from "./sections/DnsSection";
import { LocalPortsSection } from "./sections/LocalPortsSection";
import { RoutingSection } from "./sections/RoutingSection";
import { SystemSection } from "./sections/SystemSection";
import { TunEngineSection } from "./sections/TunEngineSection";

const AssetFileSheet = lazy(() =>
  import("./AssetFileSheet").then((module) => ({ default: module.AssetFileSheet })),
);
const RoutingRuleSheet = lazy(() =>
  import("./RoutingRuleSheet").then((module) => ({ default: module.RoutingRuleSheet })),
);
const RoutingRulesIOSheet = lazy(() =>
  import("./RoutingRulesIOSheet").then((module) => ({ default: module.RoutingRulesIOSheet })),
);

export default function Settings({
  onOpenBackup,
  onOpenLogs,
  onOpenAppFilter,
}: {
  onOpenBackup: () => void;
  onOpenLogs: () => void;
  onOpenAppFilter: () => void;
}) {
  const settings = useAppStore((s) => s.settings);
  const profiles = useAppStore((s) => s.profiles);
  const subscriptions = useAppStore((s) => s.subscriptions);
  const routingRules = useAppStore((s) => s.routingRules);
  const assetFiles = useAppStore((s) => s.assetFiles);
  const activeId = useAppStore((s) => s.activeId);
  const service = useAppStore((s) => s.service);
  const caps = useAppStore((s) => s.caps);
  const notify = useAppStore((s) => s.notify);
  const setSetting = useAppStore((s) => s.setSetting);
  const addRoutingRule = useAppStore((s) => s.addRoutingRule);
  const updateRoutingRule = useAppStore((s) => s.updateRoutingRule);
  const removeRoutingRule = useAppStore((s) => s.removeRoutingRule);
  const reorderRoutingRules = useAppStore((s) => s.reorderRoutingRules);
  const addAssetFile = useAppStore((s) => s.addAssetFile);
  const updateAssetFile = useAppStore((s) => s.updateAssetFile);
  const removeAssetFile = useAppStore((s) => s.removeAssetFile);
  const downloadAsset = useAppStore((s) => s.downloadAsset);
  const t = useT();
  const { lang } = useLang();
  const isWide = useIsWide();

  // The open page lives in the hash so Back (browser or WebView) returns to the list.
  const [hashPage, setHashPage] = useState(() => pageFromHash(window.location.hash));
  useEffect(() => {
    const onHash = () => setHashPage(pageFromHash(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const openPage = (next: SettingsPage) => {
    window.location.hash = `settings/${next}`;
  };
  const closePage = () => {
    window.location.hash = "settings";
  };
  // Side by side there is always a page showing; on a phone the list comes first.
  const page: SettingsPage | null = hashPage ?? (isWide ? SETTINGS_PAGES[0].id : null);
  useEscapeToClose(!isWide && hashPage !== null, closePage);

  const profileOptions = useMemo(
    () => profiles.map((p) => ({ id: p.meta.id, remarks: p.meta.remarks })),
    [profiles],
  );

  const [editingRule, setEditingRule] = useState<RoutingRule | null>(null);
  const [ruleSheetOpen, setRuleSheetOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<AssetFile | null>(null);
  const [assetSheetOpen, setAssetSheetOpen] = useState(false);
  const [busyAssets, setBusyAssets] = useState<string[]>([]);
  const [rulesIOOpen, setRulesIOOpen] = useState(false);

  const coreFor = (protocol: Protocol): CoreEngine =>
    settings.coreByProtocol?.[protocol] ?? DEFAULT_CORE_BY_PROTOCOL[protocol];
  const setCoreMap = (map: Partial<Record<Protocol, CoreEngine>>) =>
    setSetting("coreByProtocol", map);
  const setCoreFor = (protocol: Protocol, value: CoreEngine) =>
    setSetting("coreByProtocol", { ...(settings.coreByProtocol ?? {}), [protocol]: value });

  const set = <K extends keyof typeof settings>(key: K, value: (typeof settings)[K]) =>
    setSetting(key, value);
  const bridgeMode = getRuntimeBridgeMode();

  const busyAssetSet = useMemo(() => new Set(busyAssets), [busyAssets]);

  const openNewRule = () => {
    setEditingRule(null);
    setRuleSheetOpen(true);
  };

  const openRuleEditor = (rule: RoutingRule) => {
    setEditingRule(rule);
    setRuleSheetOpen(true);
  };

  const saveRule = (rule: RoutingRule) => {
    const existing = routingRules.find((item) => item.id === rule.id);
    if (existing) updateRoutingRule(rule.id, rule);
    else addRoutingRule(rule);
  };

  const openNewAsset = () => {
    setEditingAsset(null);
    setAssetSheetOpen(true);
  };

  const openAssetEditor = (asset: AssetFile) => {
    setEditingAsset(asset);
    setAssetSheetOpen(true);
  };

  const saveAsset = (asset: AssetFile) => {
    const byId = assetFiles.find((item) => item.id === asset.id);
    if (byId) {
      updateAssetFile(asset.id, asset);
      return;
    }
    const byName = assetFiles.find((item) => item.remarks === asset.remarks);
    if (byName) {
      updateAssetFile(byName.id, {
        remarks: asset.remarks,
        url: asset.url,
        locked: byName.locked,
      });
      return;
    }
    addAssetFile(asset);
  };

  const ensureProxyForAssetDownload = () => {
    if (settings.assetUpdateMode === "proxy" && !isServiceUp(service.state)) {
      notify(t("common.proxyNotRunning"));
      return false;
    }
    return true;
  };

  const runAssetDownload = async (id: string) => {
    if (!ensureProxyForAssetDownload()) return;
    setBusyAssets((current) => [...current, id]);
    try {
      await downloadAsset(id, settings.assetUpdateMode);
    } finally {
      setBusyAssets((current) => current.filter((item) => item !== id));
    }
  };

  const updateAllAssets = async () => {
    if (!ensureProxyForAssetDownload()) return;
    for (const asset of assetFiles) {
      await runAssetDownload(asset.id);
    }
  };

  const addResourceLink = (remarks: string, url: string) => {
    const existing = assetFiles.find((item) => item.remarks === remarks);
    if (existing) {
      updateAssetFile(existing.id, { url, lastUpdated: null });
      return;
    }
    addAssetFile({
      id: uid(),
      remarks,
      url,
      lastUpdated: null,
      locked: false,
    });
  };

  const setRoutingMode = (mode: typeof settings.routingMode) => set("routingMode", mode);

  const preset = coresPreset(settings.coreByProtocol);
  const coresSummary =
    preset === "default"
      ? t("settings.coresPreset.default")
      : preset === "custom"
        ? t("settings.coresPreset.custom")
        : preset;
  const summary: Record<SettingsPage, string> = {
    routing:
      settings.routingMode === "rules"
        ? `${t("settings.routingRulesEditor")} · ${t("settings.rulesCount", { count: routingRules.length })}`
        : settings.routingMode === "custom"
          ? t("settings.routingCustom")
          : t("settings.routingGlobal"),
    cores: `${coresSummary} · ${t("settings.tunEngine")}`,
    network: t("settings.page.networkSub"),
    resources: t("settings.assetCount", { count: assetFiles.length }),
    app: `${LOCALES[lang].label} · ${t("settings.page.appSub")}`,
    about: t("settings.page.aboutSub"),
  };

  const list = (
    <Card style={{ padding: "4px 10px" }}>
      {SETTINGS_PAGES.map((p) => (
        <NavRow
          key={p.id}
          icon={p.icon}
          title={t(p.titleKey)}
          sub={summary[p.id]}
          selected={isWide && page === p.id}
          onClick={() => openPage(p.id)}
        />
      ))}
    </Card>
  );

  const pageBody = (current: SettingsPage) => {
    switch (current) {
      case "routing":
        return (
          <RoutingSection
            settings={settings}
            set={set}
            routingRules={routingRules}
            profiles={profileOptions}
            setRoutingMode={setRoutingMode}
            openNewRule={openNewRule}
            onEditRule={openRuleEditor}
            addRoutingRule={addRoutingRule}
            updateRoutingRule={updateRoutingRule}
            reorderRoutingRules={reorderRoutingRules}
            removeRoutingRule={removeRoutingRule}
            onOpenRulesIO={() => setRulesIOOpen(true)}
            onOpenAppFilter={onOpenAppFilter}
          />
        );
      case "cores":
        return (
          <>
            <CoresSection
              coreByProtocol={settings.coreByProtocol}
              coreFor={coreFor}
              setCoreFor={setCoreFor}
              setCoreMap={setCoreMap}
            />
            <TunEngineSection settings={settings} set={set} />
          </>
        );
      case "network":
        return (
          <>
            <DnsSection settings={settings} set={set} />
            <ConnectionSection settings={settings} set={set} />
            <LocalPortsSection settings={settings} set={set} />
          </>
        );
      case "resources":
        return (
          <AssetFilesSection
            assetFiles={assetFiles}
            busyAssetSet={busyAssetSet}
            runAssetDownload={runAssetDownload}
            updateAllAssets={updateAllAssets}
            openNewAsset={openNewAsset}
            onEditAsset={openAssetEditor}
            settings={settings}
            set={set}
            addResourceLink={addResourceLink}
            removeAssetFile={removeAssetFile}
          />
        );
      case "app":
        return (
          <>
            <SystemSection
              settings={settings}
              set={set}
              onOpenBackup={onOpenBackup}
              onOpenLogs={onOpenLogs}
            />
            <AdvancedSection settings={settings} set={set} />
          </>
        );
      case "about":
        return (
          <>
            <AboutSection />
            <DiagnosticsSection
              bridgeMode={bridgeMode}
              xrayVersion={caps?.xrayVersion ?? ""}
              singboxVersion={caps?.singboxVersion ?? ""}
              tun={caps?.tun ?? false}
              profilesCount={profiles.length}
              subscriptionsCount={subscriptions.length}
              activeId={activeId}
            />
          </>
        );
    }
  };

  const pageTitle = page
    ? t(SETTINGS_PAGES.find((p) => p.id === page)?.titleKey ?? "settings.title")
    : "";

  return (
    <div className="app-region screen-enter">
      {isWide ? (
        <div className="settings-split">
          <div className="settings-nav" style={{ display: "flex", flexDirection: "column" }}>
            <AppBar title={t("settings.title")} subtitle={t("settings.subtitle")} />
            <div className="scroll">{list}</div>
          </div>
          <div
            className="settings-page"
            style={{ display: "flex", flexDirection: "column" }}
            key={page ?? ""}
          >
            <AppBar title={pageTitle} />
            <div className="scroll">
              {page && pageBody(page)}
              <div style={{ height: 10 }} />
            </div>
          </div>
        </div>
      ) : page ? (
        <div className="app-region screen-enter" key={page}>
          <AppBar
            title={pageTitle}
            left={<IconBtn name="arrow_back" title={t("settings.title")} onClick={closePage} />}
          />
          <div className="scroll">
            {pageBody(page)}
            <div style={{ height: 10 }} />
          </div>
        </div>
      ) : (
        <>
          <AppBar title={t("settings.title")} subtitle={t("settings.subtitle")} />
          <div className="scroll">{list}</div>
        </>
      )}

      {ruleSheetOpen && (
        <Suspense fallback={null}>
          <RoutingRuleSheet
            open={ruleSheetOpen}
            rule={editingRule}
            profiles={profileOptions}
            onClose={() => setRuleSheetOpen(false)}
            onSave={saveRule}
            onDelete={removeRoutingRule}
          />
        </Suspense>
      )}
      {rulesIOOpen && (
        <Suspense fallback={null}>
          <RoutingRulesIOSheet open={rulesIOOpen} onClose={() => setRulesIOOpen(false)} />
        </Suspense>
      )}
      {assetSheetOpen && (
        <Suspense fallback={null}>
          <AssetFileSheet
            open={assetSheetOpen}
            asset={editingAsset}
            onClose={() => setAssetSheetOpen(false)}
            onSave={saveAsset}
            onDelete={removeAssetFile}
          />
        </Suspense>
      )}
    </div>
  );
}
