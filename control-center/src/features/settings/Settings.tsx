// ============================================================
// features/settings/Settings.tsx
// Engine and UI settings.
// ============================================================
import { lazy, Suspense, useMemo, useState } from "react";
import { AppBar } from "../../components";
import { useLang, useT } from "../../i18n";
import type { ResourceUpdateMode } from "../../lib/bridge";
import { getRuntimeBridgeMode } from "../../lib/ksu-webui";
import {
  type AssetFile,
  type CoreEngineT,
  defaultCoreFor,
  type Protocol,
  type RoutingRule,
} from "../../lib/schema";
import { uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { AdvancedSection } from "./sections/AdvancedSection";
import { AppFilterSection } from "./sections/AppFilterSection";
import { AssetFilesSection } from "./sections/AssetFilesSection";
import { ConnectionSection } from "./sections/ConnectionSection";
import { CoresSection } from "./sections/CoresSection";
import { DiagnosticsSection } from "./sections/DiagnosticsSection";
import { DnsSection } from "./sections/DnsSection";
import { LanguageSection } from "./sections/LanguageSection";
import { LocalPortsSection } from "./sections/LocalPortsSection";
import { RoutingSection } from "./sections/RoutingSection";
import { SystemSection } from "./sections/SystemSection";

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
  const { lang, setLang } = useLang();

  const [editingRule, setEditingRule] = useState<RoutingRule | null>(null);
  const [ruleSheetOpen, setRuleSheetOpen] = useState(false);
  const [editingAsset, setEditingAsset] = useState<AssetFile | null>(null);
  const [assetSheetOpen, setAssetSheetOpen] = useState(false);
  const [busyAssets, setBusyAssets] = useState<string[]>([]);
  const [resourceUpdateMode, setResourceUpdateMode] = useState<ResourceUpdateMode>("auto");
  const [rulesIOOpen, setRulesIOOpen] = useState(false);

  const coreFor = (protocol: Protocol): CoreEngineT =>
    settings.coreByProtocol?.[protocol] ?? defaultCoreFor(protocol);
  const setCoreFor = (protocol: Protocol, value: CoreEngineT) =>
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
    if (resourceUpdateMode === "proxy" && service.state !== "running") {
      notify(t("settings.assetProxyNotRunning"));
      return false;
    }
    return true;
  };

  const runAssetDownload = async (id: string) => {
    if (!ensureProxyForAssetDownload()) return;
    setBusyAssets((current) => [...current, id]);
    try {
      await downloadAsset(id, resourceUpdateMode);
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

  const running = service.state === "running";

  return (
    <div className="app-region screen-enter">
      <AppBar title={t("settings.title")} subtitle={t("settings.subtitle")} />
      <div className="scroll">
        <DiagnosticsSection
          bridgeMode={bridgeMode}
          core={service.core}
          profilesCount={profiles.length}
          subscriptionsCount={subscriptions.length}
          activeId={activeId}
        />
        {running && (
          <div
            style={{
              margin: "12px 0 2px",
              padding: "12px 16px",
              borderRadius: 12,
              borderLeft: "3px solid var(--running)",
              background: "var(--sc-low)",
              color: "var(--on-surface-variant)",
              fontSize: 13,
              lineHeight: 1.5,
            }}
          >
            {t("settings.proxyRunningWarning")}
          </div>
        )}
        <div style={running ? { pointerEvents: "none", opacity: 0.5 } : undefined}>
          <RoutingSection
            settings={settings}
            set={set}
            routingRules={routingRules}
            profiles={profiles}
            setRoutingMode={setRoutingMode}
            openNewRule={openNewRule}
            onEditRule={openRuleEditor}
            addRoutingRule={addRoutingRule}
            updateRoutingRule={updateRoutingRule}
            reorderRoutingRules={reorderRoutingRules}
            removeRoutingRule={removeRoutingRule}
            onOpenRulesIO={() => setRulesIOOpen(true)}
          />
          <AppFilterSection settings={settings} set={set} onOpenAppFilter={onOpenAppFilter} />
          <AssetFilesSection
            assetFiles={assetFiles}
            busyAssetSet={busyAssetSet}
            runAssetDownload={runAssetDownload}
            updateAllAssets={updateAllAssets}
            openNewAsset={openNewAsset}
            onEditAsset={openAssetEditor}
            resourceUpdateMode={resourceUpdateMode}
            setResourceUpdateMode={setResourceUpdateMode}
            addResourceLink={addResourceLink}
            removeAssetFile={removeAssetFile}
          />
          <CoresSection coreFor={coreFor} setCoreFor={setCoreFor} />
          <DnsSection settings={settings} set={set} />
          <ConnectionSection settings={settings} set={set} />
          <LocalPortsSection settings={settings} set={set} />
        </div>
        <AdvancedSection settings={settings} set={set} />
        <LanguageSection lang={lang} setLang={setLang} />
        <SystemSection
          settings={settings}
          set={set}
          onOpenBackup={onOpenBackup}
          onOpenLogs={onOpenLogs}
        />
        <div style={{ height: 10 }} />
      </div>

      {ruleSheetOpen && (
        <Suspense fallback={null}>
          <RoutingRuleSheet
            open={ruleSheetOpen}
            rule={editingRule}
            profiles={profiles}
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
