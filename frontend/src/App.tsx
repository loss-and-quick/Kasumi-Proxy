// ============================================================
// App.tsx
// Store-driven app shell using the prototype-inspired M3 layout.
// Tabs use hash routing; overlays (editor / backup / logs) use
// internal state so the UI remains robust under WebView/file-ish
// contexts.
// ============================================================
import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Icon, Toast } from "./components";
import Overview from "./features/overview/Overview";
import { useT } from "./i18n";
import { configureKsuWebUi, hasKsuNativeApi } from "./lib/ksu-webui";
import { useIsWide } from "./lib/useIsWide";
import { useAppStore } from "./store/useAppStore";

const Backup = lazy(() => import("./features/backup/Backup"));
const Editor = lazy(() => import("./features/editor/Editor"));
const Logs = lazy(() => import("./features/logs/Logs"));
const Profiles = lazy(() => import("./features/profiles/Profiles"));
const Settings = lazy(() => import("./features/settings/Settings"));
const Subscriptions = lazy(() => import("./features/subscriptions/Subscriptions"));
const AppFilterPage = lazy(() => import("./features/appfilter/AppFilterPage"));

type Tab = "overview" | "profiles" | "subs" | "settings";

function LoadingScreen({ label }: { label: string }) {
  return (
    <div
      className="app-region screen-enter"
      style={{ alignItems: "center", justifyContent: "center" }}
    >
      <div style={{ color: "var(--on-surface-faint)", fontSize: 14 }}>{label}</div>
    </div>
  );
}

function getInitialTab(): Tab {
  if (typeof window !== "undefined") {
    const hash = window.location.hash.replace("#", "");
    if (hash === "profiles" || hash === "subs" || hash === "settings") return hash;
  }
  return "overview";
}

export default function App() {
  const hydrate = useAppStore((s) => s.hydrate);
  const hydrated = useAppStore((s) => s.hydrated);
  const toast = useAppStore((s) => s.toast);
  const t = useT();

  const [tab, setTab] = useState<Tab>(getInitialTab);
  const [editorId, setEditorId] = useState<string | "new" | null>(null);
  const [backupOpen, setBackupOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const [appFilterOpen, setAppFilterOpen] = useState(false);
  const isWide = useIsWide();

  useEffect(() => {
    hydrate();
  }, [hydrate]);
  useEffect(() => {
    configureKsuWebUi();
  }, []);
  useEffect(() => {
    const onHash = () => setTab(getInitialTab());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const nav = useMemo(
    () => ({
      go(next: Tab) {
        setEditorId(null);
        setBackupOpen(false);
        setLogsOpen(false);
        setAppFilterOpen(false);
        setTab(next);
        window.location.hash = next;
      },
      openEditor(id: string | "new") {
        setEditorId(id);
      },
      openBackup() {
        setBackupOpen(true);
      },
      openLogs() {
        setLogsOpen(true);
      },
      openAppFilter() {
        setAppFilterOpen(true);
      },
    }),
    [],
  );

  const navItems: Array<{
    id: Tab;
    icon: string;
    labelKey: "nav.overview" | "nav.profiles" | "nav.subs" | "nav.settings";
  }> = [
    { id: "overview", icon: "space_dashboard", labelKey: "nav.overview" },
    { id: "profiles", icon: "dns", labelKey: "nav.profiles" },
    { id: "subs", icon: "cloud_sync", labelKey: "nav.subs" },
    { id: "settings", icon: "tune", labelKey: "nav.settings" },
  ];
  const nativeToast = hasKsuNativeApi();
  const navVisible = !editorId && !backupOpen && !logsOpen && !appFilterOpen;
  const loadingScreen = <LoadingScreen label={t("app.loading")} />;
  const currentScreen =
    tab === "overview" ? (
      <Overview onNavigate={nav.go} onOpenLogs={nav.openLogs} onOpenBackup={nav.openBackup} />
    ) : tab === "profiles" ? (
      <Profiles onOpenEditor={nav.openEditor} />
    ) : tab === "subs" ? (
      <Subscriptions />
    ) : (
      <Settings
        onOpenBackup={nav.openBackup}
        onOpenLogs={nav.openLogs}
        onOpenAppFilter={nav.openAppFilter}
      />
    );

  return (
    <div className={`device${isWide ? " wide" : ""}`}>
      {isWide && navVisible && (
        <nav className="siderail">
          <div className="siderail-brand">kasumi</div>
          {navItems.map((n) => (
            <button
              type="button"
              key={n.id}
              className={`siderail-item${tab === n.id ? " active" : ""}`}
              onClick={() => nav.go(n.id)}
            >
              <Icon name={n.icon} />
              <span>{t(n.labelKey)}</span>
            </button>
          ))}
        </nav>
      )}

      <div className="app-main" key={tab}>
        {!hydrated ? loadingScreen : <Suspense fallback={loadingScreen}>{currentScreen}</Suspense>}
      </div>

      {!isWide && navVisible && (
        <div className="botnav">
          {navItems.map((n) => (
            <button
              type="button"
              key={n.id}
              className={`botnav-item${tab === n.id ? " active" : ""}`}
              onClick={() => nav.go(n.id)}
            >
              <div className="botnav-pill">
                <Icon name={n.icon} />
              </div>
              {t(n.labelKey)}
            </button>
          ))}
        </div>
      )}

      {editorId && (
        <Suspense fallback={null}>
          <Editor profileId={editorId} onClose={() => setEditorId(null)} />
        </Suspense>
      )}
      {backupOpen && (
        <Suspense fallback={null}>
          <Backup onClose={() => setBackupOpen(false)} />
        </Suspense>
      )}
      {logsOpen && (
        <Suspense fallback={null}>
          <Logs onClose={() => setLogsOpen(false)} />
        </Suspense>
      )}
      {appFilterOpen && (
        <Suspense fallback={null}>
          <AppFilterPage onBack={() => setAppFilterOpen(false)} />
        </Suspense>
      )}
      {!nativeToast && <Toast msg={toast} />}
    </div>
  );
}
