// ============================================================
// features/overview/Overview.tsx
// Operational dashboard — first screen users see.
// ============================================================

import { useEffect, useRef, useState } from "react";
import {
  AppBar,
  Btn,
  Card,
  EngineTag,
  Icon,
  IconBtn,
  ProtoTag,
  pingLabel,
  SectionLabel,
} from "../../components";
import { useT } from "../../i18n";
import { isServiceUp } from "../../lib/bridge";
import { formatRate, formatUptime } from "../../lib/format";
import { profileEndpointLabel } from "../../lib/profile-utils";
import { useAppStore } from "../../store/useAppStore";
import { PingActionsSheet } from "../profiles/PingActionsSheet";

export default function Overview({
  onNavigate,
  onOpenLogs,
  onOpenBackup,
}: {
  onNavigate: (screen: "overview" | "profiles" | "subs" | "settings") => void;
  onOpenLogs: () => void;
  onOpenBackup: () => void;
}) {
  const profiles = useAppStore((s) => s.profiles);
  const groups = useAppStore((s) => s.groups);
  const subs = useAppStore((s) => s.subscriptions);
  const service = useAppStore((s) => s.service);
  const downloadRate = useAppStore((s) => s.downloadRate);
  const uploadRate = useAppStore((s) => s.uploadRate);
  const assetFiles = useAppStore((s) => s.assetFiles);
  const activeId = useAppStore((s) => s.activeId);
  const activePing = useAppStore((s) =>
    activeId ? (s.testResults[activeId]?.ping ?? null) : null,
  );
  const settings = useAppStore((s) => s.settings);
  const busy = useAppStore((s) => s.busy);
  const toggleService = useAppStore((s) => s.toggleService);
  const restart = useAppStore((s) => s.restart);
  const testAll = useAppStore((s) => s.testAll);
  const pinging = useAppStore((s) => s.pinging);
  const speedTesting = useAppStore((s) => s.speedTesting);
  const removeUnreachable = useAppStore((s) => s.removeUnreachable);
  const selectBest = useAppStore((s) => s.selectBest);
  const [pingSheetOpen, setPingSheetOpen] = useState(false);
  const updateAllSubs = useAppStore((s) => s.updateAllSubs);
  const t = useT();

  const recentActivity = useAppStore((s) => s.recentActivity);
  const [, setTick] = useState(0);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Re-render every 30 s so relative timestamps stay fresh
  useEffect(() => {
    tickRef.current = setInterval(() => setTick((n) => n + 1), 30_000);
    return () => {
      if (tickRef.current) clearInterval(tickRef.current);
    };
  }, []);

  const needsAssets =
    settings.routingMode !== "global" && !assetFiles.some((a) => a.lastUpdated != null);

  const active = profiles.find((p) => p.meta.id === activeId);
  // Backend-resolved core of the active profile (`resolveCores` cache in the store).
  const resolvedCore = useAppStore((s) =>
    activeId ? (s.coreResolutions[activeId]?.resolved ?? null) : null,
  );
  const enabledSubs = subs.filter((s) => s.enabled).length;
  const connected = service.state === "connected";
  const noInternet = service.state === "noInternet";
  const failed = service.state === "failed";
  const starting = busy && service.state === "connecting";
  const connecting = service.state === "connecting" || busy;
  const up = isServiceUp(service.state); // core is up: connecting | connected | noInternet
  const onSteady = connected || noInternet; // settled "on" — stoppable / restartable
  const warn = (connecting || noInternet) && !connected; // amber tone
  const stateLabel = connected
    ? t("overview.running")
    : noInternet
      ? t("overview.noInternet")
      : starting
        ? t("overview.starting")
        : connecting
          ? t("overview.connecting")
          : failed
            ? t("overview.failed")
            : t("overview.stopped");
  const actionLabel = onSteady
    ? t("overview.stop")
    : starting
      ? t("overview.starting_btn")
      : connecting
        ? t("overview.connecting_btn")
        : t("overview.start");
  const coreSummary =
    up && service.core ? service.core : (resolvedCore ?? service.core ?? t("common.xrayCore"));

  const now = Date.now();
  const relTime = (at: number): string => {
    const sec = Math.floor((now - at) / 1000);
    if (sec < 60) return t("time.now");
    const min = Math.floor(sec / 60);
    if (min < 60) return t("time.ago", { n: min, unit: t("time.unit.m") });
    const hr = Math.floor(min / 60);
    return t("time.ago", { n: hr, unit: t("time.unit.h") });
  };

  return (
    <div className="app-region screen-enter">
      <AppBar
        large
        title={t("overview.title")}
        subtitle={t("overview.subtitle")}
        actions={<IconBtn name="description" title={t("overview.logs")} onClick={onOpenLogs} />}
      />
      <div className="scroll">
        <Card className="tonal" style={{ padding: 0, overflow: "hidden", borderRadius: 24 }}>
          <div
            style={{
              padding: "20px 20px 18px",
              background: connected
                ? "radial-gradient(120% 130% at 100% 0%, oklch(0.40 0.10 155 / 0.55), transparent 60%)"
                : warn
                  ? "radial-gradient(120% 130% at 100% 0%, oklch(0.42 0.10 85 / 0.5), transparent 60%)"
                  : "transparent",
              transition: "background 0.4s",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16 }}>
              <span className={`state-dot ${connected ? "run" : warn ? "connecting" : "stop"}`} />
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 700,
                  letterSpacing: 0.4,
                  textTransform: "uppercase",
                  color: connected
                    ? "var(--running)"
                    : warn
                      ? "var(--warn)"
                      : "var(--on-surface-faint)",
                }}
              >
                {stateLabel}
              </span>
              <div
                style={{
                  marginLeft: "auto",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  minWidth: 0,
                }}
              >
                <span
                  className="mono"
                  style={{ fontSize: 11.5, color: "var(--on-surface-variant)" }}
                >
                  {coreSummary}
                </span>
              </div>
            </div>

            {active ? (
              <button type="button" className="btn-reset" onClick={() => onNavigate("profiles")}>
                <div style={{ fontSize: 22, fontWeight: 600, lineHeight: 1.2 }}>
                  {active.meta.remarks}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                  <ProtoTag protocol={active.protocol} />
                  {/* While running show the engine that actually runs (PID truth
                      from status); resolveCore is only the intent for next start. */}
                  <EngineTag engine={(up && service.engine) || resolvedCore || "xray"} />
                  <span
                    className="mono truncate"
                    style={{ fontSize: 12.5, color: "var(--on-surface-variant)" }}
                  >
                    {profileEndpointLabel(active)}
                  </span>
                </div>
              </button>
            ) : (
              <div style={{ fontSize: 17, color: "var(--on-surface-variant)" }}>
                {t("overview.noActiveProfile")}
              </div>
            )}

            <div style={{ display: "flex", gap: 22, marginTop: 18, flexWrap: "wrap" }}>
              <Stat
                icon="south"
                label={t("overview.download")}
                value={up ? formatRate(downloadRate) : formatRate(0)}
                color="var(--running)"
              />
              <Stat
                icon="north"
                label={t("overview.upload")}
                value={up ? formatRate(uploadRate) : formatRate(0)}
                color="var(--primary)"
              />
              <Stat
                icon="schedule"
                label={t("overview.uptime")}
                value={up ? formatUptime(service.uptimeSec) : "—"}
              />
              <Stat
                icon="bolt"
                label={t("overview.ping")}
                value={active ? pingLabel(activePing) : "—"}
                color={active && activePing != null && activePing < 0 ? "var(--error)" : undefined}
              />
            </div>
          </div>

          <div
            style={{ display: "flex", gap: 10, padding: "0 16px 16px", flexDirection: "column" }}
          >
            {needsAssets && !up && (
              <div style={{ fontSize: 13, color: "var(--error)", paddingBottom: 4 }}>
                {t("overview.needsAssets")}
              </div>
            )}
            <div className="primary-actions" style={{ display: "flex", gap: 10 }}>
              <Btn
                onClick={toggleService}
                disabled={connecting || (!up && (!activeId || needsAssets))}
                style={{
                  flex: 2,
                  height: 52,
                  fontSize: 15,
                  background: onSteady ? "var(--error-container)" : "var(--running)",
                  color: onSteady ? "oklch(0.92 0.04 25)" : "var(--on-running)",
                }}
              >
                <Icon
                  name={onSteady ? "stop" : connecting ? "autorenew" : "play_arrow"}
                  className={connecting ? "spin" : ""}
                />
                {actionLabel}
              </Btn>
              <Btn
                variant="tonal"
                onClick={restart}
                disabled={!onSteady}
                style={{ flex: 1, height: 52 }}
              >
                <Icon name="restart_alt" /> {t("overview.restart")}
              </Btn>
            </div>
          </div>
        </Card>

        <div
          style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 10, marginTop: 12 }}
        >
          <Counter
            n={profiles.length}
            label={t("overview.profilesCounter")}
            icon="dns"
            onClick={() => onNavigate("profiles")}
          />
          <Counter
            n={groups.length}
            label={t("overview.groupsCounter")}
            icon="folder"
            onClick={() => onNavigate("profiles")}
          />
          <Counter
            n={enabledSubs}
            label={t("overview.subsCounter")}
            icon="cloud_sync"
            onClick={() => onNavigate("subs")}
          />
        </div>

        <SectionLabel>{t("overview.quickActions")}</SectionLabel>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
          <QuickAction
            icon="dns"
            label={t("overview.openProfiles")}
            onClick={() => onNavigate("profiles")}
          />
          <QuickAction
            icon="cloud_sync"
            label={t("overview.updateAllSubs")}
            onClick={updateAllSubs}
          />
          <QuickAction
            icon="speed"
            label={t("overview.pingAll")}
            onClick={() => setPingSheetOpen(true)}
          />
          <QuickAction icon="backup" label={t("overview.backupRestore")} onClick={onOpenBackup} />
        </div>
        <PingActionsSheet
          open={pingSheetOpen}
          onClose={() => setPingSheetOpen(false)}
          pinging={pinging.size > 0}
          speedTesting={speedTesting.size > 0}
          onTestAll={(kind) => {
            void testAll(kind);
            setPingSheetOpen(false);
          }}
          onDeleteUnreachable={() => {
            void removeUnreachable();
            setPingSheetOpen(false);
          }}
          onSelectBest={() => {
            selectBest();
            setPingSheetOpen(false);
          }}
        />

        <SectionLabel>{t("overview.recentActivity")}</SectionLabel>
        {recentActivity.length > 0 && (
          <Card style={{ padding: "4px 14px" }}>
            {recentActivity.map((l) => (
              <div key={`${l.at}-${l.text}`} className="list-row" style={{ cursor: "default" }}>
                <div className="lr-icon" style={{ background: "transparent", width: 30 }}>
                  <Icon
                    name={l.icon}
                    style={{ fontSize: 19, color: l.color || "var(--on-surface-variant)" }}
                  />
                </div>
                <div className="lr-main">
                  <div className="lr-title" style={{ fontSize: 13.5, fontWeight: 400 }}>
                    {l.text}
                  </div>
                </div>
                <span className="mono" style={{ fontSize: 11, color: "var(--on-surface-faint)" }}>
                  {relTime(l.at)}
                </span>
              </div>
            ))}
          </Card>
        )}
        <div style={{ height: 8 }} />
      </div>
    </div>
  );
}

function Stat({
  icon,
  label,
  value,
  color,
}: {
  icon: string;
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 4,
          color: "var(--on-surface-faint)",
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: 0.3,
          textTransform: "uppercase",
        }}
      >
        <Icon name={icon} style={{ fontSize: 14, color: color || "var(--on-surface-faint)" }} />
        {label}
      </div>
      <div
        className="mono"
        style={{ fontSize: 15, fontWeight: 600, marginTop: 3, whiteSpace: "nowrap", color }}
      >
        {value}
      </div>
    </div>
  );
}

function Counter({
  n,
  label,
  icon,
  onClick,
}: {
  n: number;
  label: string;
  icon: string;
  onClick: () => void;
}) {
  return (
    <Card onClick={onClick} style={{ cursor: "pointer", padding: 14, textAlign: "left" }}>
      <Icon name={icon} style={{ fontSize: 20, color: "var(--primary)" }} />
      <div style={{ fontSize: 26, fontWeight: 700, marginTop: 6, lineHeight: 1 }}>{n}</div>
      <div style={{ fontSize: 12, color: "var(--on-surface-variant)", marginTop: 3 }}>{label}</div>
    </Card>
  );
}

function QuickAction({
  icon,
  label,
  onClick,
}: {
  icon: string;
  label: string;
  onClick: () => void;
}) {
  return (
    <Card
      onClick={onClick}
      style={{ cursor: "pointer", display: "flex", alignItems: "center", gap: 12, padding: 14 }}
    >
      <div
        style={{
          width: 38,
          height: 38,
          borderRadius: 11,
          background: "var(--primary-container)",
          color: "var(--on-primary-container)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flex: "0 0 auto",
        }}
      >
        <Icon name={icon} style={{ fontSize: 20 }} />
      </div>
      <span style={{ fontSize: 13, fontWeight: 500, lineHeight: 1.25 }}>{label}</span>
    </Card>
  );
}
