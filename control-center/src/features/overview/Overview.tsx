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
  SectionLabel,
} from "../../components";
import { useT } from "../../i18n";
import { formatRate, formatUptime } from "../../lib/format";
import { profileEndpointLabel } from "../../lib/profile";
import { resolveCore } from "../../lib/schema/core";
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
  const settings = useAppStore((s) => s.settings);
  const busy = useAppStore((s) => s.busy);
  const toggleService = useAppStore((s) => s.toggleService);
  const restart = useAppStore((s) => s.restart);
  const pingAll = useAppStore((s) => s.pingAll);
  const realPingAll = useAppStore((s) => s.realPingAll);
  const speedTestAll = useAppStore((s) => s.speedTestAll);
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

  const active = profiles.find((p) => p.id === activeId);
  const resolvedCore = active ? resolveCore(active, settings) : null;
  const enabledSubs = subs.filter((s) => s.enabled).length;
  const running = service.state === "running";
  const starting = busy && service.state === "connecting";
  const connecting = service.state === "connecting" || busy;
  const stateLabel = running
    ? t("overview.running")
    : starting
      ? t("overview.starting")
      : connecting
        ? t("overview.connecting")
        : t("overview.stopped");
  const actionLabel = running
    ? t("overview.stop")
    : starting
      ? t("overview.starting_btn")
      : connecting
        ? t("overview.connecting_btn")
        : t("overview.start");
  const coreSummary =
    running && service.core ? service.core : (resolvedCore ?? service.core ?? t("common.xrayCore"));

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
              background: running
                ? "radial-gradient(120% 130% at 100% 0%, oklch(0.40 0.10 155 / 0.55), transparent 60%)"
                : connecting
                  ? "radial-gradient(120% 130% at 100% 0%, oklch(0.42 0.10 85 / 0.5), transparent 60%)"
                  : "transparent",
              transition: "background 0.4s",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16 }}>
              <span
                className={`state-dot ${running ? "run" : connecting ? "connecting" : "stop"}`}
              />
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 700,
                  letterSpacing: 0.4,
                  textTransform: "uppercase",
                  color: running
                    ? "var(--running)"
                    : connecting
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
              <button
                type="button"
                onClick={() => onNavigate("profiles")}
                style={{
                  appearance: "none",
                  background: "none",
                  border: "none",
                  color: "inherit",
                  cursor: "pointer",
                  padding: 0,
                  textAlign: "left",
                }}
              >
                <div style={{ fontSize: 22, fontWeight: 600, lineHeight: 1.2 }}>
                  {active.remarks}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                  <ProtoTag protocol={active.protocol} />
                  <EngineTag engine={resolvedCore ?? "xray"} />
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
                value={running ? formatRate(downloadRate) : formatRate(0)}
                color="var(--running)"
              />
              <Stat
                icon="north"
                label={t("overview.upload")}
                value={running ? formatRate(uploadRate) : formatRate(0)}
                color="var(--primary)"
              />
              <Stat
                icon="schedule"
                label={t("overview.uptime")}
                value={running ? formatUptime(service.uptimeSec) : "—"}
              />
              <Stat
                icon="bolt"
                label={t("overview.ping")}
                value={active ? (active.ping == null ? "—" : `${active.ping} ms`) : "—"}
              />
            </div>
          </div>

          <div
            style={{ display: "flex", gap: 10, padding: "0 16px 16px", flexDirection: "column" }}
          >
            {needsAssets && !running && (
              <div style={{ fontSize: 13, color: "var(--error)", paddingBottom: 4 }}>
                {t("overview.needsAssets")}
              </div>
            )}
            <div style={{ display: "flex", gap: 10 }}>
              <Btn
                onClick={toggleService}
                disabled={connecting || (!running && (!activeId || needsAssets))}
                style={{
                  flex: 2,
                  height: 52,
                  fontSize: 15,
                  background: running ? "var(--error-container)" : "var(--running)",
                  color: running ? "oklch(0.92 0.04 25)" : "var(--on-running)",
                }}
              >
                <Icon
                  name={running ? "stop" : connecting ? "autorenew" : "play_arrow"}
                  className={connecting ? "spin" : ""}
                />
                {actionLabel}
              </Btn>
              <Btn
                variant="tonal"
                onClick={restart}
                disabled={!running}
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
          onTcping={() => {
            void pingAll();
            setPingSheetOpen(false);
          }}
          onRealping={() => {
            void realPingAll();
            setPingSheetOpen(false);
          }}
          onSpeedTest={() => {
            void speedTestAll();
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
        <Card style={{ padding: "4px 14px" }}>
          {recentActivity.length === 0 ? (
            <div
              className="list-row"
              style={{ cursor: "default", color: "var(--on-surface-faint)", fontSize: 13 }}
            >
              {t("overview.activity.profiles", {
                profiles: profiles.length,
                groups: groups.length,
              })}
            </div>
          ) : (
            recentActivity.map((l) => (
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
            ))
          )}
        </Card>
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
        style={{ fontSize: 15, fontWeight: 600, marginTop: 3, whiteSpace: "nowrap" }}
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
      className="flat"
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
