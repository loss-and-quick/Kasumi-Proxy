// ============================================================
// features/appfilter/AppFilterPage.tsx
// Per-app proxy filter: each app can be set to default/bypass/force-proxy.
// Rendered as a full-screen overlay (.fullpage) over the current screen.
// ============================================================
import { useEffect, useMemo, useState } from "react";
import { AppBar, Card, Chip, ListRow, SectionLabel } from "../../components";
import { IconBtn } from "../../components/icons";
import { useT } from "../../i18n";
import type { AppEntry } from "../../lib/bridge";
import { bridge } from "../../lib/bridge-provider";
import { fuzzyScore, NO_MATCH } from "../../lib/fuzzy";
import { useAppStore } from "../../store/useAppStore";

// pkg:uid uniquely identifies one profile instance of an app.
const filterKey = (app: AppEntry) => `${app.pkg}:${app.uid}`;
// userId > 0 means work/secondary profile.
const profileLabel = (app: AppEntry): string | null => {
  const userId = Math.floor(app.uid / 100000);
  return userId > 0 ? `Profile ${userId}` : null;
};

export default function AppFilterPage({ onBack }: { onBack: () => void }) {
  const t = useT();
  const settings = useAppStore((s) => s.settings);
  const setSetting = useAppStore((s) => s.setSetting);
  const setAppFilterMode = useAppStore((s) => s.setAppFilterMode);

  const [apps, setApps] = useState<AppEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");

  const captureMode = settings.appCaptureMode ?? "all";
  const appFilter = settings.appFilter ?? {};

  useEffect(() => {
    bridge
      .listApps()
      .then((list) => {
        const seen = new Set<string>();
        setApps(
          list.filter((a) => {
            const k = `${a.pkg}:${a.uid}`;
            return seen.has(k) ? false : seen.add(k);
          }),
        );
      })
      .catch(() => setApps([]))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim();
    if (q) {
      return apps
        .map((app) => ({
          app,
          score: fuzzyScore(`${app.label ?? ""} ${app.pkg}`, q),
        }))
        .filter((entry) => entry.score > NO_MATCH)
        .sort((a, b) => b.score - a.score || a.app.pkg.localeCompare(b.app.pkg))
        .map((entry) => entry.app);
    }
    return [...apps].sort((a, b) => {
      const ka = filterKey(a),
        kb = filterKey(b);
      const ma = appFilter[ka];
      const mb = appFilter[kb];
      if (ma && !mb) return -1;
      if (!ma && mb) return 1;
      if (a.system !== b.system) return a.system ? 1 : -1;
      return a.pkg.localeCompare(b.pkg) || a.uid - b.uid;
    });
  }, [apps, query, appFilter]);

  const activeCount = Object.keys(appFilter).length;

  return (
    <div className="fullpage screen-enter">
      <AppBar
        title={t("appFilter.title")}
        subtitle={activeCount > 0 ? t("appFilter.subtitle", { n: activeCount }) : undefined}
        left={<IconBtn name="arrow_back" title={t("editor.cancel")} onClick={onBack} />}
      />

      <div className="scroll">
        <SectionLabel>{t("appFilter.captureMode")}</SectionLabel>
        <Card style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ display: "flex", gap: 8 }}>
            <Chip
              active={captureMode === "all"}
              onClick={() => setSetting("appCaptureMode", "all")}
            >
              {t("appFilter.captureAll")}
            </Chip>
            <Chip
              active={captureMode === "none"}
              onClick={() => setSetting("appCaptureMode", "none")}
            >
              {t("appFilter.captureNone")}
            </Chip>
          </div>
          <div style={{ fontSize: 12, color: "var(--on-surface-faint)", lineHeight: 1.4 }}>
            {captureMode === "all" ? t("appFilter.captureAllHint") : t("appFilter.captureNoneHint")}
          </div>
        </Card>

        <SectionLabel>{t("appFilter.openPage")}</SectionLabel>
        <input
          className="input"
          placeholder={t("appFilter.search")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ marginBottom: 10 }}
        />

        {loading ? (
          <div style={{ padding: 24, textAlign: "center", color: "var(--on-surface-faint)" }}>
            {t("app.loading")}
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ padding: 24, textAlign: "center", color: "var(--on-surface-faint)" }}>
            {t("appFilter.empty")}
          </div>
        ) : (
          <Card style={{ padding: "4px 14px" }}>
            {filtered.map((app) => {
              const key = filterKey(app);
              const mode = appFilter[key] ?? null;
              const pLabel = profileLabel(app);
              return (
                <ListRow
                  key={key}
                  icon={app.iconUrl ? undefined : app.system ? "shield_moon" : "smart_toy"}
                  iconSlot={
                    app.iconUrl ? (
                      <img
                        src={app.iconUrl}
                        alt=""
                        loading="lazy"
                        decoding="async"
                        style={{ width: 36, height: 36, borderRadius: 8, flexShrink: 0 }}
                      />
                    ) : undefined
                  }
                  title={app.label ?? app.pkg}
                  sub={
                    [app.label ? app.pkg : app.system ? t("appFilter.systemApp") : null, pLabel]
                      .filter(Boolean)
                      .join(" · ") || undefined
                  }
                  right={
                    <div
                      style={{ display: "flex", flexDirection: "column", gap: 4, flexShrink: 0 }}
                    >
                      <Chip
                        active={mode === "bypass"}
                        onClick={() => setAppFilterMode(key, mode === "bypass" ? null : "bypass")}
                      >
                        {t("appFilter.bypass")}
                      </Chip>
                      <Chip
                        active={mode === "force-proxy"}
                        onClick={() =>
                          setAppFilterMode(key, mode === "force-proxy" ? null : "force-proxy")
                        }
                      >
                        {t("appFilter.forceProxy")}
                      </Chip>
                    </div>
                  }
                />
              );
            })}
          </Card>
        )}
        <div style={{ height: 16 }} />
      </div>
    </div>
  );
}
