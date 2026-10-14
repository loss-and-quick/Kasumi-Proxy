import { useState } from "react";
import { Btn, Card, ListRow, NavRow, SectionLabel, Sheet } from "../../../components";
import { useT } from "../../../i18n";
import { formatLogs, notableCount, recentLogs } from "../../../lib/logger";
import { copyText } from "../../profiles/clipboard";

export function DiagnosticsSection({
  bridgeMode,
  xrayVersion,
  singboxVersion,
  tun,
  profilesCount,
  subscriptionsCount,
  activeId,
  notify,
}: {
  bridgeMode: string;
  xrayVersion: string;
  singboxVersion: string;
  tun: boolean;
  profilesCount: number;
  subscriptionsCount: number;
  activeId: string | null;
  notify: (message: string) => void;
}) {
  const t = useT();
  const notInstalled = t("common.notInstalled");
  // What the UI itself recorded this session — render throws, dropped frames,
  // dispatches that failed. The backend's log says nothing about any of that.
  const [uiLogsOpen, setUiLogsOpen] = useState(false);
  const uiEntries = recentLogs();
  const notable = notableCount();

  return (
    <>
      <SectionLabel>{t("settings.diagnostics")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <ListRow icon="link" title={t("settings.bridge")} sub={bridgeMode} />
        <ListRow icon="bolt" title={t("settings.xrayVersion")} sub={xrayVersion || notInstalled} />
        <ListRow
          icon="bolt"
          title={t("settings.singboxVersion")}
          sub={singboxVersion || notInstalled}
        />
        <ListRow
          icon="shield_moon"
          title={t("settings.tun")}
          sub={tun ? t("common.available") : t("common.unavailable")}
        />
        <ListRow icon="dns" title={t("settings.profiles")} sub={`${profilesCount}`} />
        <ListRow
          icon="cloud_sync"
          title={t("settings.subscriptions")}
          sub={`${subscriptionsCount}`}
        />
        <ListRow
          icon="bookmark"
          title={t("settings.activeProfile")}
          sub={activeId ? t("settings.activeSelected") : t("settings.activeNone")}
        />
        <NavRow
          icon="description"
          title={t("settings.uiLogs")}
          sub={
            notable > 0
              ? t("settings.uiLogsCount", { count: `${notable}` })
              : t("settings.uiLogsEmpty")
          }
          onClick={() => setUiLogsOpen(true)}
        />
      </Card>

      <Sheet open={uiLogsOpen} title={t("settings.uiLogs")} onClose={() => setUiLogsOpen(false)}>
        {uiEntries.length === 0 ? (
          <p className="muted">{t("settings.uiLogsEmpty")}</p>
        ) : (
          <>
            <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
              <Btn
                variant="outline"
                onClick={async () =>
                  notify(
                    (await copyText(formatLogs(uiEntries)))
                      ? t("logs.copied")
                      : t("logs.copyFailed"),
                  )
                }
              >
                {t("logs.copy")}
              </Btn>
            </div>
            <textarea
              className="input mono"
              readOnly
              value={formatLogs(uiEntries)}
              style={{ minHeight: 320, whiteSpace: "pre", fontSize: 11.5 }}
            />
          </>
        )}
      </Sheet>
    </>
  );
}
