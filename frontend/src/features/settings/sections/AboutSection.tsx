import type { Update } from "@tauri-apps/plugin-updater";
import { useCallback, useEffect, useState } from "react";
import { Btn, Card, Icon, ListRow, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import {
  checkForUpdate,
  currentVersion,
  installUpdate,
  updateSupported,
} from "../../../lib/updater";

type Status = "idle" | "checking" | "uptodate" | "available" | "downloading" | "error";

/** Desktop-only version + auto-update controls. Android is updated by the root
 * manager, so this renders nothing where the updater isn't supported. */
export function AboutSection() {
  const t = useT();
  const [version, setVersion] = useState("");
  const [update, setUpdate] = useState<Update | null>(null);
  const [status, setStatus] = useState<Status>("idle");
  const [percent, setPercent] = useState(0);

  const runCheck = useCallback(async () => {
    setStatus("checking");
    try {
      const u = await checkForUpdate();
      setUpdate(u);
      setStatus(u ? "available" : "uptodate");
    } catch {
      setStatus("error");
    }
  }, []);

  useEffect(() => {
    if (!updateSupported()) return;
    void currentVersion().then((v) => {
      if (v) setVersion(v);
    });
    void runCheck();
  }, [runCheck]);

  if (!updateSupported()) return null;

  async function doInstall() {
    if (!update) return;
    setStatus("downloading");
    setPercent(0);
    try {
      // On success the app relaunches into the new version — nothing runs after.
      await installUpdate(update, ({ downloaded, total }) => {
        setPercent(total ? Math.round((downloaded / total) * 100) : 0);
      });
    } catch {
      setStatus("error");
    }
  }

  const busy = status === "checking" || status === "downloading";
  const statusText =
    status === "checking"
      ? t("settings.updateChecking")
      : status === "uptodate"
        ? t("settings.updateUpToDate")
        : status === "available"
          ? t("settings.updateAvailable", { version: update?.version ?? "" })
          : status === "downloading"
            ? t("settings.updateDownloading", { percent })
            : status === "error"
              ? t("settings.updateError")
              : undefined;

  return (
    <>
      <SectionLabel>{t("settings.updates")}</SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <ListRow icon="info" title={t("settings.appVersion")} sub={version || "—"} />
        <ListRow
          icon="system_update"
          title={t("settings.checkUpdates")}
          sub={statusText}
          onClick={busy || status === "available" ? undefined : () => void runCheck()}
          right={
            status === "available" ? (
              <Btn sm onClick={() => void doInstall()}>
                {t("settings.updateInstall")}
              </Btn>
            ) : (
              <Icon
                name="refresh"
                style={{ color: "var(--on-surface-faint)", opacity: busy ? 0.4 : 1 }}
              />
            )
          }
        />
      </Card>
    </>
  );
}
