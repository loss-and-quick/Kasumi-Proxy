import type { Update } from "@tauri-apps/plugin-updater";
import { useCallback, useEffect, useState } from "react";
import { Btn, Card, Icon, ListRow, SectionLabel } from "../../../components";
import { useT } from "../../../i18n";
import {
  checkForUpdate,
  currentVersion,
  getUpdatePolicy,
  installUpdate,
  type UpdatePolicy,
  updateSupported,
} from "../../../lib/updater";

export type UpdateStatus =
  | "idle"
  | "checking"
  | "uptodate"
  | "available"
  | "downloading"
  | "error"
  // The download or the install failed; the update can be tried again.
  | "installError";

export function AboutCard({
  version,
  policy,
  status,
  availableVersion,
  percent,
  onCheck,
  onInstall,
}: {
  version: string;
  policy: UpdatePolicy | null;
  status: UpdateStatus;
  availableVersion: string | null;
  percent: number;
  onCheck: () => void;
  onInstall: () => void;
}) {
  const t = useT();
  const busy = status === "checking" || status === "downloading";
  const canInstall =
    availableVersion !== null && (status === "available" || status === "installError");
  const statusText =
    status === "checking"
      ? t("settings.updateChecking")
      : status === "uptodate"
        ? t("settings.updateUpToDate")
        : status === "available"
          ? t("settings.updateAvailable", { version: availableVersion ?? "" })
          : status === "downloading"
            ? t("settings.updateDownloading", { percent })
            : status === "error"
              ? t("settings.updateError")
              : status === "installError"
                ? t("settings.updateInstallError")
                : undefined;

  const passiveReason =
    policy === "externallyManaged"
      ? t("settings.updateManagedExternally")
      : policy === "portable"
        ? t("settings.updatePortable")
        : null;

  return (
    <>
      <SectionLabel>
        {policy === "selfUpdate" ? t("settings.updates") : t("settings.page.about")}
      </SectionLabel>
      <Card style={{ padding: "4px 14px" }}>
        <ListRow icon="info" title={t("settings.appVersion")} sub={version || "—"} />
        {policy === "selfUpdate" && (
          <ListRow
            icon="system_update"
            title={t("settings.checkUpdates")}
            sub={statusText}
            onClick={busy || canInstall ? undefined : onCheck}
            right={
              canInstall ? (
                <Btn sm onClick={onInstall}>
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
        )}
        {passiveReason && (
          <ListRow icon="system_update" title={t("settings.updates")} sub={passiveReason} />
        )}
      </Card>
    </>
  );
}

/** Desktop-only version + auto-update controls. Android is updated by the root
 * manager, so this renders nothing outside the desktop shell. Externally managed
 * packages and portable zips show their version without an active updater action. */
export function AboutSection() {
  const [version, setVersion] = useState("");
  const [policy, setPolicy] = useState<UpdatePolicy | null>(null);
  const [update, setUpdate] = useState<Update | null>(null);
  const [status, setStatus] = useState<UpdateStatus>("idle");
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
    let alive = true;
    void currentVersion().then(
      (v) => {
        if (alive && v) setVersion(v);
      },
      () => {
        // Leave the version blank if the desktop shell call fails.
      },
    );
    void getUpdatePolicy().then(
      (p) => {
        if (!alive) return;
        setPolicy(p);
        if (p === "selfUpdate") {
          void runCheck();
        }
      },
      () => {
        // Policy stays unknown; update actions remain hidden.
      },
    );
    return () => {
      alive = false;
    };
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
      setStatus("installError");
    }
  }

  return (
    <AboutCard
      version={version}
      policy={policy}
      status={status}
      availableVersion={update?.version ?? null}
      percent={percent}
      onCheck={() => void runCheck()}
      onInstall={() => void doInstall()}
    />
  );
}
