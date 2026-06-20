// ============================================================
// features/logs/Logs.tsx
// Runtime log viewer with copy / refresh.
// ============================================================
import { useCallback, useEffect, useState } from "react";
import { Btn, Dialog, Sheet } from "../../components";
import { useT } from "../../i18n";
import type { LogTarget } from "../../lib/bridge";
import { bridge } from "../../lib/bridge-provider";
import { useAppStore } from "../../store/useAppStore";

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export default function Logs({ onClose }: { onClose: () => void }) {
  const notify = useAppStore((s) => s.notify);
  const t = useT();
  const [target, setTarget] = useState<LogTarget>("daemon");
  const [lines, setLines] = useState(300);
  const [text, setText] = useState(t("app.loading"));
  const [loading, setLoading] = useState(false);
  const [clearOpen, setClearOpen] = useState(false);
  const [clearing, setClearing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setText(await bridge.log({ target, lines }));
    } catch (e: unknown) {
      setText(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [lines, target]);

  const clearLogs = useCallback(async () => {
    setClearing(true);
    try {
      const result = await bridge.clearLogs();
      if (!result.ok) {
        throw new Error(result.error || t("logs.clearFailed"));
      }
      setClearOpen(false);
      notify(t("logs.cleared"));
      await load();
    } catch (e: unknown) {
      notify(e instanceof Error ? e.message : t("logs.clearFailed"));
    } finally {
      setClearing(false);
    }
  }, [load, notify, t]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <>
      <Sheet open title={t("logs.title")} onClose={onClose}>
        <div
          style={{
            display: "flex",
            gap: 10,
            alignItems: "end",
            marginBottom: 12,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div className="field-label">{t("logs.target")}</div>
            <select
              className="select-box"
              value={target}
              onChange={(e) => setTarget(e.target.value as LogTarget)}
            >
              <option value="daemon">{t("logs.target.daemon")}</option>
              <option value="xray">{t("logs.target.xray")}</option>
              <option value="singbox">{t("logs.target.singbox")}</option>
              <option value="tun2socks">{t("logs.target.tun2socks")}</option>
            </select>
          </div>
          <div>
            <div className="field-label">{t("logs.lines")}</div>
            <input
              className="input"
              type="number"
              value={lines}
              onChange={(e) => setLines(Number(e.target.value || 300))}
              style={{ width: 100 }}
            />
          </div>
          <Btn variant="tonal" onClick={() => void load()} disabled={loading || clearing}>
            {loading ? t("logs.refreshing") : t("logs.refresh")}
          </Btn>
          <Btn
            variant="outline"
            onClick={async () =>
              notify((await copyText(text)) ? t("logs.copied") : t("logs.copyFailed"))
            }
            disabled={clearing}
          >
            {t("logs.copy")}
          </Btn>
          <Btn variant="error" icon="delete" onClick={() => setClearOpen(true)} disabled={clearing}>
            {t("logs.clear")}
          </Btn>
        </div>
        <textarea
          className="input mono"
          readOnly
          value={text}
          style={{ minHeight: 420, whiteSpace: "pre", fontSize: 11.5 }}
        />
      </Sheet>
      <Dialog
        open={clearOpen}
        icon="delete"
        iconColor={{ bg: "var(--error-container)", fg: "oklch(0.92 0.04 25)" }}
        title={t("logs.clear")}
        onClose={() => !clearing && setClearOpen(false)}
        actions={
          <>
            <Btn variant="text" onClick={() => setClearOpen(false)} disabled={clearing}>
              {t("profiles.confirmDel.cancel")}
            </Btn>
            <Btn variant="error" onClick={() => void clearLogs()} disabled={clearing}>
              {t("logs.clear")}
            </Btn>
          </>
        }
      >
        {t("logs.clearConfirm")}
      </Dialog>
    </>
  );
}
