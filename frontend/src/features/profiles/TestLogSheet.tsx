// ============================================================
// features/profiles/TestLogSheet.tsx
// Reason behind a profile's real-ping / speed-test `err`: the retained
// test-core log. Adapted from features/logs/Logs.tsx for one profile.
// ============================================================
import { useCallback, useEffect, useState } from "react";
import { Btn, Sheet } from "../../components";
import type { Profile, TestKind } from "../../generated/bindings";
import { useT } from "../../i18n";
import { bridge } from "../../lib/bridge-provider";
import { useAppStore } from "../../store/useAppStore";
import { copyText } from "./clipboard";

export function TestLogSheet({
  profile,
  kind,
  onClose,
}: {
  profile: Profile;
  kind: TestKind;
  onClose: () => void;
}) {
  const notify = useAppStore((s) => s.notify);
  const testProfile = useAppStore((s) => s.testProfile);
  const busy = useAppStore(
    (s) => s.pinging.has(profile.meta.id) || s.speedTesting.has(profile.meta.id),
  );
  const t = useT();
  const [text, setText] = useState(t("app.loading"));
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setText(await bridge.testLog(profile.meta.id, kind));
    } catch (e: unknown) {
      setText(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [profile.meta.id, kind]);

  useEffect(() => {
    void load();
  }, [load]);

  const rerun = useCallback(async () => {
    await testProfile(profile.meta.id, kind);
    await load();
  }, [kind, profile.meta.id, testProfile, load]);

  const title = `${t(kind === "speed" ? "testlog.titleSpeed" : "testlog.titlePing")}: ${profile.meta.remarks}`;
  const empty = !loading && text.trim().length === 0;

  return (
    <Sheet open title={title} onClose={onClose}>
      <div style={{ display: "flex", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <Btn variant="tonal" icon="replay" onClick={() => void rerun()} disabled={busy || loading}>
          {busy ? t("logs.refreshing") : t("testlog.rerun")}
        </Btn>
        <Btn
          variant="outline"
          onClick={async () =>
            notify((await copyText(text)) ? t("logs.copied") : t("logs.copyFailed"))
          }
          disabled={empty}
        >
          {t("logs.copy")}
        </Btn>
      </div>
      {empty ? (
        <div
          style={{
            padding: "40px 16px",
            textAlign: "center",
            color: "var(--on-surface-variant)",
            fontSize: 13.5,
          }}
        >
          {t("testlog.empty")}
        </div>
      ) : (
        <textarea
          className="input mono"
          readOnly
          value={text}
          style={{ minHeight: 360, whiteSpace: "pre", fontSize: 11.5 }}
        />
      )}
    </Sheet>
  );
}
