import { toDataURL } from "qrcode";
import { useEffect, useState } from "react";
import { useT } from "../i18n";
import { Btn } from "./buttons";
import { Sheet } from "./overlays";

type Props = {
  open: boolean;
  title?: string;
  text: string;
  onClose: () => void;
};

async function copyText(text: string) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function QrCodeSheet({ open, title, text, onClose }: Props) {
  const t = useT();
  const [dataUrl, setDataUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) {
      setDataUrl(null);
      setError(null);
      setBusy(false);
      return;
    }

    let cancelled = false;
    setBusy(true);
    setError(null);
    setDataUrl(null);

    void toDataURL(text, {
      errorCorrectionLevel: "L",
      margin: 2,
      width: 320,
    })
      .then((nextUrl) => {
        if (!cancelled) setDataUrl(nextUrl);
      })
      .catch(() => {
        if (!cancelled) setError(t("qr.show.tooLarge"));
      })
      .finally(() => {
        if (!cancelled) setBusy(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, text, t]);

  return (
    <Sheet open={open} title={title ?? t("qr.show.title")} onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div
          style={{
            borderRadius: 18,
            border: "1px solid oklch(1 0 0 / 0.06)",
            background: "var(--sc-lowest)",
            padding: 16,
            minHeight: 260,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          {dataUrl ? (
            <img
              src={dataUrl}
              alt={t("qr.show.title")}
              style={{ width: "100%", maxWidth: 320, display: "block" }}
            />
          ) : (
            <div
              style={{
                fontSize: 12.5,
                color: error ? "var(--error)" : "var(--on-surface-variant)",
                lineHeight: 1.5,
                textAlign: "center",
              }}
            >
              {error ?? (busy ? t("qr.show.generating") : t("qr.show.title"))}
            </div>
          )}
        </div>

        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11.5,
            color: "var(--on-surface-faint)",
            background: "var(--sc-low)",
            padding: 10,
            borderRadius: 12,
            wordBreak: "break-all",
            maxHeight: 120,
            overflow: "auto",
          }}
        >
          {text}
        </div>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <Btn
            variant="outline"
            icon="content_copy"
            onClick={async () => {
              await copyText(text);
            }}
          >
            {t("qr.show.copy")}
          </Btn>
          <Btn variant="text" onClick={onClose}>
            {t("qr.scan.close")}
          </Btn>
        </div>
      </div>
    </Sheet>
  );
}
