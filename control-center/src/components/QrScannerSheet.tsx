import jsQR from "jsqr";
import { useCallback, useEffect, useRef, useState } from "react";
import { useT } from "../i18n";
import { Btn } from "./buttons";
import { Icon } from "./icons";
import { Sheet } from "./overlays";

type Props = {
  open: boolean;
  title?: string;
  onClose: () => void;
  onResult: (text: string) => boolean | undefined | Promise<boolean | undefined>;
};

function qrErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof DOMException) {
    if (error.name === "NotAllowedError" || error.name === "PermissionDeniedError") return fallback;
    if (error.name === "NotFoundError" || error.name === "DevicesNotFoundError") return fallback;
    if (error.name === "NotReadableError" || error.name === "TrackStartError") return fallback;
  }
  return fallback;
}

function loadImage(file: File): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve(img);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error("image-load-failed"));
    };
    img.src = url;
  });
}

function fitInside(width: number, height: number, maxDimension: number) {
  const ratio = Math.min(1, maxDimension / Math.max(width, height));
  return {
    width: Math.max(1, Math.round(width * ratio)),
    height: Math.max(1, Math.round(height * ratio)),
  };
}

export function QrScannerSheet({ open, title, onClose, onResult }: Props) {
  const t = useT();
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const frameRef = useRef<number | null>(null);
  const handlingResultRef = useRef(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Non-error: live camera isn't usable here (common in KernelSU WebView) — we
  // fall back to capturing/choosing a photo instead of showing a scary error.
  const [cameraNote, setCameraNote] = useState<string | null>(null);
  const [imageBusy, setImageBusy] = useState(false);

  const stopScanner = useCallback(() => {
    if (frameRef.current !== null) {
      cancelAnimationFrame(frameRef.current);
      frameRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => {
        track.stop();
      });
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.pause();
      videoRef.current.srcObject = null;
    }
  }, []);

  const decodeCanvas = useCallback((width: number, height: number): string | null => {
    const canvas = canvasRef.current ?? document.createElement("canvas");
    canvasRef.current = canvas;
    const size = fitInside(width, height, 960);
    canvas.width = size.width;
    canvas.height = size.height;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    const video = videoRef.current;
    if (!video) return null;
    ctx.drawImage(video, 0, 0, size.width, size.height);
    const frame = ctx.getImageData(0, 0, size.width, size.height);
    return (
      jsQR(frame.data, size.width, size.height, { inversionAttempts: "attemptBoth" })?.data ?? null
    );
  }, []);

  const decodeImageFile = useCallback(async (file: File): Promise<string | null> => {
    const image = await loadImage(file);
    const canvas = canvasRef.current ?? document.createElement("canvas");
    canvasRef.current = canvas;
    const size = fitInside(
      image.naturalWidth || image.width,
      image.naturalHeight || image.height,
      1600,
    );
    canvas.width = size.width;
    canvas.height = size.height;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
    const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return (
      jsQR(frame.data, canvas.width, canvas.height, { inversionAttempts: "attemptBoth" })?.data ??
      null
    );
  }, []);

  const finishScan = useCallback(
    async (text: string) => {
      if (handlingResultRef.current) return;
      handlingResultRef.current = true;
      try {
        const result = await onResult(text);
        if (result === false) {
          handlingResultRef.current = false;
          return;
        }
        stopScanner();
        handlingResultRef.current = false;
        onClose();
      } catch {
        handlingResultRef.current = false;
      }
    },
    [onClose, onResult, stopScanner],
  );

  useEffect(() => {
    if (!open) {
      setMessage("");
      setError(null);
      setCameraNote(null);
      handlingResultRef.current = false;
      stopScanner();
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia) {
      stopScanner();
      setMessage("");
      setError(null);
      setCameraNote(t("qr.scan.unsupported"));
      return;
    }

    let cancelled = false;
    setError(null);
    setCameraNote(null);
    setMessage(t("qr.scan.starting"));
    handlingResultRef.current = false;

    const scanLoop = () => {
      if (cancelled || handlingResultRef.current) return;
      const video = videoRef.current;
      if (
        video &&
        video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA &&
        video.videoWidth > 0 &&
        video.videoHeight > 0
      ) {
        const text = decodeCanvas(video.videoWidth, video.videoHeight);
        if (text) {
          void finishScan(text);
          return;
        }
      }
      frameRef.current = requestAnimationFrame(scanLoop);
    };

    void (async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: false,
          video: { facingMode: { ideal: "environment" } },
        });
        if (cancelled) {
          stream.getTracks().forEach((track) => {
            track.stop();
          });
          return;
        }
        streamRef.current = stream;
        const video = videoRef.current;
        if (!video) return;
        video.srcObject = stream;
        await video.play();
        if (cancelled) return;
        setMessage(t("qr.scan.hint"));
        frameRef.current = requestAnimationFrame(scanLoop);
      } catch (e) {
        if (!cancelled) {
          stopScanner();
          setMessage("");
          setError(null);
          setCameraNote(qrErrorMessage(e, t("qr.scan.denied")));
        }
      }
    })();

    return () => {
      cancelled = true;
      stopScanner();
    };
  }, [decodeCanvas, finishScan, open, stopScanner, t]);

  return (
    <Sheet open={open} title={title ?? t("qr.scan.title")} onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div
          style={{
            borderRadius: 18,
            overflow: "hidden",
            background: "var(--sc-low)",
            border: "1px solid oklch(1 0 0 / 0.06)",
          }}
        >
          {cameraNote ? (
            <div
              style={{
                aspectRatio: "3 / 4",
                minHeight: 220,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                gap: 12,
                padding: "20px 18px",
                textAlign: "center",
                color: "var(--on-surface-variant)",
              }}
            >
              <Icon name="image" style={{ fontSize: 40, color: "var(--on-surface-faint)" }} />
              <div style={{ fontSize: 13, lineHeight: 1.5 }}>{cameraNote}</div>
              <div style={{ fontSize: 12, color: "var(--on-surface-faint)", lineHeight: 1.5 }}>
                {t("qr.scan.fromImage")}
              </div>
            </div>
          ) : (
            <video
              ref={videoRef}
              autoPlay
              muted
              playsInline
              style={{
                width: "100%",
                display: "block",
                aspectRatio: "3 / 4",
                objectFit: "cover",
                background: "oklch(0.18 0.01 260)",
              }}
            />
          )}
        </div>

        {error ? (
          <div role="alert" style={{ fontSize: 12.5, color: "var(--error)", lineHeight: 1.5 }}>
            {error}
          </div>
        ) : message ? (
          <div
            style={{
              fontSize: 12.5,
              color: "var(--on-surface-variant)",
              lineHeight: 1.5,
            }}
          >
            {message}
          </div>
        ) : null}

        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          capture="environment"
          style={{ display: "none" }}
          onChange={(event) => {
            const file = event.target.files?.[0];
            event.currentTarget.value = "";
            if (!file) return;
            setImageBusy(true);
            setError(null);
            setMessage(t("qr.scan.imageProcessing"));
            void decodeImageFile(file)
              .then(async (text) => {
                if (!text) {
                  setMessage("");
                  setError(t("qr.scan.noCode"));
                  return;
                }
                await finishScan(text);
              })
              .catch(() => {
                setMessage("");
                setError(t("qr.scan.noCode"));
              })
              .finally(() => setImageBusy(false));
          }}
        />

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <Btn
            variant={cameraNote ? "filled" : "outline"}
            icon="image"
            disabled={imageBusy}
            onClick={() => inputRef.current?.click()}
          >
            {imageBusy ? t("qr.scan.imageProcessing") : t("qr.scan.fromImage")}
          </Btn>
          <Btn variant="text" onClick={onClose}>
            {t("qr.scan.close")}
          </Btn>
        </div>
      </div>
    </Sheet>
  );
}
