import type { I18nFormatters } from "../i18n/runtime";

/** A byte count in binary steps, with the number and unit in the reader's locale. */
export function formatBytes(bytes: number, formatNumber: I18nFormatters["formatNumber"]): string {
  const kb = bytes > 0 ? bytes / 1024 : 0;
  const mb = kb / 1024;
  const unit = (value: number, name: string, digits: number) =>
    formatNumber(value, {
      style: "unit",
      unit: name,
      unitDisplay: "short",
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    });
  if (mb >= 1024) return unit(mb / 1024, "gigabyte", 2);
  if (mb >= 1 || kb === 0) return unit(mb, "megabyte", 1);
  return unit(kb, "kilobyte", 1);
}

export function formatRate(bytesPerSec: number): string {
  if (!bytesPerSec || bytesPerSec < 0) return "0 B/s";
  if (bytesPerSec < 1024) return `${Math.round(bytesPerSec)} B/s`;

  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB/s`;

  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB/s`;

  return `${(mb / 1024).toFixed(2)} GB/s`;
}

export function formatUptime(sec: number): string {
  if (!sec || sec < 0) return "—";
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

export function timeAgo(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return d.toISOString().slice(0, 10);
}
