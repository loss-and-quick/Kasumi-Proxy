export { uid } from "./profile-utils";

export function toText(value?: string[]): string {
  return value?.join("\n") ?? "";
}

export function normalizeList(value: string): string[] | undefined {
  const parts = value
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.length ? parts : undefined;
}

/** Format a minute count as an HH:MM clock string for `<input type="time">`. */
export function minutesToClock(total: number): string {
  const safe = Math.max(0, Math.floor(total) || 0);
  const h = Math.floor(safe / 60);
  const m = safe % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

/** Parse an HH:MM clock string back into a minute count (0 on malformed input). */
export function clockToMinutes(clock: string): number {
  const m = clock.match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return 0;
  return Number(m[1]) * 60 + Number(m[2]);
}
