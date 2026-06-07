export const uid = () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);

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
