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

function isPrivateIpv4(host: string): boolean {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  if (a === 0 || a === 10 || a === 127) return true; // this-host, private, loopback
  if (a === 192 && b === 168) return true; // private
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 169 && b === 254) return true; // link-local
  return false;
}

/**
 * True when a URL points at localhost or a private/link-local address — where a
 * self-signed cert is normal and skipping TLS verification is acceptable, and an
 * "unencrypted HTTP" warning would just be noise.
 */
export function isLocalOrPrivateHost(url: string): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  if (!hostname) return false;
  // URL keeps IPv6 literals bracketed, so this also disambiguates them from domains.
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    const ip = hostname.slice(1, -1);
    return ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80");
  }
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local"))
    return true;
  return isPrivateIpv4(hostname);
}

/** True when the URL uses plain, unencrypted HTTP. */
export function isInsecureHttpUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "http:";
  } catch {
    return false;
  }
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
