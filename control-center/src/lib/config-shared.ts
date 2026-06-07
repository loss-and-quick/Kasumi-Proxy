// ============================================================
// src/lib/config-shared.ts
// String helpers shared by the xray-config and singbox-config
// generators, so the two cores parse user-entered lists the same way.
// ============================================================

/** Split a comma-separated string into trimmed, non-empty parts, or undefined. */
export const splitCsv = (s: string): string[] | undefined => {
  const parts = (s || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  return parts.length ? parts : undefined;
};

/** Split on commas or newlines into trimmed, non-empty parts, or a fallback. */
export const splitList = (v: string | undefined, fallback: string[]): string[] => {
  const parts = (v || "")
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);
  return parts.length ? parts : fallback;
};

export function parseWsEarlyData(path: string | undefined): {
  path: string;
  wsEarlyData: number;
  wsEarlyDataHeader: string;
} {
  let nextPath = path || "";
  let wsEarlyData = 0;
  let wsEarlyDataHeader = "";

  const edMatch = nextPath.match(/[?&]ed=(\d+)/);
  if (edMatch) {
    wsEarlyData = Number(edMatch[1]) || 0;
    wsEarlyDataHeader = "Sec-WebSocket-Protocol";
    nextPath = nextPath.replace(/[?&]ed=\d+/, "");
  }

  const ehMatch = nextPath.match(/[?&]eh=([^&]+)/);
  if (ehMatch) {
    wsEarlyDataHeader = decodeURIComponent(ehMatch[1]);
    nextPath = nextPath.replace(/[?&]eh=[^&]+/, "");
  }

  nextPath = nextPath.replace("?&", "?").replace("&&", "&");
  if (nextPath.endsWith("?") || nextPath.endsWith("&")) nextPath = nextPath.slice(0, -1);

  return { path: nextPath, wsEarlyData, wsEarlyDataHeader };
}

export function buildWsPath(
  path: string | undefined,
  wsEarlyData?: number,
  wsEarlyDataHeader?: string,
): string {
  const base = path || "/";
  const params = new URLSearchParams();
  if ((wsEarlyData || 0) > 0) params.set("ed", String(wsEarlyData));
  if (wsEarlyDataHeader) params.set("eh", wsEarlyDataHeader);
  const qs = params.toString();
  return qs ? `${base}${base.includes("?") ? "&" : "?"}${qs}` : base;
}

export function parsePemChain(pem: string | undefined): string[] | undefined {
  if (!pem?.trim()) return undefined;
  const matches = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  const certs = (matches ?? [pem]).map((value) => value.trim()).filter(Boolean);
  return certs.length ? certs : undefined;
}
