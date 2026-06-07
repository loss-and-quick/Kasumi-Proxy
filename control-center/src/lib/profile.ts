// ============================================================
// src/lib/profile.ts
// Safe accessors over the Profile discriminated union, so display
// and filtering code doesn't repeat `"field" in p` guards.
// ============================================================
import type { Profile, Security } from "./schema";

export const hasEndpoint = (p: Profile): p is Extract<Profile, { address: string }> =>
  "address" in p;
export const hasTransport = (p: Profile): p is Extract<Profile, { network: string }> =>
  "network" in p;
export const hasTls = (p: Profile): p is Extract<Profile, { security: Security }> =>
  "security" in p;

export function profileAddress(p: Profile): string {
  return hasEndpoint(p) ? p.address : "";
}
export function profilePort(p: Profile): number | null {
  return hasEndpoint(p) ? p.port : null;
}
export function profileNetwork(p: Profile): string {
  return hasTransport(p) ? p.network : p.protocol === "wireguard" ? "udp" : "—";
}
export function profileSecurity(p: Profile): Security {
  return hasTls(p) ? p.security : "none";
}

/** "host:port" for endpoints, protocol name otherwise (custom). */
export function profileEndpointLabel(p: Profile): string {
  return hasEndpoint(p) ? `${p.address}:${p.port}` : p.protocol;
}

/** Lower-cased searchable haystack for filtering. */
export function profileSearchText(p: Profile): string {
  const parts = [p.remarks, p.protocol];
  if (hasEndpoint(p)) {
    parts.push(p.address, String(p.port));
  }
  if (hasTransport(p)) {
    parts.push(p.network, p.host, p.path);
  }
  if (hasTls(p)) {
    parts.push(p.security, p.sni);
  }
  return parts.filter(Boolean).join(" ").toLowerCase();
}
