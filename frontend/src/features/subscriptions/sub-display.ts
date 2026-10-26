// What a subscription card shows of the provider's meta. Pure, so it is tested
// without rendering.
import type { SubErrorKind, SubWarning, TrafficInfo } from "../../generated/bindings";
import type { DictKey } from "../../i18n/types";
import type { Subscription } from "../../lib/bridge";
import { hostOf } from "../../lib/groups";

/** Happ reminds about an expiring subscription this long before the date. */
export const EXPIRE_SOON_MS = 3 * 24 * 60 * 60 * 1000;

export type ExpiryState = "none" | "ok" | "soon" | "expired";

export function displayTitle(s: Subscription): string {
  return s.remarks.trim() || s.provider?.title || hostOf(s.url);
}

/** Used and total bytes; `ratio` is null for an unmetered plan (total 0). */
export function trafficUsage(t: TrafficInfo): {
  used: number;
  total: number;
  ratio: number | null;
} {
  const used = t.upload + t.download;
  return { used, total: t.total, ratio: t.total > 0 ? Math.min(used / t.total, 1) : null };
}

export function expiryState(expireSecs: number | null | undefined, nowMs: number): ExpiryState {
  if (!expireSecs) return "none";
  const left = expireSecs * 1000 - nowMs;
  if (left <= 0) return "expired";
  return left <= EXPIRE_SOON_MS ? "soon" : "ok";
}

/** Whole days left, rounded up, for "expires in N days". */
export function daysLeft(expireSecs: number, nowMs: number): number {
  return Math.max(1, Math.ceil((expireSecs * 1000 - nowMs) / 86_400_000));
}

/** The schedule a subscription runs on: the provider's hours or the user's minutes. */
export function intervalLabel(
  s: Subscription,
): { kind: "provider"; hours: number } | { kind: "own"; minutes: number } {
  return s.providerIntervalHours != null && !s.intervalOverride
    ? { kind: "provider", hours: s.providerIntervalHours }
    : { kind: "own", minutes: s.interval };
}

export function errorKey(kind: SubErrorKind): DictKey {
  switch (kind.kind) {
    case "network":
      return "subs.error.network";
    case "http":
      return "subs.error.http";
    case "decrypt":
      return "subs.error.decrypt";
    case "urlDecrypt":
      return "subs.error.urlDecrypt";
    case "emptyBody":
      return "subs.error.empty";
    case "unknownContent":
      if (kind.hint === "yaml") return "subs.error.yaml";
      if (kind.hint === "html") return "subs.error.html";
      return "subs.error.unknown";
    case "unsupportedPayload":
      return "subs.error.jsonConsent";
    case "noProfiles":
      return "subs.error.noProfiles";
    case "limit":
      return "subs.error.limit";
    case "invalid":
      return "subs.error.invalid";
    case "incompatibleProviderConfig":
      return "subs.error.incompatibleConfig";
  }
}

/** Variables for the message `errorKey` picks; `detail` is the raw cause. */
export function errorVars(kind: SubErrorKind, detail: string): Record<string, string | number> {
  switch (kind.kind) {
    case "http":
      return { status: kind.status };
    case "decrypt":
      return { key: kind.keyId ? ` (${kind.keyId})` : "" };
    case "network":
      return { detail };
    case "incompatibleProviderConfig":
      return { detail: kind.detail };
    default:
      return {};
  }
}

export function warningKey(w: SubWarning): DictKey {
  switch (w.kind) {
    case "skippedLines":
      return "subs.warnings.skippedLines";
    case "unsupportedLinks":
      return "subs.warnings.unsupportedLinks";
    case "invalidRouting":
      return "subs.warnings.invalidRouting";
    case "invalidFragment":
      return "subs.warnings.invalidFragment";
    case "legacyParser":
      return "subs.warnings.legacyParser";
    case "usedFallback":
      return "subs.warnings.usedFallback";
    case "rejectedConfigs":
      return "subs.warnings.rejectedConfigs";
    case "skippedOutbounds":
      return "subs.warnings.skippedOutbounds";
    case "unavailableProtocols":
      return "subs.warnings.unavailableProtocols";
    case "providerSettingsOmitted":
      return "subs.warnings.providerSettingsOmitted";
  }
}
