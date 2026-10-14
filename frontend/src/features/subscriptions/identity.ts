// Pure helpers for the request-identity UI. The request itself is built in Rust
// (happ-sub); these only decide what the screens show about it.
import type { DictKey } from "../../i18n";
import type { HwidSource, ResolvedIdentity } from "../../lib/bridge";

export const HWID_SOURCE_KEY: Record<HwidSource, DictKey> = {
  subscription: "subs.identity.hwidSource.subscription",
  settings: "subs.identity.hwidSource.settings",
  happStored: "subs.identity.hwidSource.happStored",
  happComputed: "subs.identity.hwidSource.happComputed",
  machineId: "subs.identity.hwidSource.machineId",
  deviceId: "subs.identity.hwidSource.deviceId",
  incyDerived: "subs.identity.hwidSource.incyDerived",
  incySeed: "subs.identity.hwidSource.incySeed",
};

/** A typed value, or `undefined` when the field was left blank (inherit). */
export function typed(v: string): string | undefined {
  return v.trim() ? v : undefined;
}

/** A HWID was typed for `expected` but the backend did not take it: it isn't valid. */
export function hwidRejected(
  value: string | null | undefined,
  expected: HwidSource,
  view: ResolvedIdentity | null,
): boolean {
  return !!value?.trim() && !!view && view.hwidSource !== expected;
}

/** What the provider asked for, in the order the screen lists it. */
export function providerAsks(view: ResolvedIdentity | null): DictKey[] {
  if (!view) return [];
  const out: DictKey[] = [];
  if (view.locks.userAgent) out.push("subs.identity.providerUa");
  if (view.locks.sendHwid) out.push("subs.identity.providerAlwaysHwid");
  else if (view.providerHidesDevice) out.push("subs.identity.providerNoDevice");
  if (view.locks.hwidInCookie)
    out.push(
      view.providerHwidCookie ? "subs.identity.providerCookie" : "subs.identity.providerHeader",
    );
  return out;
}
