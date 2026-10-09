// ============================================================
// src/lib/add-input.ts
// Sorting pasted or scanned text into subscriptions and profile links.
// ============================================================

import type { Subscription } from "./bridge";
import { hostOf } from "./groups";
import { uid } from "./utils";

export type SubDefaults = { autoUpdate: boolean; interval: number };

/** What a paste holds: subscriptions to add, and the rest of the text for the
 *  backend's share-link parser. */
export type AddInput = { subs: Subscription[]; profileText: string };

/** A new subscription from a URL, or from an exported dump's fields. */
export function makeSubscription(
  p: Partial<Subscription> & { url: string },
  defaults: SubDefaults,
): Subscription {
  return {
    id: uid(),
    remarks: p.remarks?.trim() || hostOf(p.url),
    url: p.url.trim(),
    enabled: p.enabled ?? true,
    groupId: p.groupId ?? null,
    autoUpdate: p.autoUpdate ?? defaults.autoUpdate,
    interval: p.interval ?? defaults.interval,
    allowInsecure: p.allowInsecure ?? false,
    userAgent: p.userAgent ?? "",
    filter: p.filter ?? "",
    updateMode: p.updateMode ?? "auto",
    lastUpdated: "",
    count: 0,
    lastError: null,
  };
}

/** A plain `http(s)://` URL is a subscription. With a user part
 *  (`http://user:pass@host:port`) it's an HTTP proxy link, which the backend's
 *  share-link parser reads the same way. */
function isSubscriptionUrl(token: string): boolean {
  if (!/^https?:\/\//i.test(token)) return false;
  try {
    const u = new URL(token);
    return !u.username && !u.password;
  } catch {
    return false;
  }
}

/** The subscriptions in an exported dump (a JSON object or array with `url`s),
 *  or null when the text isn't one. */
function parseSubscriptionDump(text: string, defaults: SubDefaults): Subscription[] | null {
  if (!text.startsWith("[") && !text.startsWith("{")) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const items = Array.isArray(parsed) ? parsed : [parsed];
  const subs = items
    .filter(
      (x): x is Partial<Subscription> & { url: string } =>
        !!x &&
        typeof (x as { url?: unknown }).url === "string" &&
        (x as { url: string }).url.trim() !== "",
    )
    .map((x) => makeSubscription(x, defaults));
  return subs.length ? subs : null;
}

/** Split a paste into subscriptions and profile text. Subscription URLs are
 *  taken token by token, so a list of them works whatever separates them;
 *  everything else (share links, a base64 subscription body) stays as text. */
export function classifyAddInput(text: string, defaults: SubDefaults): AddInput {
  const trimmed = text.trim();
  if (!trimmed) return { subs: [], profileText: "" };
  const dump = parseSubscriptionDump(trimmed, defaults);
  if (dump) return { subs: dump, profileText: "" };

  const subs: Subscription[] = [];
  const rest: string[] = [];
  for (const line of trimmed.split(/\r?\n/)) {
    // Share links can carry spaces in their #name, so only a line made of
    // nothing but subscription URLs is taken apart.
    const tokens = line.trim().split(/\s+/).filter(Boolean);
    if (tokens.length && tokens.every(isSubscriptionUrl)) {
      for (const url of tokens) subs.push(makeSubscription({ url }, defaults));
    } else if (line.trim()) {
      rest.push(line);
    }
  }
  return { subs, profileText: rest.join("\n") };
}
