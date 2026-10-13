// ============================================================
// src/lib/add-input.ts
// Turning pasted or scanned text into subscriptions, routing profiles and profile
// links. The backend sorts the text (`resolveImportInput`); an exported dump is
// read here.
// ============================================================

import type { DictKey } from "../i18n";
import type { Bridge, ResolvedImport, Subscription } from "./bridge";
import { hostOf } from "./groups";
import { uid } from "./utils";

export type SubDefaults = { autoUpdate: boolean; interval: number };

type UnsupportedKind = ResolvedImport["unsupported"][number]["kind"];

/** Why each kind of `happ://` link is skipped. */
export const UNSUPPORTED_TEXT: Record<UnsupportedKind, DictKey> = {
  control: "add.unsupported.control",
  sendToDevice: "add.unsupported.sendToDevice",
  routingOff: "add.unsupported.routingOff",
  urlDecrypt: "add.unsupported.urlDecrypt",
  invalid: "add.unsupported.invalid",
  unavailableProtocol: "add.unsupported.unavailableProtocol",
};

/** What a paste holds: subscriptions to add, the rest of the text for the backend's
 *  share-link parser, routing profiles and the links Kasumi can't use. */
export type AddInput = {
  subs: Subscription[];
  profileText: string;
  routing: ResolvedImport["routing"];
  unsupported: ResolvedImport["unsupported"];
};

export const EMPTY_ADD_INPUT: AddInput = {
  subs: [],
  profileText: "",
  routing: [],
  unsupported: [],
};

/** A new subscription from a URL, or from an exported dump's fields. */
export function makeSubscription(
  p: Partial<Subscription> & { url: string },
  defaults: SubDefaults,
): Subscription {
  const remarks = p.remarks?.trim() ?? "";
  return {
    id: uid(),
    remarks: remarks || hostOf(p.url),
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
    // A dump from an older build has no flag: a name other than the host was typed.
    manualTitle: p.manualTitle ?? (remarks !== "" && remarks !== hostOf(p.url)),
    intervalOverride: p.intervalOverride ?? false,
    bodyEncrypted: false,
    warnings: [],
    insecureByProvider: false,
    allowProviderConfigs: false,
  };
}

/** The subscriptions in an exported dump (a JSON object or array with `url`s),
 *  or null when the text isn't one. */
export function parseSubscriptionDump(text: string, defaults: SubDefaults): Subscription[] | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("[") && !trimmed.startsWith("{")) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
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

/** What the add sheet adds from the backend's sorting of a paste. An encrypted
 *  link is named `encryptedName` until the provider sends a title. */
export function addInputFrom(
  resolved: ResolvedImport,
  defaults: SubDefaults,
  encryptedName: string,
): AddInput {
  return {
    subs: resolved.subscriptions.map(({ url, encrypted }) =>
      makeSubscription(
        encrypted ? { url, remarks: encryptedName, manualTitle: false } : { url },
        defaults,
      ),
    ),
    profileText: resolved.shareText,
    routing: resolved.routing,
    unsupported: resolved.unsupported,
  };
}

/** The backend's sorting of pasted or scanned text, and how many profile links the
 *  rest holds. When the backend can't answer, all of it is left as share-link text. */
export async function resolveAddText(
  text: string,
  b: Pick<Bridge, "resolveImportInput" | "parseShareLinks">,
): Promise<{ value: ResolvedImport; profileCount: number }> {
  try {
    const value = await b.resolveImportInput(text);
    const profileCount = value.shareText.trim()
      ? (await b.parseShareLinks(value.shareText)).length
      : 0;
    return { value, profileCount };
  } catch {
    return {
      value: { subscriptions: [], routing: [], unsupported: [], shareText: text },
      profileCount: 0,
    };
  }
}

/** The subscription URL "with options" should open with: the first one the text
 *  holds, read the way the sheet reads it (an exported dump here, anything else by
 *  the backend), or null when the text carries no subscription. Asked afresh so a
 *  paste still being sorted isn't dropped. */
export async function firstSubscriptionUrl(
  text: string,
  defaults: SubDefaults,
  b: Pick<Bridge, "resolveImportInput" | "parseShareLinks">,
): Promise<string | null> {
  if (!text.trim()) return null;
  const dump = parseSubscriptionDump(text, defaults);
  if (dump) return dump[0]?.url ?? null;
  const { value } = await resolveAddText(text, b);
  return value.subscriptions[0]?.url ?? null;
}

/** A scanned QR code goes on a line of its own after what the field holds. */
export function appendScanned(current: string, scanned: string): string {
  return current.trim() ? `${current.trim()}\n${scanned}` : scanned;
}

/** The add sheet opens on the clipboard's text unless something is already typed. */
export function withClipboard(current: string, clip: string | null): string {
  const v = clip?.trim();
  return v && !current.trim() ? v : current;
}

/** What a typed subscription URL is: a link to store (`happ://add/` unwrapped, an
 *  encrypted one kept), a `happ://` link that is no subscription, or anything else,
 *  saved as typed. */
export type SubscriptionUrlCheck =
  | { kind: "url"; url: string; encrypted: boolean }
  | { kind: "routing" }
  | { kind: "unsupported"; reason: UnsupportedKind }
  | { kind: "other" };

export async function checkSubscriptionUrl(
  url: string,
  b: Pick<Bridge, "resolveImportInput">,
): Promise<SubscriptionUrlCheck> {
  let r: ResolvedImport;
  try {
    r = await b.resolveImportInput(url);
  } catch {
    return { kind: "other" };
  }
  if (r.unsupported.length) return { kind: "unsupported", reason: r.unsupported[0].kind };
  if (r.routing.length) return { kind: "routing" };
  if (r.subscriptions.length === 1 && !r.shareText.trim())
    return { kind: "url", ...r.subscriptions[0] };
  return { kind: "other" };
}

/** The name a subscription gets from its address when none is typed: the host it
 *  fetches from, or the encrypted-link name. A `happ://` link that isn't read yet,
 *  or isn't a subscription, gives none: its scheme words (`add`, `routing`) are no
 *  name. */
export function subscriptionNameFrom(
  url: string,
  check: SubscriptionUrlCheck | null,
  encryptedName: string,
): string {
  if (check?.kind === "url") return check.encrypted ? encryptedName : hostOf(check.url);
  if (check?.kind === "routing" || check?.kind === "unsupported") return "";
  return isHappLink(url) ? "" : hostOf(url);
}

export const isHappLink = (text: string) => /^\s*happ:\/\//i.test(text);

/** Links pasted where JSON is expected: routing profiles alone, a `happ://` link
 *  Kasumi skips, or anything else the add sheet takes. */
export type LinkInput =
  | { kind: "routing"; links: ResolvedImport["routing"] }
  | { kind: "unsupported"; reason: UnsupportedKind }
  | { kind: "add" };

/** What resolved text amounts to as links, or `null` when it holds none. */
export function linkInput({
  value,
  profileCount,
}: {
  value: ResolvedImport;
  profileCount: number;
}): LinkInput | null {
  const others = value.subscriptions.length > 0 || profileCount > 0;
  if (value.routing.length && !others && !value.unsupported.length)
    return { kind: "routing", links: value.routing };
  if (value.unsupported.length && !others && !value.routing.length)
    return { kind: "unsupported", reason: value.unsupported[0].kind };
  return others || value.routing.length || value.unsupported.length ? { kind: "add" } : null;
}

/** JSON is read as JSON: it never goes to the link parser. */
export const looksLikeJson = (text: string) => /^\s*[[{]/.test(text);

/** `text` read as links by the backend, or `null` for JSON and text with none. */
export async function resolveLinkInput(
  text: string,
  b: Pick<Bridge, "resolveImportInput" | "parseShareLinks">,
): Promise<LinkInput | null> {
  if (!text.trim() || looksLikeJson(text)) return null;
  return linkInput(await resolveAddText(text.trim(), b));
}

/** Why a JSON import can't take these links. */
export function linkInputText(link: LinkInput): DictKey {
  return link.kind === "unsupported" ? UNSUPPORTED_TEXT[link.reason] : "add.linkUseAdd";
}
