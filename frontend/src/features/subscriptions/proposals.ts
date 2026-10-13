// How the review sheet arranges a subscription's proposed changes. Pure, so it is
// tested without rendering; what each change does is decided in Rust.

import type { Route } from "../../generated/bindings";
import type { DictKey } from "../../i18n/types";
import type { ChangeAction, PendingChange, RoutingImport } from "../../lib/bridge";
import { DEFAULT_ROUTE_ID, routeEnabled, routeGroups } from "../../lib/routes";

export type ProposalGroup = "trust" | "tunnel" | "unsupported";

export const GROUP_ORDER: ProposalGroup[] = ["trust", "tunnel", "unsupported"];

// Within a group, the changes that move the subscription come first.
const KEY_ORDER = [
  "new-url",
  "new-domain",
  "fallback-url",
  "routing",
  "routing-enable",
  "insecure",
  "change-user-agent",
  "manual-block-user-agent",
  "mux-enable",
  "fragmentation-enable",
  "fragmentation-packets",
  "fragmentation-length",
  "fragmentation-interval",
  "sniffing-enable",
];

const KEY_LABELS: Record<string, DictKey> = {
  "new-url": "subs.changes.key.newUrl",
  "new-domain": "subs.changes.key.newDomain",
  "fallback-url": "subs.changes.key.fallbackUrl",
  "change-user-agent": "subs.changes.key.changeUserAgent",
  "manual-block-user-agent": "subs.changes.key.lockUserAgent",
  insecure: "subs.changes.key.insecure",
  routing: "subs.changes.key.routing",
  "routing-enable": "subs.changes.key.routingEnable",
  "mux-enable": "settings.mux",
  "fragmentation-enable": "settings.fragment",
  "fragmentation-packets": "settings.fragmentPackets",
  "fragmentation-length": "settings.fragmentLength",
  "fragmentation-interval": "settings.fragmentDelay",
  "sniffing-enable": "settings.domainSniffing",
};

/** The translated name of a key Kasumi knows; others are shown as the raw key. */
export function keyLabel(key: string): DictKey | null {
  return KEY_LABELS[key] ?? null;
}

export function groupOf(c: PendingChange): ProposalGroup {
  if (c.action.kind === "unsupported") return "unsupported";
  return c.risk === "tunnelBehaviour" ? "tunnel" : "trust";
}

function rank(key: string): number {
  const i = KEY_ORDER.indexOf(key);
  return i < 0 ? KEY_ORDER.length : i;
}

/** Non-empty groups in display order, each sorted by importance, then key. */
export function groupChanges(
  changes: PendingChange[],
): { group: ProposalGroup; items: PendingChange[] }[] {
  return GROUP_ORDER.map((group) => ({
    group,
    items: changes
      .filter((c) => groupOf(c) === group)
      .sort((a, b) => rank(a.key) - rank(b.key) || a.key.localeCompare(b.key)),
  })).filter((g) => g.items.length > 0);
}

/** Changes that only tune the connection; they can be accepted together. */
export function safeDigests(changes: PendingChange[]): string[] {
  return changes.filter((c) => groupOf(c) === "tunnel").map((c) => c.digest);
}

export type DomainMove = { from: string; to: string; otherDomain: boolean };

/** The host move a URL or domain change makes, if it is one. */
export function domainMove(action: ChangeAction): DomainMove | null {
  if (action.kind !== "replaceUrl" && action.kind !== "replaceDomain") return null;
  return { from: action.fromHost, to: action.toHost, otherDomain: action.otherDomain };
}

/** An on/off value the UI words instead of printing `true`. */
export function boolValue(action: ChangeAction): boolean | null {
  switch (action.kind) {
    case "setInsecure":
    case "setRoutingEnabled":
      return action.on;
    case "tunnelSetting":
      return "on" in action.setting ? action.setting.on : null;
    default:
      return null;
  }
}

export const ROUTING_LISTS = [
  "blockSites",
  "blockIp",
  "directSites",
  "directIp",
  "proxySites",
  "proxyIp",
] as const satisfies readonly (keyof RoutingImport)[];

/** The route the group runs with now, the one an import would take it from. */
export function currentGroupRoute(routes: Route[], groupId: string): Route | undefined {
  return (
    routes.find((r) => routeEnabled(r) && routeGroups(r).includes(groupId)) ??
    routes.find((r) => r.id === DEFAULT_ROUTE_ID)
  );
}

/** How many proposals a card badge counts. */
export const proposalCount = (changes: PendingChange[] | undefined) => changes?.length ?? 0;

/** The pending tunnel keys a card shows as small badges. */
export function tunnelKeys(changes: PendingChange[] | undefined): string[] {
  return (changes ?? []).filter((c) => groupOf(c) === "tunnel").map((c) => c.key);
}
