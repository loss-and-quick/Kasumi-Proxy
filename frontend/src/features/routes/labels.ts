// ============================================================
// features/routes/labels.ts
// How routes, their outbounds and who they apply to read in the UI.
// ============================================================

import type {
  CoreEngine,
  CoreResolution,
  Group,
  Route,
  TargetFallback,
} from "../../generated/bindings";
import { type Translate, type useFormatters, useT } from "../../i18n";
import { coreConflictText } from "../../lib/core-conflict";
import { isDefaultRoute, routeGroups, routeProfiles } from "../../lib/routes";
import { useAppStore } from "../../store/useAppStore";
import { type ProfileLabels, profileLabelText } from "../profiles/labels";

type T = ReturnType<typeof useT>;
type Formatters = ReturnType<typeof useFormatters>;

/** The default route is named in the user's language; others by the user. */
export const routeName = (route: Route, t: T) =>
  isDefaultRoute(route) ? t("routes.default") : route.name;

/**
 * An outbound as a title and what tells it apart. A profile that no longer
 * exists reads as the proxy, which is where the config builders send its
 * traffic, marked as deleted so the dangling pick doesn't pass unnoticed.
 */
export function outboundParts(
  tag: string,
  t: T,
  labels: ProfileLabels,
): { title: string; sub?: string } {
  if (tag === "direct") return { title: t("routes.out.direct") };
  if (tag === "block") return { title: t("routes.out.block") };
  if (tag === "proxy" || !tag) return { title: t("routes.out.proxy") };
  const label = labels.get(tag);
  if (!label) return { title: t("routes.out.proxy"), sub: t("profiles.label.deleted") };
  return { title: label.name, sub: label.detail.join(" · ") || undefined };
}

export function outboundLabel(tag: string, t: T, labels: ProfileLabels): string {
  const label = labels.get(tag);
  if (label) return profileLabelText(label);
  const { title, sub } = outboundParts(tag, t, labels);
  return sub ? t("routes.out.deleted") : title;
}

/** "Everyone else" (plus pinned profiles), or the groups and profiles a route lists. */
export function scopeSummary(
  route: Route,
  t: T,
  formatters: Formatters,
  groups: Group[],
  labels: ProfileLabels,
): string {
  const everyoneElse = isDefaultRoute(route) ? t("routes.scope.everyoneElse") : null;
  const groupNames = routeGroups(route)
    .map((id) => groups.find((g) => g.id === id)?.name)
    .filter((name): name is string => !!name);
  // A deleted profile listed here matches no one, so it isn't named.
  const profileNames = routeProfiles(route)
    .map((id) => labels.get(id))
    .filter((label) => !!label)
    .map(profileLabelText);
  if (!groupNames.length && !profileNames.length) return everyoneElse ?? t("routes.scope.nobody");
  // The default route covers everyone else, plus the profiles pinned to it.
  const parts: string[] = everyoneElse ? [everyoneElse] : [];
  if (groupNames.length) parts.push(formatters.formatList(groupNames));
  if (profileNames.length)
    parts.push(
      profileNames.length <= 2
        ? formatters.formatList(profileNames)
        : t("routes.scope.profiles", { count: profileNames.length }),
    );
  return parts.join(" · ");
}

/**
 * Why the active profile's core can't send a rule's traffic to the profile
 * `tag`, so the config builders send it through the active proxy: the
 * backend's `ruleTargetFallback`. Null for the built-in outbounds, a deleted
 * profile (named as such already) and the active profile, which is the proxy.
 */
export function targetFallback(
  tag: string,
  activeId: string | null,
  resolutions: Readonly<Record<string, CoreResolution>>,
): { core: CoreEngine; fallback: TargetFallback } | null {
  if (!activeId || tag === activeId) return null;
  const core = resolutions[activeId]?.resolved;
  const fallback = core && resolutions[tag]?.ruleTargetFallback?.[core];
  return core && fallback ? { core, fallback } : null;
}

export function targetFallbackText(
  t: Translate,
  { core, fallback }: { core: CoreEngine; fallback: TargetFallback },
): string {
  switch (fallback.kind) {
    case "customConfig":
      return t("routes.target.customConfig");
    case "singBoxOnly":
      return t("routes.target.singBoxOnly", { core });
    case "cantStart":
      return t("routes.target.cantStart", { reason: coreConflictText(t, fallback.conflict) });
  }
}

/** {@link targetFallbackText} for a rule target under the current active profile. */
export function useTargetFallbackText(): (tag: string) => string | null {
  const t = useT();
  const activeId = useAppStore((s) => s.activeId);
  const resolutions = useAppStore((s) => s.coreResolutions);
  return (tag) => {
    const why = targetFallback(tag, activeId, resolutions);
    return why ? targetFallbackText(t, why) : null;
  };
}
