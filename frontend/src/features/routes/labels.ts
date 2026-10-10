// ============================================================
// features/routes/labels.ts
// How routes, their outbounds and who they apply to read in the UI.
// ============================================================

import type { Group, Profile, Route } from "../../generated/bindings";
import type { useFormatters, useT } from "../../i18n";
import { isDefaultRoute, routeGroups, routeProfiles } from "../../lib/routes";

type T = ReturnType<typeof useT>;
type Formatters = ReturnType<typeof useFormatters>;

/** The default route is named in the user's language; others by the user. */
export const routeName = (route: Route, t: T) =>
  isDefaultRoute(route) ? t("routes.default") : route.name;

export function outboundLabel(tag: string, t: T, profiles: Pick<Profile, "meta">[]): string {
  if (tag === "direct") return t("routes.out.direct");
  if (tag === "block") return t("routes.out.block");
  if (tag === "proxy" || !tag) return t("routes.out.proxy");
  return profiles.find((p) => p.meta.id === tag)?.meta.remarks ?? t("routes.out.proxy");
}

/** "Everyone else", or the groups and profiles a route lists. */
export function scopeSummary(
  route: Route,
  t: T,
  formatters: Formatters,
  groups: Group[],
  profiles: Pick<Profile, "meta">[],
): string {
  if (isDefaultRoute(route)) return t("routes.scope.everyoneElse");
  const groupNames = routeGroups(route)
    .map((id) => groups.find((g) => g.id === id)?.name)
    .filter((name): name is string => !!name);
  const profileNames = routeProfiles(route)
    .map((id) => profiles.find((p) => p.meta.id === id)?.meta.remarks)
    .filter((name): name is string => !!name);
  if (!groupNames.length && !profileNames.length) return t("routes.scope.nobody");
  const parts: string[] = [];
  if (groupNames.length) parts.push(formatters.formatList(groupNames));
  if (profileNames.length)
    parts.push(
      profileNames.length <= 2
        ? formatters.formatList(profileNames)
        : t("routes.scope.profiles", { count: profileNames.length }),
    );
  return parts.join(" · ");
}
