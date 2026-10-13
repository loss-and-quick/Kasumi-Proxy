import type { ReactNode } from "react";
import { Icon, RowToggle } from "../../components";
import { useFormatters, useT } from "../../i18n";
import type { RoutingImport } from "../../lib/bridge";
import { useAppStore } from "../../store/useAppStore";
import { currentGroupRoute, ROUTING_LISTS } from "./proposals";

const COUNT_KEY = {
  blockSites: "subs.routing.counts.blockSites",
  blockIp: "subs.routing.counts.blockIp",
  directSites: "subs.routing.counts.directSites",
  directIp: "subs.routing.counts.directIp",
  proxySites: "subs.routing.counts.proxySites",
  proxyIp: "subs.routing.counts.proxyIp",
} as const;

/** What importing a routing profile would do. As a group's route it names the group,
 *  warns about the route it replaces and offers the switch to turn it on; without
 *  a group it becomes a route of its own that applies to nothing yet. */
export function RoutingImportCard({
  groupId,
  ownerSubId,
  routing,
  activate,
  onActivate,
  children,
}: {
  /** The group whose route it becomes. */
  groupId?: string;
  /** The subscription that sent it: re-importing replaces its own route, no conflict. */
  ownerSubId?: string;
  routing: RoutingImport;
  activate?: boolean;
  onActivate?: (on: boolean) => void;
  /** Shown above the group line, such as a choice of group. */
  children?: ReactNode;
}) {
  const t = useT();
  const { formatList } = useFormatters();
  const groups = useAppStore((s) => s.groups);
  const routes = useAppStore((s) => s.routes);
  const routingMode = useAppStore((s) => s.settings.routingMode);
  const groupName = groups.find((g) => g.id === groupId)?.name ?? groupId;
  const current = groupId === undefined ? undefined : currentGroupRoute(routes, groupId);
  // Re-importing replaces this subscription's own route; that is no conflict.
  const replaces = current && (!ownerSubId || current.sourceSubId !== ownerSubId) ? current : null;
  const counts = ROUTING_LISTS.filter((k) => routing[k].length > 0);

  return (
    <div
      style={{
        marginTop: 10,
        padding: "12px 14px",
        background: "var(--sc-high)",
        borderRadius: 12,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        fontSize: 13,
        lineHeight: 1.45,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <Icon name="route" style={{ fontSize: 20, color: "var(--primary)", flexShrink: 0 }} />
        <span dir="auto" style={{ fontWeight: 600, fontSize: 14 }} className="truncate">
          {routing.name}
        </span>
      </div>
      {counts.length > 0 ? (
        <ul style={{ margin: 0, paddingInlineStart: 18, color: "var(--on-surface-variant)" }}>
          {counts.map((k) => (
            <li key={k}>{t(COUNT_KEY[k], { count: routing[k].length })}</li>
          ))}
        </ul>
      ) : (
        <div style={{ color: "var(--on-surface-variant)" }}>{t("subs.routing.noRules")}</div>
      )}
      <div style={{ color: "var(--on-surface-variant)" }}>
        {routing.globalProxy === false
          ? t("subs.routing.final.direct")
          : t("subs.routing.final.proxy")}
      </div>
      {children}
      <div>
        {groupId === undefined
          ? t("subs.routing.standalone")
          : t("subs.routing.appliesTo", { group: groupName ?? groupId })}
      </div>
      {replaces && (
        <div style={{ display: "flex", gap: 8, color: "var(--warn)" }}>
          <Icon name="warning" style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }} />
          <span>{t("subs.routing.conflict", { route: replaces.name })}</span>
        </div>
      )}
      {routing.ignoredFields.length > 0 && (
        <div style={{ color: "var(--on-surface-variant)" }}>
          {t("subs.routing.ignored")}{" "}
          <span className="mono" style={{ fontSize: 11.5, overflowWrap: "anywhere" }}>
            {formatList(routing.ignoredFields)}
          </span>
        </div>
      )}
      {routingMode !== "rules" && (
        <div style={{ color: "var(--on-surface-variant)" }}>{t("subs.routing.modeNote")}</div>
      )}
      {groupId !== undefined && onActivate && (
        <div style={{ marginInline: -4 }}>
          <RowToggle
            icon="toggle_on"
            title={t("subs.routing.activate")}
            sub={t("subs.routing.activateSub")}
            on={activate ?? false}
            onChange={onActivate}
          />
        </div>
      )}
    </div>
  );
}
