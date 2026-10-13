import { Icon, RowToggle } from "../../components";
import { useFormatters, useT } from "../../i18n";
import type { RoutingImport, Subscription } from "../../lib/bridge";
import { BASE_GROUP_ID } from "../../lib/groups";
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

/** What importing a provider's routing profile would do, and the switch to turn it on. */
export function RoutingImportCard({
  sub,
  routing,
  activate,
  onActivate,
}: {
  sub: Subscription;
  routing: RoutingImport;
  activate: boolean;
  onActivate: (on: boolean) => void;
}) {
  const t = useT();
  const { formatList } = useFormatters();
  const groups = useAppStore((s) => s.groups);
  const routes = useAppStore((s) => s.routes);
  const routingMode = useAppStore((s) => s.settings.routingMode);
  const groupId = sub.groupId ?? BASE_GROUP_ID;
  const groupName = groups.find((g) => g.id === groupId)?.name ?? groupId;
  const current = currentGroupRoute(routes, groupId);
  // Re-importing replaces this subscription's own route; that is no conflict.
  const replaces = current && current.sourceSubId !== sub.id ? current : null;
  const counts = ROUTING_LISTS.filter((k) => routing[k].length > 0);

  return (
    <div
      style={{
        marginTop: 10,
        padding: "12px 14px",
        background: "var(--sc-low)",
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
      <div>{t("subs.routing.appliesTo", { group: groupName })}</div>
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
      <div style={{ marginInline: -4 }}>
        <RowToggle
          icon="toggle_on"
          title={t("subs.routing.activate")}
          sub={t("subs.routing.activateSub")}
          on={activate}
          onChange={onActivate}
        />
      </div>
    </div>
  );
}
