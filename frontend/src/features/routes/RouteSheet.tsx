// ============================================================
// features/routes/RouteSheet.tsx
// Create a route or change who it applies to. Whole groups are the steady
// choice (new profiles of a subscription join on their own); single profiles
// can be picked inside a group. A profile or group another route has is
// marked, and picking it here moves it.
// ============================================================

import { useMemo, useState } from "react";
import {
  Btn,
  confirm,
  Field,
  Icon,
  IconBtn,
  ListRow,
  RowToggle,
  SectionLabel,
  Segmented,
  Sheet,
} from "../../components";
import type { Route } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import {
  isDefaultRoute,
  routeBlocks,
  routeEnabled,
  routeFinal,
  routeGroups,
  routeProfiles,
} from "../../lib/routes";
import { useAppStore } from "../../store/useAppStore";
import { routeName } from "./labels";

const SEARCH_FROM = 8;

export function RouteSheet({
  routeId,
  copyFrom,
  onClose,
  onCreated,
}: {
  /** The route to edit; `null` creates one. */
  routeId: string | null;
  /** Offered as "same blocks as …" when creating. */
  copyFrom: Route;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const t = useT();
  const formatters = useFormatters();
  const routes = useAppStore((s) => s.routes);
  const groups = useAppStore((s) => s.groups);
  const profiles = useAppStore((s) => s.profiles);
  const saveRoute = useAppStore((s) => s.saveRoute);
  const addRoute = useAppStore((s) => s.addRoute);
  const removeRoute = useAppStore((s) => s.removeRoute);

  const route = routes.find((r) => r.id === routeId);
  const creating = !route;
  const [name, setName] = useState(() => route?.name ?? t("routes.newName", { n: routes.length }));
  const [start, setStart] = useState<"empty" | "copy">("empty");
  const [enabled, setEnabled] = useState(() => (route ? routeEnabled(route) : true));
  const [pickedGroups, setPickedGroups] = useState(() => new Set(route ? routeGroups(route) : []));
  const [pickedProfiles, setPickedProfiles] = useState(
    () => new Set(route ? routeProfiles(route) : []),
  );
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [query, setQuery] = useState("");

  // Who else has each group and profile, to mark them and to say a pick moves them.
  const owner = useMemo(() => {
    const groupsOf = new Map<string, Route>();
    const profilesOf = new Map<string, Route>();
    for (const r of routes) {
      if (r.id === routeId) continue;
      for (const g of routeGroups(r)) groupsOf.set(g, r);
      for (const p of routeProfiles(r)) profilesOf.set(p, r);
    }
    return { groupsOf, profilesOf };
  }, [routes, routeId]);

  const dirty =
    creating ||
    name !== route.name ||
    enabled !== routeEnabled(route) ||
    !sameSet(pickedGroups, routeGroups(route)) ||
    !sameSet(pickedProfiles, routeProfiles(route));

  const toggle = (set: Set<string>, id: string) => {
    const next = new Set(set);
    if (!next.delete(id)) next.add(id);
    return next;
  };

  const save = async () => {
    const trimmed = name.trim() || t("routes.newName", { n: routes.length });
    const scope = { groups: [...pickedGroups], profiles: [...pickedProfiles] };
    if (route) {
      await saveRoute({ ...route, name: trimmed, enabled, ...scope });
    } else {
      const id = await addRoute(trimmed, {
        ...scope,
        ...(start === "copy"
          ? { blocks: routeBlocks(copyFrom), finalOutbound: routeFinal(copyFrom) }
          : {}),
      });
      onCreated(id);
    }
    onClose();
  };

  const remove = async () => {
    if (!route) return;
    const ok = await confirm({
      title: t("routes.deleteTitle", { name: route.name }),
      body: t("routes.deleteBody"),
      confirmLabel: t("routes.delete"),
    });
    if (!ok) return;
    void removeRoute(route.id);
    onClose();
  };

  if (route && isDefaultRoute(route)) {
    const others = routes.filter((r) => !isDefaultRoute(r));
    return (
      <Sheet open title={routeName(route, t)} onClose={onClose}>
        <div className="hint" style={{ marginBottom: 12 }}>
          {t("routes.defaultAbout")}
        </div>
        {others.length > 0 && (
          <div className="hint">
            {t("routes.defaultOthers", {
              routes: formatters.formatList(others.map((r) => r.name)),
            })}
          </div>
        )}
      </Sheet>
    );
  }

  const q = query.trim().toLowerCase();
  const profilesOf = (groupId: string) => profiles.filter((p) => p.meta.groupId === groupId);
  const check = (on: boolean) => (on ? "check_box" : "check_box_outline_blank");
  const movesFrom = (other: Route | undefined) =>
    other ? t("routes.scope.nowIn", { route: routeName(other, t) }) : undefined;

  const profileRow = (p: (typeof profiles)[number], viaGroup: boolean, showGroup: boolean) => {
    const listed = pickedProfiles.has(p.meta.id);
    const other = owner.profilesOf.get(p.meta.id);
    const group = groups.find((g) => g.id === p.meta.groupId)?.name;
    const sub = [
      showGroup ? group : undefined,
      !listed && viaGroup && !other ? t("routes.scope.viaGroup") : undefined,
      listed ? undefined : movesFrom(other),
    ]
      .filter(Boolean)
      .join(" · ");
    return (
      <div key={p.meta.id} className="route-scope-profile">
        <ListRow
          icon={check(listed || (viaGroup && !other))}
          title={p.meta.remarks}
          sub={sub || undefined}
          onClick={() => setPickedProfiles((s) => toggle(s, p.meta.id))}
        />
      </div>
    );
  };

  return (
    <Sheet
      open
      title={creating ? t("routes.new") : routeName(route, t)}
      onClose={onClose}
      beforeClose={async () =>
        !dirty ||
        creating ||
        confirm({
          title: t("routes.discardTitle"),
          confirmLabel: t("editor.discard.action"),
        })
      }
    >
      <Field mono={false} label={t("routes.name")} value={name} onChange={setName} />
      {!creating && (
        <RowToggle
          icon="toggle_on"
          title={t("routes.enabled")}
          sub={t("routes.enabledSub")}
          on={enabled}
          onChange={setEnabled}
        />
      )}
      {creating && routeBlocks(copyFrom).length > 0 && (
        <div style={{ margin: "4px 0 12px" }}>
          <Segmented
            ariaLabel={t("routes.startFrom")}
            label={t("routes.startFrom")}
            value={start}
            onChange={setStart}
            options={[
              { value: "empty", label: t("routes.startEmpty") },
              {
                value: "copy",
                label: t("routes.startCopy", { route: routeName(copyFrom, t) }),
              },
            ]}
          />
          {start === "copy" && (
            <div className="hint" style={{ marginTop: 6 }}>
              {t("routes.startCopyHint")}
            </div>
          )}
        </div>
      )}

      <SectionLabel>{t("routes.scope.title")}</SectionLabel>
      <div className="hint" style={{ marginBottom: 6 }}>
        {t("routes.scope.hint")}
      </div>
      {profiles.length > SEARCH_FROM && (
        <div className="route-search">
          <Icon name="search" />
          <input
            className="input"
            value={query}
            placeholder={t("routes.scope.search")}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      )}

      {q
        ? profiles
            .filter((p) => p.meta.remarks.toLowerCase().includes(q))
            .map((p) => profileRow(p, pickedGroups.has(p.meta.groupId), true))
        : groups.map((g) => {
            const members = profilesOf(g.id);
            const groupOn = pickedGroups.has(g.id);
            const other = owner.groupsOf.get(g.id);
            const expanded = open.has(g.id);
            const listedInside = members.filter((p) => pickedProfiles.has(p.meta.id)).length;
            return (
              <div key={g.id}>
                <ListRow
                  icon={check(groupOn)}
                  title={g.name}
                  sub={[
                    t("profiles.groups.count", { count: members.length }),
                    !groupOn && listedInside > 0
                      ? t("routes.scope.someProfiles", { count: listedInside })
                      : undefined,
                    groupOn ? undefined : movesFrom(other),
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                  onClick={() => setPickedGroups((s) => toggle(s, g.id))}
                  right={
                    members.length > 0 ? (
                      <IconBtn
                        name={expanded ? "expand_more" : "chevron_right"}
                        sm
                        title={t("routes.scope.pickProfiles")}
                        onClick={() => setOpen((s) => toggle(s, g.id))}
                      />
                    ) : undefined
                  }
                />
                {expanded && members.map((p) => profileRow(p, groupOn, false))}
              </div>
            );
          })}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 20 }}>
        <Btn icon="check" onClick={save} disabled={!dirty}>
          {creating ? t("routes.create") : t("routingSheet.save")}
        </Btn>
        {route && (
          <Btn variant="error" icon="delete" onClick={remove}>
            {t("routes.delete")}
          </Btn>
        )}
      </div>
    </Sheet>
  );
}

function sameSet(a: Set<string>, b: string[]) {
  return a.size === b.length && b.every((x) => a.has(x));
}
