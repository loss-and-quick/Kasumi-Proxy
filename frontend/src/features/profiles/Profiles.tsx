// ============================================================
// features/profiles/Profiles.tsx
// Profile manager — search, filter, sort, activate, edit, clone,
// delete, share, import pasted links, and basic bulk actions.
// ============================================================

import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import { Btn, Card, confirm, Icon } from "../../components";
import type { Profile, TestKind } from "../../generated/bindings";
import { useT } from "../../i18n";
import { bridge } from "../../lib/bridge-provider";
import { fuzzyFilterSort } from "../../lib/fuzzy";
import { BASE_GROUP_ID, type GroupChoice, groupChoiceReady } from "../../lib/groups";
import { profileSearchText } from "../../lib/profile-utils";
import { useAppStore } from "../../store/useAppStore";
import { AddSheet } from "../add/AddSheet";
import type { NewProfile } from "../editor/Editor";
import { copyText } from "./clipboard";
import { askRemoveUnreachable } from "./confirmations";
import { planLocateActive } from "./locate";
import { groupSections, sortProfiles } from "./order";
import { PingActionsSheet } from "./PingActionsSheet";
import { ProfilesList } from "./ProfilesList";
import { ProfilesToolbar } from "./ProfilesToolbar";
import { useProfilesView } from "./viewState";

const DeleteProfileDialog = lazy(() =>
  import("./DeleteProfileDialog").then((module) => ({ default: module.DeleteProfileDialog })),
);
const ProfileActionsSheet = lazy(() =>
  import("./ProfileActionsSheet").then((module) => ({ default: module.ProfileActionsSheet })),
);
const TestLogSheet = lazy(() =>
  import("./TestLogSheet").then((module) => ({ default: module.TestLogSheet })),
);
const QrCodeSheet = lazy(() =>
  import("../../components/QrCodeSheet").then((module) => ({ default: module.QrCodeSheet })),
);
const ManageGroupsSheet = lazy(() =>
  import("./ManageGroupsSheet").then((module) => ({ default: module.ManageGroupsSheet })),
);

export default function Profiles({
  onOpenEditor,
}: {
  onOpenEditor: (id: string | "new", newProfile?: NewProfile) => void;
}) {
  const profiles = useAppStore((s) => s.profiles);
  const testResults = useAppStore((s) => s.testResults);
  const groups = useAppStore((s) => s.groups);
  const activeId = useAppStore((s) => s.activeId);
  const notify = useAppStore((s) => s.notify);
  const setActive = useAppStore((s) => s.setActive);
  const cloneProfile = useAppStore((s) => s.cloneProfile);
  const removeProfile = useAppStore((s) => s.removeProfile);
  const removeProfiles = useAppStore((s) => s.removeProfiles);
  const moveProfiles = useAppStore((s) => s.moveProfiles);
  const testProfile = useAppStore((s) => s.testProfile);
  const testAll = useAppStore((s) => s.testAll);
  const pinging = useAppStore((s) => s.pinging);
  const speedTesting = useAppStore((s) => s.speedTesting);
  const removeUnreachable = useAppStore((s) => s.removeUnreachable);
  const removeDuplicates = useAppStore((s) => s.removeDuplicates);
  const selectBest = useAppStore((s) => s.selectBest);
  const resolveGroup = useAppStore((s) => s.resolveGroup);
  const t = useT();

  const [pingSheetOpen, setPingSheetOpen] = useState(false);

  const listScrollRef = useRef<HTMLDivElement | null>(null);
  const targetRowRef = useRef<HTMLDivElement | null>(null);
  const [highlightId, setHighlightId] = useState<string | null>(null);

  const view = useProfilesView();
  const {
    query,
    setQuery,
    searchOpen,
    setSearchOpen,
    sort,
    setSort,
    setGroupFilter,
    setFilters,
    locateTargetId,
    clearLocate,
  } = view;
  // A remembered group that has since been deleted falls back to all of them.
  const groupFilter =
    view.groupFilter !== "all" && groups.some((g) => g.id === view.groupFilter)
      ? view.groupFilter
      : "all";
  // A search kept from the last visit stays visible, not applied out of sight.
  useEffect(() => {
    const kept = useProfilesView.getState();
    if (kept.query.trim()) kept.setSearchOpen(true);
  }, []);

  // When navigated to with a locate request (e.g. tapping active profile on Overview),
  // ensure the profile is visible, scroll it into view, and briefly highlight it.
  useEffect(() => {
    if (!locateTargetId) return;

    const targetProfile = profiles.find((p) => p.meta.id === locateTargetId);
    if (!targetProfile) {
      clearLocate();
      return;
    }

    const plan = planLocateActive({
      activeProfile: targetProfile,
      currentGroupFilter: groupFilter,
      currentQuery: query,
      groups,
    });

    if (plan && (plan.nextGroupFilter !== undefined || plan.nextQuery !== undefined)) {
      setFilters({
        ...(plan.nextGroupFilter !== undefined ? { groupFilter: plan.nextGroupFilter } : {}),
        ...(plan.nextQuery !== undefined ? { query: plan.nextQuery } : {}),
      });
    }

    clearLocate();

    const targetId = locateTargetId;
    const frame = requestAnimationFrame(() => {
      const row = targetRowRef.current;
      const list = listScrollRef.current;
      if (row && list) {
        const rowRect = row.getBoundingClientRect();
        const listRect = list.getBoundingClientRect();
        const top =
          list.scrollTop +
          rowRect.top -
          listRect.top -
          list.clientTop -
          (list.clientHeight - rowRect.height) / 2;

        const prefersReducedMotion =
          typeof window !== "undefined" &&
          window.matchMedia("(prefers-reduced-motion: reduce)").matches;

        list.scrollTo({
          top: Math.max(0, Math.min(top, list.scrollHeight - list.clientHeight)),
          behavior: prefersReducedMotion ? "auto" : "smooth",
        });

        setHighlightId(targetId);
      }
    });

    return () => cancelAnimationFrame(frame);
  }, [locateTargetId, profiles, groupFilter, query, groups, clearLocate, setFilters]);

  useEffect(() => {
    if (!highlightId) return;
    const timer = setTimeout(() => setHighlightId(null), 2000);
    return () => clearTimeout(timer);
  }, [highlightId]);
  const [sheetProfile, setSheetProfile] = useState<Profile | null>(null);
  const [confirmDel, setConfirmDel] = useState<Profile | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const addDefaultGroup = useMemo<GroupChoice>(
    () => ({ id: groupFilter !== "all" ? groupFilter : BASE_GROUP_ID }),
    [groupFilter],
  );
  const [bulkMode, setBulkMode] = useState(false);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [moveGroup, setMoveGroup] = useState<GroupChoice>({ id: BASE_GROUP_ID });
  const [qrPayload, setQrPayload] = useState<{ title: string; text: string } | null>(null);
  const [testLogTarget, setTestLogTarget] = useState<{ profile: Profile; kind: TestKind } | null>(
    null,
  );
  const [manageGroupsOpen, setManageGroupsOpen] = useState(false);

  const toggleSelected = (id: string) =>
    setSelected((current) => ({ ...current, [id]: !current[id] }));
  // Select or clear many at once: a whole group, or everything on screen.
  const setSelectedMany = (ids: string[], on: boolean) =>
    setSelected((current) => {
      const next = { ...current };
      for (const id of ids) next[id] = on;
      return next;
    });
  const selectedIds = useMemo(
    () =>
      Object.entries(selected)
        .filter(([, value]) => value)
        .map(([id]) => id),
    [selected],
  );

  let list = profiles;
  if (groupFilter !== "all") list = list.filter((profile) => profile.meta.groupId === groupFilter);
  if (query.trim()) {
    // While searching, rank by fuzzy relevance instead of the chosen sort.
    list = fuzzyFilterSort(list, query, profileSearchText);
  } else {
    list = sortProfiles(list, sort, testResults);
  }

  const sections = groupSections(list, groups);
  const byGroup = Object.fromEntries(sections.map((s) => [s.group.id, s.profiles]));
  const orderedGroups = sections.map((s) => s.group);
  // "All" means what the group filter and the search leave on screen.
  const visibleIds = list.map((profile) => profile.meta.id);
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selected[id]);

  const closeSheetProfile = () => setSheetProfile(null);

  async function doShare(profile: Profile) {
    try {
      const link = await bridge.buildShareLink(profile);
      if (!link) {
        notify(t("profiles.qr.unsupported"));
        return;
      }
      notify((await copyText(link)) ? t("profiles.shareCopied") : link);
    } catch {
      notify(t("profiles.qr.unsupported"));
    }
  }

  async function doShareSelected() {
    try {
      const text = (
        await Promise.all(
          profiles
            .filter((profile) => selectedIds.includes(profile.meta.id))
            .map((profile) => bridge.buildShareLink(profile)),
        )
      )
        .filter(Boolean)
        .join("\n");
      if (!text) {
        notify(t("profiles.qr.unsupported"));
        return;
      }
      notify(
        (await copyText(text))
          ? t("profiles.shareCopiedMany", { count: selectedIds.length })
          : text,
      );
    } catch {
      notify(t("profiles.qr.unsupported"));
    }
  }

  async function openProfileQr(profile: Profile) {
    try {
      const link = await bridge.buildShareLink(profile);
      if (!link) {
        notify(t("profiles.qr.unsupported"));
        return;
      }
      setQrPayload({ title: profile.meta.remarks || t("qr.show.title"), text: link });
    } catch {
      notify(t("profiles.qr.unsupported"));
    }
  }

  async function doBulkPing() {
    for (const id of selectedIds) await testProfile(id, "tcpPing");
    notify(t("profiles.bulkPingDone", { count: selectedIds.length }));
  }

  async function doBulkMove() {
    if (!selectedIds.length) return;
    if (!groupChoiceReady(moveGroup)) {
      notify(t("groups.picker.needName"));
      return;
    }
    const groupId = await resolveGroup(moveGroup, "");
    setMoveGroup({ id: groupId });
    await moveProfiles(selectedIds, groupId);
    notify(t("profiles.bulkMoveDone", { count: selectedIds.length }));
  }

  async function doBulkDelete() {
    const count = selectedIds.length;
    const ok = await confirm({
      title: t("confirm.bulkDelete.title", { count }),
      body: t("confirm.bulkDelete.body"),
      confirmLabel: t("profiles.confirmDel.delete"),
    });
    if (!ok) return;
    await removeProfiles(selectedIds);
    setSelected({});
    notify(t("profiles.bulkDeleteDone", { count }));
  }

  async function doBulkDedup() {
    const ok = await confirm({
      icon: "content_cut",
      title: t("confirm.dedup.title"),
      body: groupFilter === "all" ? t("confirm.dedup.bodyAll") : t("confirm.dedup.bodyGroup"),
      confirmLabel: t("confirm.dedup.action"),
    });
    if (ok) await removeDuplicates(groupFilter);
  }

  function toggleBulkMode() {
    setBulkMode((current) => !current);
    setSelected({});
  }

  return (
    <div className="app-region screen-enter">
      <ProfilesToolbar
        profileCount={profiles.length}
        groupCount={groups.length}
        searchOpen={searchOpen}
        query={query}
        setQuery={setQuery}
        onToggleSearch={() => setSearchOpen(!searchOpen)}
        onOpenPingSheet={() => setPingSheetOpen(true)}
        bulkMode={bulkMode}
        onToggleBulk={toggleBulkMode}
        onOpenAdd={() => setAddOpen(true)}
        onManageGroups={() => setManageGroupsOpen(true)}
        groupFilter={groupFilter}
        setGroupFilter={setGroupFilter}
        groups={groups}
        sort={sort}
        setSort={setSort}
        selectedCount={selectedIds.length}
        visibleCount={visibleIds.length}
        allVisibleSelected={allVisibleSelected}
        onSelectAll={() => setSelectedMany(visibleIds, !allVisibleSelected)}
        moveGroup={moveGroup}
        setMoveGroup={setMoveGroup}
        onBulkPing={() => void doBulkPing()}
        onBulkShare={() => void doShareSelected()}
        onBulkMove={() => void doBulkMove()}
        onBulkDelete={() => void doBulkDelete()}
        onBulkDedup={() => void doBulkDedup()}
      />

      <ProfilesList
        scrollRef={listScrollRef}
        targetRowRef={targetRowRef}
        targetId={locateTargetId ?? highlightId ?? activeId}
        highlightId={highlightId}
        groups={orderedGroups}
        byGroup={byGroup}
        activeId={activeId}
        bulkMode={bulkMode}
        selected={selected}
        emptyText={t("profiles.noResults")}
        empty={
          // First run: "no matching profiles" would read as a failed search.
          profiles.length === 0 ? (
            <Card
              className="flat"
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: 10,
                padding: "28px 16px",
                textAlign: "center",
                marginTop: 4,
              }}
            >
              <Icon name="dns" style={{ fontSize: 32, color: "var(--on-surface-variant)" }} />
              <div style={{ fontSize: 15, fontWeight: 600 }}>{t("profiles.emptyTitle")}</div>
              <div style={{ fontSize: 13, color: "var(--on-surface-variant)", maxWidth: 300 }}>
                {t("profiles.emptyBody")}
              </div>
              <Btn variant="filled" icon="add" onClick={() => setAddOpen(true)}>
                {t("add.submit")}
              </Btn>
            </Card>
          ) : undefined
        }
        onToggleSelected={toggleSelected}
        onToggleGroup={(ids, on) => setSelectedMany(ids, on)}
        onUse={(id) => void setActive(id)}
        onEdit={onOpenEditor}
        onMore={setSheetProfile}
        onShowTestLog={(profile, kind) => setTestLogTarget({ profile, kind })}
      />

      <button type="button" className="fab" onClick={() => setAddOpen(true)}>
        <Icon name="add" /> {t("profiles.fabNew")}
      </button>

      <PingActionsSheet
        open={pingSheetOpen}
        onClose={() => setPingSheetOpen(false)}
        pinging={pinging.size > 0}
        speedTesting={speedTesting.size > 0}
        onTestAll={(kind) => {
          void testAll(kind, groupFilter);
          setPingSheetOpen(false);
        }}
        onDeleteUnreachable={() => {
          setPingSheetOpen(false);
          void askRemoveUnreachable(groupFilter).then((ok) => {
            if (ok) void removeUnreachable(groupFilter);
          });
        }}
        onSelectBest={() => {
          selectBest(groupFilter);
          setPingSheetOpen(false);
        }}
      />

      {sheetProfile && (
        <Suspense fallback={null}>
          <ProfileActionsSheet
            profile={sheetProfile}
            onClose={closeSheetProfile}
            pinging={sheetProfile ? pinging.has(sheetProfile.meta.id) : false}
            speedTesting={sheetProfile ? speedTesting.has(sheetProfile.meta.id) : false}
            onUse={(profile) => {
              void setActive(profile.meta.id);
              closeSheetProfile();
            }}
            onEdit={(profile) => {
              onOpenEditor(profile.meta.id);
              closeSheetProfile();
            }}
            onClone={(profile) => {
              cloneProfile(profile.meta.id);
              closeSheetProfile();
              notify(t("profiles.cloneDone"));
            }}
            onShare={(profile) => {
              void doShare(profile);
              closeSheetProfile();
            }}
            onShowQr={(profile) => {
              void openProfileQr(profile);
              closeSheetProfile();
            }}
            onTest={(profile, kind) => {
              void testProfile(profile.meta.id, kind);
              closeSheetProfile();
            }}
            onDelete={(profile) => {
              setConfirmDel(profile);
              closeSheetProfile();
            }}
          />
        </Suspense>
      )}

      {testLogTarget && (
        <Suspense fallback={null}>
          <TestLogSheet
            profile={testLogTarget.profile}
            kind={testLogTarget.kind}
            onClose={() => setTestLogTarget(null)}
          />
        </Suspense>
      )}

      <AddSheet
        open={addOpen}
        onClose={() => setAddOpen(false)}
        // Pasted profiles land in the group being looked at, if any.
        defaultGroup={addDefaultGroup}
        inGroup={groupFilter !== "all"}
        // The sheet stays open beneath the editor: cancelling returns to it, saving
        // completes the add.
        onManualProfile={(draft, group) =>
          onOpenEditor("new", {
            draft: draft ?? undefined,
            group,
            onSaved: () => setAddOpen(false),
          })
        }
        onDone={({ subs, profiles: added, profileGroup, routes }) => {
          if (subs) notify(t("subs.imported", { count: subs }));
          if (routes) notify(t("add.routingImported", { count: routes }));
          if (added && profileGroup) setGroupFilter(profileGroup);
        }}
      />

      {manageGroupsOpen && (
        <Suspense fallback={null}>
          <ManageGroupsSheet open onClose={() => setManageGroupsOpen(false)} />
        </Suspense>
      )}

      {qrPayload && (
        <Suspense fallback={null}>
          <QrCodeSheet
            open
            title={qrPayload.title}
            text={qrPayload.text}
            onClose={() => setQrPayload(null)}
          />
        </Suspense>
      )}

      <Suspense fallback={null}>
        <DeleteProfileDialog
          profile={confirmDel}
          onClose={() => setConfirmDel(null)}
          onConfirm={(profile) => {
            removeProfile(profile.meta.id);
            notify(t("profiles.deleted"));
            setConfirmDel(null);
          }}
        />
      </Suspense>
    </div>
  );
}
