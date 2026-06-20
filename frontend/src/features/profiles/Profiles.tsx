// ============================================================
// features/profiles/Profiles.tsx
// Profile manager — search, filter, sort, activate, edit, clone,
// delete, share, import pasted links, and basic bulk actions.
// ============================================================

import { lazy, Suspense, useMemo, useState } from "react";
import { Icon } from "../../components";
import type { Profile } from "../../generated/bindings";
import { useT } from "../../i18n";
import { bridge } from "../../lib/bridge-provider";
import { fuzzyFilterSort } from "../../lib/fuzzy";
import { profileSearchText } from "../../lib/profile-utils";
import { useAppStore } from "../../store/useAppStore";
import { copyText } from "./clipboard";
import { PingActionsSheet } from "./PingActionsSheet";
import { ProfilesList } from "./ProfilesList";
import { ProfilesToolbar } from "./ProfilesToolbar";
import type { SortMode } from "./types";

const AddProfileSheet = lazy(() =>
  import("./AddProfileSheet").then((module) => ({ default: module.AddProfileSheet })),
);
const DeleteProfileDialog = lazy(() =>
  import("./DeleteProfileDialog").then((module) => ({ default: module.DeleteProfileDialog })),
);
const ImportProfilesSheet = lazy(() =>
  import("./ImportProfilesSheet").then((module) => ({ default: module.ImportProfilesSheet })),
);
const ProfileActionsSheet = lazy(() =>
  import("./ProfileActionsSheet").then((module) => ({ default: module.ProfileActionsSheet })),
);
const QrCodeSheet = lazy(() =>
  import("../../components/QrCodeSheet").then((module) => ({ default: module.QrCodeSheet })),
);
const QrScannerSheet = lazy(() =>
  import("../../components/QrScannerSheet").then((module) => ({ default: module.QrScannerSheet })),
);
const ManageGroupsSheet = lazy(() =>
  import("./ManageGroupsSheet").then((module) => ({ default: module.ManageGroupsSheet })),
);

export default function Profiles({ onOpenEditor }: { onOpenEditor: (id: string | "new") => void }) {
  const profiles = useAppStore((s) => s.profiles);
  const groups = useAppStore((s) => s.groups);
  const activeId = useAppStore((s) => s.activeId);
  const notify = useAppStore((s) => s.notify);
  const setActive = useAppStore((s) => s.setActive);
  const cloneProfile = useAppStore((s) => s.cloneProfile);
  const removeProfile = useAppStore((s) => s.removeProfile);
  const removeProfiles = useAppStore((s) => s.removeProfiles);
  const moveProfiles = useAppStore((s) => s.moveProfiles);
  const pingProfile = useAppStore((s) => s.pingProfile);
  const realPingProfile = useAppStore((s) => s.realPingProfile);
  const pingAll = useAppStore((s) => s.pingAll);
  const realPingAll = useAppStore((s) => s.realPingAll);
  const speedTestAll = useAppStore((s) => s.speedTestAll);
  const speedTestProfile = useAppStore((s) => s.speedTestProfile);
  const pinging = useAppStore((s) => s.pinging);
  const speedTesting = useAppStore((s) => s.speedTesting);
  const removeUnreachable = useAppStore((s) => s.removeUnreachable);
  const removeDuplicates = useAppStore((s) => s.removeDuplicates);
  const selectBest = useAppStore((s) => s.selectBest);
  const addProfiles = useAppStore((s) => s.addProfiles);
  const t = useT();

  const [pingSheetOpen, setPingSheetOpen] = useState(false);

  const [groupFilter, setGroupFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [sort, setSort] = useState<SortMode>("name");
  const [sheetProfile, setSheetProfile] = useState<Profile | null>(null);
  const [confirmDel, setConfirmDel] = useState<Profile | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importGroup, setImportGroup] = useState<string>(groups[0]?.id ?? "g-main");
  const [bulkMode, setBulkMode] = useState(false);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [moveGroup, setMoveGroup] = useState<string>(groups[0]?.id ?? "g-main");
  const [qrScannerOpen, setQrScannerOpen] = useState(false);
  const [qrPayload, setQrPayload] = useState<{ title: string; text: string } | null>(null);
  const [manageGroupsOpen, setManageGroupsOpen] = useState(false);

  const toggleSelected = (id: string) =>
    setSelected((current) => ({ ...current, [id]: !current[id] }));
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
    list = [...list].sort((left, right) => {
      if (sort === "ping") {
        return (
          (left.meta.ping != null && left.meta.ping >= 0
            ? left.meta.ping
            : Number.MAX_SAFE_INTEGER) -
            (right.meta.ping != null && right.meta.ping >= 0
              ? right.meta.ping
              : Number.MAX_SAFE_INTEGER) || left.meta.remarks.localeCompare(right.meta.remarks)
        );
      }
      return left.meta.remarks.localeCompare(right.meta.remarks);
    });
  }

  const byGroup: Record<string, Profile[]> = {};
  list.forEach((profile) => {
    const groupProfiles = byGroup[profile.meta.groupId] ?? [];
    groupProfiles.push(profile);
    byGroup[profile.meta.groupId] = groupProfiles;
  });
  const orderedGroups = groups.filter((group) => byGroup[group.id]?.length);

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

  async function importProfilesFromText(text: string) {
    const parsed = await bridge.parseShareLinks(text);
    if (!parsed.length) {
      notify(t("profiles.import.none"));
      return false;
    }
    addProfiles(
      parsed.map((profile) => ({ ...profile, meta: { ...profile.meta, groupId: importGroup } })),
    );
    setImportText("");
    setImportOpen(false);
    setAddOpen(false);
    return true;
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
    for (const id of selectedIds) await pingProfile(id);
    notify(t("profiles.bulkPingDone", { count: selectedIds.length }));
  }

  function doBulkMove() {
    if (!selectedIds.length) return;
    moveProfiles(selectedIds, moveGroup);
    notify(t("profiles.bulkMoveDone", { count: selectedIds.length }));
  }

  function doBulkDelete() {
    removeProfiles(selectedIds);
    setSelected({});
    notify(t("profiles.bulkDeleteDone", { count: selectedIds.length }));
  }

  function doBulkDedup() {
    removeDuplicates(groupFilter);
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
        onToggleSearch={() => setSearchOpen((current) => !current)}
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
        moveGroup={moveGroup}
        setMoveGroup={setMoveGroup}
        onBulkPing={() => void doBulkPing()}
        onBulkShare={() => void doShareSelected()}
        onBulkMove={doBulkMove}
        onBulkDelete={doBulkDelete}
        onBulkDedup={doBulkDedup}
      />

      <ProfilesList
        groups={orderedGroups}
        byGroup={byGroup}
        activeId={activeId}
        bulkMode={bulkMode}
        selected={selected}
        emptyText={t("profiles.noResults")}
        onToggleSelected={toggleSelected}
        onUse={(id) => void setActive(id)}
        onEdit={onOpenEditor}
        onMore={setSheetProfile}
      />

      <button type="button" className="fab" onClick={() => setAddOpen(true)}>
        <Icon name="add" /> {t("profiles.fabNew")}
      </button>

      <PingActionsSheet
        open={pingSheetOpen}
        onClose={() => setPingSheetOpen(false)}
        pinging={pinging.size > 0}
        speedTesting={speedTesting.size > 0}
        onTcping={() => {
          void pingAll(groupFilter);
          setPingSheetOpen(false);
        }}
        onRealping={() => {
          void realPingAll(groupFilter);
          setPingSheetOpen(false);
        }}
        onSpeedTest={() => {
          void speedTestAll(groupFilter);
          setPingSheetOpen(false);
        }}
        onDeleteUnreachable={() => {
          void removeUnreachable(groupFilter);
          setPingSheetOpen(false);
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
            onPing={(profile) => {
              void pingProfile(profile.meta.id);
              closeSheetProfile();
            }}
            onRealPing={(profile) => {
              void realPingProfile(profile.meta.id);
              closeSheetProfile();
            }}
            onSpeedTest={(profile) => {
              void speedTestProfile(profile.meta.id);
              closeSheetProfile();
            }}
            onDelete={(profile) => {
              setConfirmDel(profile);
              closeSheetProfile();
            }}
          />
        </Suspense>
      )}

      {addOpen && (
        <Suspense fallback={null}>
          <AddProfileSheet
            open={addOpen}
            onClose={() => setAddOpen(false)}
            onManual={() => {
              setAddOpen(false);
              onOpenEditor("new");
            }}
            onPaste={() => {
              setAddOpen(false);
              setImportOpen(true);
            }}
            onScanQr={() => {
              setAddOpen(false);
              setImportOpen(true);
              setQrScannerOpen(true);
            }}
            onNewGroup={() => {
              setAddOpen(false);
              setManageGroupsOpen(true);
            }}
          />
        </Suspense>
      )}

      {importOpen && (
        <Suspense fallback={null}>
          <ImportProfilesSheet
            open={importOpen}
            onClose={() => setImportOpen(false)}
            importText={importText}
            setImportText={setImportText}
            importGroup={importGroup}
            setImportGroup={setImportGroup}
            groups={groups}
            onImport={() => void importProfilesFromText(importText)}
            onScanQr={() => setQrScannerOpen(true)}
          />
        </Suspense>
      )}

      {qrScannerOpen && (
        <Suspense fallback={null}>
          <QrScannerSheet
            open={qrScannerOpen}
            title={t("qr.scan.title")}
            onClose={() => setQrScannerOpen(false)}
            onResult={(text) => importProfilesFromText(text)}
          />
        </Suspense>
      )}

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

      {confirmDel && (
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
      )}
    </div>
  );
}
