// ============================================================
// features/subscriptions/Subscriptions.tsx
// Manage remote profile sources.
// ============================================================
import { lazy, Suspense, useMemo, useState } from "react";
import { AppBar, Btn, Card, Dialog, Icon, IconBtn, Sheet, SheetAction } from "../../components";
import type { SubWarning } from "../../generated/bindings";
import { useT } from "../../i18n";
import type { Subscription } from "../../lib/bridge";
import { bridge } from "../../lib/bridge-provider";
import { BASE_GROUP_ID, type GroupChoice, ownedGroupLeftEmpty } from "../../lib/groups";
import { wasReported } from "../../store/errors";
import { useAppStore } from "../../store/useAppStore";
import { AddSheet } from "../add/AddSheet";
import { copyText } from "../profiles/clipboard";
import { AuditSheet } from "./AuditSheet";
import { IdentityNotice } from "./IdentityNotice";
import { ProposedChangesSheet } from "./ProposedChangesSheet";
import { SubCard, WarningsSheet } from "./SubCard";
import { SubEditSheet } from "./SubEditSheet";
import { displayTitle } from "./sub-display";

const ManageGroupsSheet = lazy(() =>
  import("../profiles/ManageGroupsSheet").then((module) => ({
    default: module.ManageGroupsSheet,
  })),
);

export default function Subscriptions({
  onOpenGroup,
}: {
  /** Show the group's profiles on the Profiles screen. */
  onOpenGroup: (groupId: string) => void;
}) {
  const subs = useAppStore((s) => s.subscriptions);
  const groups = useAppStore((s) => s.groups);
  const notify = useAppStore((s) => s.notify);
  const upsertSub = useAppStore((s) => s.upsertSub);
  const saveSubscription = useAppStore((s) => s.saveSubscription);
  const removeSub = useAppStore((s) => s.removeSub);
  const updateSub = useAppStore((s) => s.updateSub);
  const updateAllSubs = useAppStore((s) => s.updateAllSubs);
  const updatingSubs = useAppStore((s) => s.updatingSubs);
  const t = useT();

  const [addOpen, setAddOpen] = useState(false);
  const addDefaultGroup = useMemo<GroupChoice>(() => ({ id: BASE_GROUP_ID }), []);
  const [edit, setEdit] = useState<Subscription | "new" | null>(null);
  // The address typed in the Add sheet before it handed over to the editor.
  const [newUrl, setNewUrl] = useState("");
  const [confirmDel, setConfirmDel] = useState<Subscription | null>(null);
  const [delGroupToo, setDelGroupToo] = useState(true);
  const [manageGroupsOpen, setManageGroupsOpen] = useState(false);
  const profiles = useAppStore((s) => s.profiles);
  // The group made for the subscription being deleted, when it would be left empty.
  const groupLeftEmpty = confirmDel
    ? ownedGroupLeftEmpty({ groups, profiles, subscriptions: subs }, confirmDel.id)
    : undefined;
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [exportOpen, setExportOpen] = useState(false);
  const [warningsOf, setWarningsOf] = useState<SubWarning[] | null>(null);
  // Sheets hold an id, so they follow the subscription as answers update it.
  const [changesOf, setChangesOf] = useState<string | null>(null);
  const [auditOf, setAuditOf] = useState<string | null>(null);
  const [menuOf, setMenuOf] = useState<string | null>(null);
  const byId = (id: string | null) => (id ? (subs.find((s) => s.id === id) ?? null) : null);
  const menuSub = byId(menuOf);

  const enabledCount = subs.filter((s) => s.enabled).length;
  const importedCount = subs.reduce((n, s) => n + s.count, 0);

  const exportCopy = async (text: string, count: number) => {
    setExportOpen(false);
    notify((await copyText(text)) ? t("subs.exportCopied", { count }) : text);
  };

  const copySubUrl = async (sub: Subscription) => {
    notify((await copyText(sub.url)) ? t("subs.urlCopied") : sub.url);
  };

  const openUrl = async (url: string) => {
    try {
      await bridge.openUrl(url);
    } catch {
      notify(t("subs.openLinkFailed"));
    }
  };

  const exportUrls = () => {
    const urls = subs.map((s) => s.url.trim()).filter(Boolean);
    if (!urls.length) return notify(t("subs.exportEmpty"));
    return exportCopy(urls.join("\n"), urls.length);
  };

  const exportJson = () => {
    if (!subs.length) return notify(t("subs.exportEmpty"));
    // Config-only fields; runtime/bookkeeping (id, count, lastUpdated, lastError,
    // prev/nextProfile) is intentionally dropped so the dump is portable.
    const payload = subs.map((s) => ({
      remarks: s.remarks,
      url: s.url,
      enabled: s.enabled,
      groupId: s.groupId,
      autoUpdate: s.autoUpdate,
      interval: s.interval,
      allowInsecure: s.allowInsecure,
      userAgent: s.userAgent,
      request: s.request,
      filter: s.filter,
      updateMode: s.updateMode,
      manualTitle: s.manualTitle,
      intervalOverride: s.intervalOverride,
    }));
    return exportCopy(JSON.stringify(payload, null, 2), payload.length);
  };

  return (
    <div className="app-region screen-enter">
      <AppBar
        title={t("subs.title")}
        subtitle={t("subs.subtitle", { active: enabledCount, imported: importedCount })}
        actions={
          <>
            <IconBtn
              name="folder_managed"
              title={t("profiles.manageGroups")}
              onClick={() => setManageGroupsOpen(true)}
            />
            <IconBtn
              name="ios_share"
              title={t("subs.export")}
              onClick={() => setExportOpen(true)}
            />
            <IconBtn
              name="cloud_sync"
              title={t("subs.updateAll")}
              onClick={() => void updateAllSubs()}
              disabled={updatingSubs.size > 0}
              spinning={updatingSubs.size > 0}
            />
            <IconBtn name="add" title={t("subs.add")} onClick={() => setAddOpen(true)} />
          </>
        }
      />

      <div className="scroll">
        <IdentityNotice />
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {subs.map((s) => (
            <SubCard
              key={s.id}
              s={s}
              groupName={groups.find((g) => g.id === (s.groupId ?? BASE_GROUP_ID))?.name ?? ""}
              onOpenGroup={() => onOpenGroup(s.groupId ?? BASE_GROUP_ID)}
              revealed={!!revealed[s.id]}
              onReveal={() => setRevealed((r) => ({ ...r, [s.id]: !r[s.id] }))}
              onToggle={(enabled) => upsertSub({ ...s, enabled }, s)}
              updating={updatingSubs.has(s.id)}
              onUpdate={() => void updateSub(s.id)}
              onEdit={() => setEdit(s)}
              onMore={() => setMenuOf(s.id)}
              onOpenUrl={(url) => void openUrl(url)}
              onShowWarnings={() => setWarningsOf(s.warnings ?? [])}
              onShowChanges={() => setChangesOf(s.id)}
            />
          ))}
        </div>

        {subs.length === 0 && (
          <Btn
            variant="tonal"
            block
            icon="add"
            style={{ marginTop: 14 }}
            onClick={() => setAddOpen(true)}
          >
            {t("subs.addBtn")}
          </Btn>
        )}
        <Card
          className="flat"
          style={{ marginTop: 14, display: "flex", gap: 12, alignItems: "flex-start" }}
        >
          <Icon name="info" style={{ color: "var(--on-surface-faint)", fontSize: 20 }} />
          <div style={{ fontSize: 12.5, color: "var(--on-surface-variant)", lineHeight: 1.5 }}>
            {t("subs.infoText")}
          </div>
        </Card>
      </div>

      <AddSheet
        open={addOpen}
        onClose={() => setAddOpen(false)}
        defaultGroup={addDefaultGroup}
        onManualSub={(url) => {
          setAddOpen(false);
          setNewUrl(url ?? "");
          setEdit("new");
        }}
        onDone={({ subs: added, profiles, profileGroup, routes }) => {
          if (added) notify(t("subs.imported", { count: added }));
          if (routes) notify(t("add.routingImported", { count: routes }));
          // Pasted profile links live on the Profiles screen; show them there.
          if (profiles && profileGroup) onOpenGroup(profileGroup);
        }}
      />

      <Sheet open={exportOpen} title={t("subs.export")} onClose={() => setExportOpen(false)}>
        <div style={{ fontSize: 12.5, color: "var(--on-surface-variant)", marginBottom: 12 }}>
          {t("subs.exportHint")}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <Btn variant="tonal" block icon="link" onClick={() => void exportUrls()}>
            {t("subs.exportUrls")}
          </Btn>
          <Btn variant="tonal" block icon="data_object" onClick={() => void exportJson()}>
            {t("subs.exportJson")}
          </Btn>
        </div>
      </Sheet>

      <SubEditSheet
        open={!!edit}
        sub={edit === "new" ? null : edit}
        initialUrl={newUrl}
        onClose={() => setEdit(null)}
        onSave={async (data, group) => {
          const isNew = edit === "new";
          try {
            await saveSubscription(data, group, edit && edit !== "new" ? edit : undefined);
          } catch (e) {
            if (!wasReported(e))
              notify(
                t("store.service.error", { error: String(e instanceof Error ? e.message : e) }),
              );
            return;
          }
          setEdit(null);
          // A new subscription is fetched straight away; the card shows the result.
          if (isNew) void updateSub(data.id);
          else notify(t("subs.saved"));
        }}
      />

      <WarningsSheet warnings={warningsOf} onClose={() => setWarningsOf(null)} />

      <ProposedChangesSheet sub={byId(changesOf)} onClose={() => setChangesOf(null)} />
      <AuditSheet sub={byId(auditOf)} onClose={() => setAuditOf(null)} />

      <Sheet
        open={!!menuSub}
        title={menuSub ? displayTitle(menuSub) : ""}
        onClose={() => setMenuOf(null)}
      >
        {menuSub && (
          <div style={{ display: "flex", flexDirection: "column" }}>
            <SheetAction
              icon="content_copy"
              label={t("subs.copyUrl")}
              onClick={() => {
                setMenuOf(null);
                void copySubUrl(menuSub);
              }}
            />
            <SheetAction
              icon="history"
              label={t("subs.menu.history")}
              sub={t("subs.menu.historySub", { count: menuSub.audit?.length ?? 0 })}
              onClick={() => {
                setMenuOf(null);
                setAuditOf(menuSub.id);
              }}
            />
            <SheetAction
              icon="delete"
              label={t("subs.deleteAction")}
              danger
              onClick={() => {
                setMenuOf(null);
                setDelGroupToo(true);
                setConfirmDel(menuSub);
              }}
            />
          </div>
        )}
      </Sheet>

      <Dialog
        open={!!confirmDel}
        icon="delete"
        iconColor={{ bg: "var(--error-container)", fg: "oklch(0.92 0.04 25)" }}
        title={t("subs.confirmDel.title")}
        onClose={() => setConfirmDel(null)}
        actions={
          <>
            <Btn variant="text" onClick={() => setConfirmDel(null)}>
              {t("subs.confirmDel.cancel")}
            </Btn>
            <Btn
              variant="error"
              onClick={() => {
                if (confirmDel) void removeSub(confirmDel.id, !!groupLeftEmpty && delGroupToo);
                setConfirmDel(null);
                notify(t("subs.deleted"));
              }}
            >
              {t("subs.confirmDel.delete")}
            </Btn>
          </>
        }
      >
        {t("subs.confirmDel.prefix")}{" "}
        <b style={{ color: "var(--on-surface)" }}>{confirmDel?.remarks}</b>?{" "}
        {t("subs.confirmDel.body")}
        {groupLeftEmpty && (
          <label style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 12 }}>
            <input
              type="checkbox"
              style={{ accentColor: "var(--primary)", width: 18, height: 18 }}
              checked={delGroupToo}
              onChange={(e) => setDelGroupToo(e.target.checked)}
            />
            <span>{t("subs.confirmDel.alsoGroup", { name: groupLeftEmpty.name })}</span>
          </label>
        )}
      </Dialog>

      {manageGroupsOpen && (
        <Suspense fallback={null}>
          <ManageGroupsSheet open onClose={() => setManageGroupsOpen(false)} />
        </Suspense>
      )}
    </div>
  );
}
