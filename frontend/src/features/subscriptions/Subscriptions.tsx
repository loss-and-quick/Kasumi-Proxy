// ============================================================
// features/subscriptions/Subscriptions.tsx
// Manage remote profile sources.
// ============================================================
import { lazy, Suspense, useEffect, useState } from "react";
import {
  AppBar,
  Btn,
  Card,
  Dialog,
  Field,
  GroupPicker,
  Icon,
  IconBtn,
  IntervalField,
  RowToggle,
  SettingGroup,
  Sheet,
  SheetAction,
  Switch,
  UpdateModeControl,
} from "../../components";
import { useFormatters, useT } from "../../i18n";
import type { Subscription } from "../../lib/bridge";
import {
  BASE_GROUP_ID,
  type GroupChoice,
  groupChoiceReady,
  hostOf,
  ownedGroupLeftEmpty,
} from "../../lib/groups";
import { isInsecureHttpUrl, isLocalOrPrivateHost, minutesToClock, uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { copyText, readText } from "../profiles/clipboard";

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
  const t = useT();

  const [addOpen, setAddOpen] = useState(false);
  const [edit, setEdit] = useState<Subscription | "new" | null>(null);
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
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  // Each imported subscription gets a group of its own unless one is picked.
  const [importEach, setImportEach] = useState(true);
  const [importGroup, setImportGroup] = useState<GroupChoice>({ id: BASE_GROUP_ID });
  const [importAutoUpdate, setImportAutoUpdate] = useState(false);
  const [importInterval, setImportInterval] = useState(360); // minutes (06:00)

  const enabledCount = subs.filter((s) => s.enabled).length;
  const importedCount = subs.reduce((n, s) => n + s.count, 0);

  const exportCopy = async (text: string, count: number) => {
    setExportOpen(false);
    notify((await copyText(text)) ? t("subs.exportCopied", { count }) : text);
  };

  const copySubUrl = async (sub: Subscription) => {
    notify((await copyText(sub.url)) ? t("subs.urlCopied") : sub.url);
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
      filter: s.filter,
      updateMode: s.updateMode,
    }));
    return exportCopy(JSON.stringify(payload, null, 2), payload.length);
  };

  const openImport = () => {
    setImportOpen(true);
    // Prefill from the clipboard (native under Tauri, web Clipboard API otherwise);
    // leave the field untouched if something is typed there or the clipboard is
    // empty or unreadable.
    if (importText.trim()) return;
    readText().then((txt) => {
      const v = txt?.trim();
      if (v) setImportText((cur) => (cur.trim() ? cur : v));
    });
  };

  const importSubs = async () => {
    const text = importText.trim();
    if (!text) return notify(t("subs.importEmpty"));
    let parsed: Subscription[];
    try {
      parsed = parseSubscriptionsInput(text, {
        autoUpdate: importAutoUpdate,
        interval: importInterval,
      });
    } catch {
      return notify(t("subs.importInvalid"));
    }
    if (!parsed.length) return notify(t("subs.importInvalid"));
    if (!importEach && !groupChoiceReady(importGroup)) return notify(t("groups.picker.needName"));
    // Sequential so each write sees the previous one: a shared new group is made
    // once, and two subscriptions from the same host land in one group.
    try {
      for (const sub of parsed) {
        // Unless a group is picked, a JSON dump keeps the group it names when
        // that group still exists.
        const kept = groups.find((g) => g.id === sub.groupId);
        const choice: GroupChoice = !importEach
          ? importGroup
          : kept
            ? { id: kept.id }
            : { newName: "" };
        await saveSubscription(sub, choice);
      }
    } catch (e) {
      notify(t("store.service.error", { error: String(e instanceof Error ? e.message : e) }));
      return;
    }
    setImportText("");
    setImportOpen(false);
    notify(t("subs.imported", { count: parsed.length }));
    for (const sub of parsed) if (sub.enabled) await updateSub(sub.id);
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
            />
            <IconBtn name="add" title={t("subs.add")} onClick={() => setAddOpen(true)} />
          </>
        }
      />

      <div className="scroll">
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {subs.map((s) => (
            <SubCard
              key={s.id}
              s={s}
              groupName={groups.find((g) => g.id === (s.groupId ?? BASE_GROUP_ID))?.name ?? ""}
              onOpenGroup={() => onOpenGroup(s.groupId ?? BASE_GROUP_ID)}
              revealed={!!revealed[s.id]}
              onReveal={() => setRevealed((r) => ({ ...r, [s.id]: !r[s.id] }))}
              onToggle={(enabled) => upsertSub({ ...s, enabled })}
              onUpdate={() => void updateSub(s.id)}
              onEdit={() => setEdit(s)}
              onDelete={() => {
                setDelGroupToo(true);
                setConfirmDel(s);
              }}
              onCopyUrl={() => void copySubUrl(s)}
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

      <Sheet open={addOpen} title={t("subs.addBtn")} onClose={() => setAddOpen(false)}>
        <div style={{ display: "flex", flexDirection: "column" }}>
          <SheetAction
            icon="edit_note"
            label={t("subs.add.manual")}
            sub={t("subs.add.manualSub")}
            onClick={() => {
              setAddOpen(false);
              setEdit("new");
            }}
          />
          <SheetAction
            icon="content_paste"
            label={t("subs.add.paste")}
            sub={t("subs.add.pasteSub")}
            onClick={() => {
              setAddOpen(false);
              openImport();
            }}
          />
        </div>
      </Sheet>

      <Sheet open={importOpen} title={t("subs.import")} onClose={() => setImportOpen(false)}>
        <Field
          label={t("subs.importLabel")}
          value={importText}
          onChange={setImportText}
          area
          mono={false}
          hint={t("subs.importHint")}
        />
        <RowToggle
          icon="create_new_folder"
          title={t("subs.import.groupEach")}
          sub={t("subs.import.groupEachSub")}
          on={importEach}
          onChange={setImportEach}
        />
        {!importEach && (
          <GroupPicker
            label={t("subs.edit.targetGroup")}
            groups={groups}
            value={importGroup}
            onChange={setImportGroup}
          />
        )}
        <div style={{ marginTop: 14 }}>
          <RowToggle
            icon="autorenew"
            title={t("subs.autoUpdate")}
            sub={t("subs.autoUpdateSub")}
            on={importAutoUpdate}
            onChange={setImportAutoUpdate}
          />
          {importAutoUpdate && (
            <div style={{ paddingLeft: 54 }}>
              <IntervalField
                label={t("subs.interval")}
                minutes={importInterval}
                onChange={setImportInterval}
              />
            </div>
          )}
        </div>
        <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
          <Btn variant="text" onClick={() => setImportOpen(false)}>
            {t("subs.confirmDel.cancel")}
          </Btn>
          <Btn variant="filled" onClick={() => void importSubs()} disabled={!importText.trim()}>
            {t("subs.importBtn")}
          </Btn>
        </div>
      </Sheet>

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
        onClose={() => setEdit(null)}
        onSave={async (data, group) => {
          const isNew = edit === "new";
          try {
            await saveSubscription(data, group);
          } catch (e) {
            notify(t("store.service.error", { error: String(e instanceof Error ? e.message : e) }));
            return;
          }
          setEdit(null);
          // A new subscription is fetched straight away; the card shows the result.
          if (isNew) void updateSub(data.id);
          else notify(t("subs.saved"));
        }}
      />

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

// Parse the import text into subscriptions. JSON (an exported dump, object or
// array) is read field-by-field; anything else is treated as a whitespace-
// separated list of URLs. Throws on malformed JSON so the caller can report it.
function parseSubscriptionsInput(
  text: string,
  defaults: { autoUpdate: boolean; interval: number },
): Subscription[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  const make = (p: Partial<Subscription> & { url: string }): Subscription => ({
    id: uid(),
    remarks: p.remarks?.trim() || hostOf(p.url),
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
  });
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    const parsed: unknown = JSON.parse(trimmed);
    const arr = Array.isArray(parsed) ? parsed : [parsed];
    return arr
      .filter(
        (x): x is Partial<Subscription> & { url: string } =>
          !!x &&
          typeof (x as { url?: unknown }).url === "string" &&
          (x as { url: string }).url.trim() !== "",
      )
      .map(make);
  }
  return trimmed
    .split(/\s+/)
    .map((u) => u.trim())
    .filter(Boolean)
    .map((url) => make({ url }));
}

function SubCard({
  s,
  groupName,
  onOpenGroup,
  revealed,
  onReveal,
  onToggle,
  onUpdate,
  onEdit,
  onDelete,
  onCopyUrl,
}: {
  s: Subscription;
  groupName: string;
  onOpenGroup: () => void;
  revealed: boolean;
  onReveal: () => void;
  onToggle: (enabled: boolean) => void;
  onUpdate: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onCopyUrl: () => void;
}) {
  const t = useT();
  const { formatDateTime } = useFormatters();
  return (
    <Card style={{ padding: 14, opacity: s.enabled ? 1 : 0.6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 15.5, fontWeight: 600 }} className="truncate">
            {s.remarks}
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginTop: 4,
              fontSize: 11.5,
              color: "var(--on-surface-variant)",
            }}
          >
            <span className="mono">{t("subs.profilesCount", { n: s.count })}</span>
            <span>·</span>
            <span>
              {s.lastUpdated
                ? t("subs.updatedAt", { date: formatDateTime(new Date(s.lastUpdated)) })
                : t("subs.neverUpdated")}
            </span>
          </div>
        </div>
        <Switch on={s.enabled} onChange={onToggle} />
      </div>
      <button
        type="button"
        className="btn-reset sub-group-link"
        title={t("subs.openGroup")}
        onClick={onOpenGroup}
      >
        <Icon name="folder" style={{ fontSize: 15 }} />
        <span className="truncate">{groupName}</span>
      </button>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          marginTop: 12,
          background: "var(--sc-lowest)",
          borderRadius: 9,
          padding: "8px 6px 8px 11px",
        }}
      >
        <span
          className="mono truncate"
          style={{ flex: 1, fontSize: 11.5, color: "var(--on-surface-variant)" }}
        >
          {revealed
            ? s.url
            : s.url.replace(/(token=|\/)([^/=&]{4})[^/=&]*/g, (_m, a, b) => `${a}${b}••••••`)}
        </span>
        <IconBtn
          sm
          name={revealed ? "visibility_off" : "visibility"}
          onClick={onReveal}
          title={t("subs.toggleUrl")}
        />
      </div>

      <div
        style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12, flexWrap: "wrap" }}
      >
        {s.autoUpdate ? (
          <span
            className="chip active"
            style={{ height: 28, fontSize: 11.5, pointerEvents: "none" }}
          >
            <Icon name="autorenew" style={{ fontSize: 15 }} />{" "}
            {t("subs.autoLabel", { interval: minutesToClock(s.interval) })}
          </span>
        ) : (
          <span className="chip" style={{ height: 28, fontSize: 11.5, pointerEvents: "none" }}>
            <Icon name="schedule" style={{ fontSize: 15 }} /> {t("subs.manualLabel")}
          </span>
        )}
        {s.allowInsecure && (
          <span
            className="chip"
            style={{
              height: 28,
              fontSize: 11.5,
              pointerEvents: "none",
              color: "var(--warn)",
              borderColor: "var(--warn)",
            }}
          >
            <Icon name="gpp_maybe" style={{ fontSize: 15 }} /> {t("subs.insecureLabel")}
          </span>
        )}
        {s.lastError && (
          <span
            className="chip"
            style={{
              height: 28,
              fontSize: 11.5,
              pointerEvents: "none",
              color: "var(--error)",
              borderColor: "var(--error)",
            }}
          >
            <Icon name="error" style={{ fontSize: 15 }} /> {t("subs.errorLabel")}
          </span>
        )}
        <div style={{ flex: 1 }} />
        <IconBtn sm name="content_copy" onClick={onCopyUrl} title={t("subs.copyUrl")} />
        <IconBtn sm name="edit" onClick={onEdit} title={t("subs.editAction")} />
        <IconBtn sm name="delete" onClick={onDelete} title={t("subs.deleteAction")} />
        <Btn variant="tonal" sm icon="refresh" onClick={onUpdate}>
          {t("subs.updateBtn")}
        </Btn>
      </div>
      {s.lastError && (
        <div className="hint error" style={{ marginTop: 8 }}>
          {s.lastError}
        </div>
      )}
    </Card>
  );
}

function SubEditSheet({
  open,
  sub,
  onClose,
  onSave,
}: {
  open: boolean;
  sub: Subscription | null;
  onClose: () => void;
  onSave: (sub: Subscription, group: GroupChoice) => Promise<void>;
}) {
  const t = useT();
  const groups = useAppStore((s) => s.groups);
  const [d, setD] = useState<Subscription | null>(null);
  const [group, setGroup] = useState<GroupChoice>({ newName: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setErrors({});
    setSaving(false);
    if (sub) {
      setD({ ...sub });
      setGroup({ id: sub.groupId ?? BASE_GROUP_ID });
      return;
    }
    // A new subscription gets a group of its own, named after it, unless the
    // user picks an existing one.
    setGroup({ newName: "" });
    setD({
      id: uid(),
      remarks: "",
      url: "",
      userAgent: "",
      filter: "",
      enabled: true,
      groupId: null,
      autoUpdate: false,
      interval: 360, // minutes (06:00)
      allowInsecure: false,
      updateMode: "auto",
      lastUpdated: "",
      count: 0,
      lastError: null,
    });
  }, [open, sub]);

  if (!open || !d) return null;
  const set = <K extends keyof Subscription>(k: K, v: Subscription[K]) =>
    setD((s) => (s ? { ...s, [k]: v } : s));
  const name = d.remarks.trim() || hostOf(d.url);
  const submit = async () => {
    const nextErrors: Record<string, string> = {};
    if (!d.url.trim()) nextErrors.url = t("subs.edit.validationUrl");
    if (d.autoUpdate && (!Number.isFinite(d.interval) || d.interval <= 0))
      nextErrors.interval = t("subs.edit.validationInterval");
    if (d.filter.trim()) {
      try {
        const source = d.filter.trim().startsWith("(?i)") ? d.filter.trim().slice(4) : d.filter;
        const flags = d.filter.trim().startsWith("(?i)") ? "i" : "";
        new RegExp(source, flags);
      } catch {
        nextErrors.filter = t("subs.edit.validationFilter");
      }
    }
    if (!groupChoiceReady(group, name)) nextErrors.group = t("groups.picker.needName");
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;
    setSaving(true);
    try {
      // TLS verification is skipped only for localhost / private hosts (self-signed
      // certs are normal there); public URLs are always verified strictly.
      await onSave(
        { ...d, url: d.url.trim(), remarks: name, allowInsecure: isLocalOrPrivateHost(d.url) },
        group,
      );
    } finally {
      setSaving(false);
    }
  };

  const showInsecureHint =
    d.url.trim() !== "" && isInsecureHttpUrl(d.url) && !isLocalOrPrivateHost(d.url);

  return (
    <Sheet
      open={open}
      title={sub ? t("subs.edit.editTitle") : t("subs.edit.newTitle")}
      onClose={onClose}
    >
      <Field
        label={t("subs.edit.url")}
        value={d.url}
        area
        mono={false}
        placeholder={t("subs.edit.urlPh")}
        onChange={(v) => set("url", v)}
        error={errors.url}
        hint={showInsecureHint ? t("subs.edit.urlInsecureHint") : undefined}
      />
      <Field
        label={t("subs.edit.remarks")}
        value={d.remarks}
        mono={false}
        placeholder={hostOf(d.url) || t("subs.edit.remarksPh")}
        onChange={(v) => set("remarks", v)}
        hint={t("subs.edit.remarksHint")}
      />
      <GroupPicker
        label={t("subs.edit.targetGroup")}
        groups={groups}
        value={group}
        onChange={setGroup}
        suggestedName={name}
      />
      {errors.group && (
        <div className="hint error" style={{ marginTop: -8, marginBottom: 10 }}>
          {errors.group}
        </div>
      )}
      <div className="input-row" style={{ marginBottom: 14, marginTop: 14 }}>
        <Field
          label={t("subs.edit.userAgent")}
          value={d.userAgent}
          mono={false}
          placeholder={t("subs.edit.userAgentPh")}
          onChange={(v) => set("userAgent", v)}
        />
        <Field
          label={t("subs.edit.filter")}
          value={d.filter}
          placeholder={t("subs.edit.filterPh")}
          onChange={(v) => set("filter", v)}
          error={errors.filter}
        />
      </div>
      <UpdateModeControl value={d.updateMode} onChange={(v) => set("updateMode", v)} />
      <RowToggle
        icon="autorenew"
        title={t("subs.autoUpdate")}
        sub={t("subs.autoUpdateSub")}
        on={d.autoUpdate}
        onChange={(v) => set("autoUpdate", v)}
      />
      {d.autoUpdate && (
        <SettingGroup>
          <IntervalField
            label={t("subs.interval")}
            minutes={d.interval}
            onChange={(v) => set("interval", v)}
            error={errors.interval}
          />
        </SettingGroup>
      )}
      <div style={{ display: "flex", gap: 10, marginTop: 14, justifyContent: "flex-end" }}>
        <Btn variant="text" onClick={onClose}>
          {t("subs.confirmDel.cancel")}
        </Btn>
        <Btn variant="filled" icon="check" disabled={saving} onClick={() => void submit()}>
          {sub ? t("subs.edit.save") : t("subs.edit.addAndUpdate")}
        </Btn>
      </div>
    </Sheet>
  );
}
