// ============================================================
// features/subscriptions/Subscriptions.tsx
// Manage remote profile sources.
// ============================================================
import { useEffect, useRef, useState } from "react";
import {
  AppBar,
  Btn,
  Card,
  Dialog,
  Field,
  Icon,
  IconBtn,
  RowToggle,
  Sheet,
  Switch,
} from "../../components";
import { useFormatters, useT } from "../../i18n";
import type { Subscription } from "../../lib/bridge";
import {
  clockToMinutes,
  isInsecureHttpUrl,
  isLocalOrPrivateHost,
  minutesToClock,
  uid,
} from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { copyText } from "../profiles/clipboard";

export default function Subscriptions() {
  const subs = useAppStore((s) => s.subscriptions);
  const groups = useAppStore((s) => s.groups);
  const notify = useAppStore((s) => s.notify);
  const upsertSub = useAppStore((s) => s.upsertSub);
  const removeSub = useAppStore((s) => s.removeSub);
  const updateSub = useAppStore((s) => s.updateSub);
  const updateAllSubs = useAppStore((s) => s.updateAllSubs);
  const addGroup = useAppStore((s) => s.addGroup);
  const t = useT();

  const [edit, setEdit] = useState<Subscription | "new" | null>(null);
  const [confirmDel, setConfirmDel] = useState<Subscription | null>(null);
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [exportOpen, setExportOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importGroup, setImportGroup] = useState(groups[0]?.id ?? "g-main");

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
    // The UI runs in a secure context (http://127.0.0.1), so prefill from the
    // clipboard; leave the field untouched if it's empty or unreadable.
    navigator.clipboard
      .readText()
      .then((txt) => {
        const v = txt.trim();
        if (v) setImportText(v);
      })
      .catch(() => {});
  };

  const importSubs = async () => {
    const text = importText.trim();
    if (!text) return notify(t("subs.importEmpty"));
    let parsed: Subscription[];
    try {
      parsed = parseSubscriptionsInput(text, importGroup);
    } catch {
      return notify(t("subs.importInvalid"));
    }
    if (!parsed.length) return notify(t("subs.importInvalid"));
    // Sequential so each functional patch sees the previous insert (avoids
    // racing the persisted state write).
    for (const sub of parsed) await upsertSub(sub);
    setImportText("");
    setImportOpen(false);
    notify(t("subs.imported", { count: parsed.length }));
  };

  return (
    <div className="app-region screen-enter">
      <AppBar
        title={t("subs.title")}
        subtitle={t("subs.subtitle", { active: enabledCount, imported: importedCount })}
        actions={
          <>
            <IconBtn name="content_paste" title={t("subs.import")} onClick={openImport} />
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
            <IconBtn name="add" title={t("subs.add")} onClick={() => setEdit("new")} />
          </>
        }
      />

      <div className="scroll">
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {subs.map((s) => (
            <SubCard
              key={s.id}
              s={s}
              revealed={!!revealed[s.id]}
              onReveal={() => setRevealed((r) => ({ ...r, [s.id]: !r[s.id] }))}
              onToggle={(enabled) => upsertSub({ ...s, enabled })}
              onUpdate={() => void updateSub(s.id)}
              onEdit={() => setEdit(s)}
              onDelete={() => setConfirmDel(s)}
              onCopyUrl={() => void copySubUrl(s)}
            />
          ))}
        </div>

        <Btn
          variant="tonal"
          block
          icon="add"
          style={{ marginTop: 14 }}
          onClick={() => setEdit("new")}
        >
          {t("subs.addBtn")}
        </Btn>
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

      <Sheet open={importOpen} title={t("subs.import")} onClose={() => setImportOpen(false)}>
        <Field
          label={t("subs.importLabel")}
          value={importText}
          onChange={setImportText}
          area
          mono={false}
          hint={t("subs.importHint")}
        />
        <div className="field-label">{t("subs.edit.targetGroup")}</div>
        <select
          className="select-box"
          value={importGroup}
          onChange={(e) => setImportGroup(e.target.value)}
        >
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name}
            </option>
          ))}
        </select>
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
        onNewGroup={addGroup}
        defaultGroupId={groups[0]?.id ?? "g-main"}
        onClose={() => setEdit(null)}
        onSave={async (data) => {
          try {
            await upsertSub(data);
            setEdit(null);
            notify(edit === "new" ? t("subs.added") : t("subs.saved"));
          } catch (e) {
            notify(t("store.service.error", { error: String(e instanceof Error ? e.message : e) }));
          }
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
                if (confirmDel) removeSub(confirmDel.id);
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
      </Dialog>
    </div>
  );
}

// Parse the import text into subscriptions. JSON (an exported dump, object or
// array) is read field-by-field; anything else is treated as a whitespace-
// separated list of URLs. Throws on malformed JSON so the caller can report it.
function parseSubscriptionsInput(text: string, groupId: string): Subscription[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  const deriveRemarks = (url: string) => {
    try {
      return new URL(url).hostname || url;
    } catch {
      return url;
    }
  };
  const make = (p: Partial<Subscription> & { url: string }): Subscription => ({
    id: uid(),
    remarks: p.remarks?.trim() || deriveRemarks(p.url.trim()),
    url: p.url.trim(),
    enabled: p.enabled ?? true,
    groupId: p.groupId ?? groupId,
    autoUpdate: p.autoUpdate ?? false,
    interval: p.interval ?? 360,
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
  revealed,
  onReveal,
  onToggle,
  onUpdate,
  onEdit,
  onDelete,
  onCopyUrl,
}: {
  s: Subscription;
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
        <div style={{ marginTop: 8, fontSize: 12, color: "var(--error)" }}>{s.lastError}</div>
      )}
    </Card>
  );
}

function SubEditSheet({
  open,
  sub,
  onClose,
  onSave,
  onNewGroup,
  defaultGroupId,
}: {
  open: boolean;
  sub: Subscription | null;
  onClose: () => void;
  onSave: (sub: Subscription) => Promise<void>;
  onNewGroup: (name: string) => Promise<string>;
  defaultGroupId: string;
}) {
  const t = useT();
  const groups = useAppStore((s) => s.groups);
  const groupOptions = groups.map((g) => ({ value: g.id, label: g.name }));
  const [d, setD] = useState<Subscription | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [newGroupName, setNewGroupName] = useState<string | null>(null);
  const newGroupInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (newGroupName !== null) newGroupInputRef.current?.focus();
  }, [newGroupName]);

  useEffect(() => {
    if (open) {
      setD(
        sub
          ? { ...sub }
          : {
              id: uid(),
              remarks: "",
              url: "",
              userAgent: "",
              filter: "",
              enabled: true,
              groupId: defaultGroupId,
              autoUpdate: false,
              interval: 360, // minutes (06:00)
              allowInsecure: false,
              updateMode: "auto",
              lastUpdated: "",
              count: 0,
              lastError: null,
            },
      );
    }
  }, [open, sub, defaultGroupId]);

  if (!open || !d) return null;
  const set = <K extends keyof Subscription>(k: K, v: Subscription[K]) =>
    setD((s) => (s ? { ...s, [k]: v } : s));
  const submit = () => {
    const nextErrors: Record<string, string> = {};
    if (!d.remarks.trim()) nextErrors.remarks = t("subs.edit.validationRemarks");
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
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;
    // TLS verification is skipped only for localhost / private hosts (self-signed
    // certs are normal there); public URLs are always verified strictly.
    onSave({ ...d, allowInsecure: isLocalOrPrivateHost(d.url) });
  };

  const showInsecureHint =
    d.url.trim() !== "" && isInsecureHttpUrl(d.url) && !isLocalOrPrivateHost(d.url);

  return (
    <Sheet
      open={open}
      title={sub ? t("subs.edit.editTitle") : t("subs.edit.newTitle")}
      onClose={onClose}
      headRight={
        <Btn variant="filled" sm icon="check" onClick={submit}>
          {t("subs.edit.save")}
        </Btn>
      }
    >
      <Field
        label={t("subs.edit.remarks")}
        value={d.remarks}
        mono={false}
        placeholder={t("subs.edit.remarksPh")}
        onChange={(v) => set("remarks", v)}
        error={errors.remarks}
      />
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
      <div className="field-label">{t("subs.edit.targetGroup")}</div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        {newGroupName !== null ? (
          <input
            ref={newGroupInputRef}
            className="input"
            value={newGroupName}
            onChange={(e) => setNewGroupName(e.target.value)}
            onBlur={async () => {
              const name = newGroupName.trim();
              if (name) set("groupId", await onNewGroup(name));
              setNewGroupName(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.currentTarget.blur();
              }
              if (e.key === "Escape") setNewGroupName(null);
            }}
            style={{ flex: 1 }}
          />
        ) : (
          <select
            className="select-box"
            value={d.groupId ?? groupOptions[0]?.value ?? "g-main"}
            onChange={(e) => set("groupId", e.target.value)}
            style={{ flex: 1 }}
          >
            {groupOptions.map((g) => (
              <option key={g.value} value={g.value}>
                {g.label}
              </option>
            ))}
          </select>
        )}
        <IconBtn
          name={newGroupName !== null ? "close" : "add"}
          title={t("profiles.add.newGroup")}
          onClick={() => setNewGroupName(newGroupName !== null ? null : "")}
          onMouseDown={(e) => e.preventDefault()}
        />
      </div>
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
      <div className="field-label">{t("common.updateMode")}</div>
      <select
        className="select-box"
        value={d.updateMode}
        onChange={(e) => set("updateMode", e.target.value as Subscription["updateMode"])}
        style={{ width: "100%", marginBottom: 14 }}
      >
        <option value="auto">{t("common.mode.auto")}</option>
        <option value="proxy">{t("common.mode.proxy")}</option>
        <option value="direct">{t("common.mode.direct")}</option>
      </select>
      <RowToggle
        icon="autorenew"
        title={t("subs.edit.autoUpdate")}
        sub={t("subs.edit.autoUpdateSub")}
        on={d.autoUpdate}
        onChange={(v) => set("autoUpdate", v)}
      />
      {d.autoUpdate && (
        <div style={{ paddingLeft: 54 }}>
          <Field
            label={t("subs.edit.interval")}
            value={minutesToClock(d.interval)}
            type="time"
            onChange={(v) => set("interval", clockToMinutes(v))}
            error={errors.interval}
          />
        </div>
      )}
      <div style={{ height: 10 }} />
    </Sheet>
  );
}
