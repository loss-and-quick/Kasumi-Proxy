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
import { useT } from "../../i18n";
import type { Subscription } from "../../lib/bridge";
import { uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";

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

  const enabledCount = subs.filter((s) => s.enabled).length;
  const importedCount = subs.reduce((n, s) => n + s.count, 0);

  return (
    <div className="app-region screen-enter">
      <AppBar
        title={t("subs.title")}
        subtitle={t("subs.subtitle", { active: enabledCount, imported: importedCount })}
        actions={
          <>
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

      <SubEditSheet
        open={!!edit}
        sub={edit === "new" ? null : edit}
        onNewGroup={addGroup}
        defaultGroupId={groups[0]?.id ?? "g-main"}
        onClose={() => setEdit(null)}
        onSave={(data) => {
          upsertSub(data);
          setEdit(null);
          notify(edit === "new" ? t("subs.added") : t("subs.saved"));
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

function SubCard({
  s,
  revealed,
  onReveal,
  onToggle,
  onUpdate,
  onEdit,
  onDelete,
}: {
  s: Subscription;
  revealed: boolean;
  onReveal: () => void;
  onToggle: (enabled: boolean) => void;
  onUpdate: () => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const t = useT();
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
                ? t("subs.updatedAt", { date: s.lastUpdated.split("T")[0] })
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
            {t("subs.autoLabel", { interval: s.interval })}
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
  onSave: (sub: Subscription) => void;
  onNewGroup: (name: string) => string;
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
              interval: 6,
              allowInsecure: false,
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
    onSave(d);
  };

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
      />
      <div className="field-label">{t("subs.edit.targetGroup")}</div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        {newGroupName !== null ? (
          <input
            ref={newGroupInputRef}
            className="input"
            value={newGroupName}
            onChange={(e) => setNewGroupName(e.target.value)}
            onBlur={() => setNewGroupName(null)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                const name = newGroupName.trim();
                if (name) set("groupId", onNewGroup(name));
                setNewGroupName(null);
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
      <RowToggle
        icon="toggle_on"
        title={t("subs.edit.enabled")}
        sub={t("subs.edit.enabledSub")}
        on={d.enabled}
        onChange={(v) => set("enabled", v)}
      />
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
            value={d.interval}
            type="number"
            onChange={(v) => set("interval", Number(v))}
            error={errors.interval}
          />
        </div>
      )}
      <RowToggle
        icon="gpp_maybe"
        title={t("subs.edit.insecure")}
        sub={t("subs.edit.insecureSub")}
        on={d.allowInsecure}
        onChange={(v) => set("allowInsecure", v)}
        danger
      />
      <div style={{ height: 10 }} />
    </Sheet>
  );
}
