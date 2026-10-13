import { useEffect, useState } from "react";
import {
  Btn,
  Field,
  GroupPicker,
  Icon,
  IntervalField,
  RowToggle,
  SettingGroup,
  Sheet,
  UpdateModeControl,
} from "../../components";
import { useT } from "../../i18n";
import type { Subscription } from "../../lib/bridge";
import { BASE_GROUP_ID, type GroupChoice, groupChoiceReady, hostOf } from "../../lib/groups";
import { isInsecureHttpUrl, isLocalOrPrivateHost, uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";

export function SubEditSheet({
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
      manualTitle: false,
      intervalOverride: false,
      bodyEncrypted: false,
      warnings: [],
    });
  }, [open, sub]);

  if (!open || !d) return null;
  const set = <K extends keyof Subscription>(k: K, v: Subscription[K]) =>
    setD((s) => (s ? { ...s, [k]: v } : s));
  // The name the subscription gets when the field is left empty.
  const defaultName = d.provider?.title || hostOf(d.url);
  const name = d.remarks.trim() || defaultName;
  const providerHours = d.providerIntervalHours ?? null;
  const ownInterval = providerHours == null || d.intervalOverride;
  const submit = async () => {
    const nextErrors: Record<string, string> = {};
    if (!d.url.trim()) nextErrors.url = t("subs.edit.validationUrl");
    if (d.autoUpdate && ownInterval && (!Number.isFinite(d.interval) || d.interval <= 0))
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
        {
          ...d,
          url: d.url.trim(),
          remarks: name,
          // A name the user typed survives the provider's title; the default does not.
          manualTitle: d.remarks.trim() !== "" && d.remarks.trim() !== defaultName,
          allowInsecure: isLocalOrPrivateHost(d.url),
        },
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
        placeholder={defaultName || t("subs.edit.remarksPh")}
        onChange={(v) => set("remarks", v)}
        hint={
          d.provider?.title
            ? t("subs.edit.titleFromProvider", { title: d.provider.title })
            : t("subs.edit.remarksHint")
        }
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
          {providerHours != null && (
            <>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  padding: "4px 0 2px",
                  fontSize: 13,
                  color: d.intervalOverride ? "var(--on-surface-faint)" : "var(--on-surface)",
                }}
              >
                <Icon
                  name="schedule"
                  style={{ fontSize: 18, color: "var(--on-surface-variant)" }}
                />
                {t("subs.interval.provider", { hours: providerHours })}
              </div>
              <RowToggle
                icon="tune"
                title={t("subs.interval.useOwn")}
                sub={t("subs.interval.useOwnSub")}
                on={d.intervalOverride}
                onChange={(v) => set("intervalOverride", v)}
              />
            </>
          )}
          {/* The dial stops at 23:59, so a provider's day-long interval is shown, not edited. */}
          {ownInterval && (
            <IntervalField
              label={t("subs.interval")}
              minutes={d.interval}
              onChange={(v) => set("interval", v)}
              error={errors.interval}
            />
          )}
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
