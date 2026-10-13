import { useEffect, useState } from "react";
import {
  Btn,
  confirm,
  Disclosure,
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
import {
  checkSubscriptionUrl,
  isHappLink,
  type SubscriptionUrlCheck,
  subscriptionNameFrom,
  UNSUPPORTED_TEXT,
} from "../../lib/add-input";
import type { Subscription } from "../../lib/bridge";
import { bridge } from "../../lib/bridge-provider";
import {
  BASE_GROUP_ID,
  type GroupChoice,
  groupChoiceReady,
  providerConfigsOf,
} from "../../lib/groups";
import { isInsecureHttpUrl, isLocalOrPrivateHost, uid } from "../../lib/utils";
import { useAppStore } from "../../store/useAppStore";
import { SubIdentitySection } from "./SubIdentitySection";
import { savedName } from "./sub-edit";

export function SubEditSheet({
  open,
  sub,
  initialUrl = "",
  onClose,
  onSave,
}: {
  open: boolean;
  sub: Subscription | null;
  /** The address a new subscription starts with. */
  initialUrl?: string;
  onClose: () => void;
  onSave: (sub: Subscription, group: GroupChoice) => Promise<void>;
}) {
  const t = useT();
  const groups = useAppStore((s) => s.groups);
  const profiles = useAppStore((s) => s.profiles);
  const identityDefaults = useAppStore((s) => s.settings.requestIdentity);
  const [d, setD] = useState<Subscription | null>(null);
  const [group, setGroup] = useState<GroupChoice>({ newName: "" });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  // Whether the saved URL is an encrypted link (`null` while the backend checks),
  // and the address behind it once the user asks to see it.
  const [encrypted, setEncrypted] = useState<boolean | null>(false);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [urlCheck, setUrlCheck] = useState<{ url: string; check: SubscriptionUrlCheck } | null>(
    null,
  );
  const notify = useAppStore((s) => s.notify);

  useEffect(() => {
    setRevealed(null);
    const url = open ? sub?.url.trim() : "";
    if (!url) {
      setEncrypted(false);
      return;
    }
    setEncrypted(null);
    let alive = true;
    bridge
      .resolveImportInput(url)
      .then((r) => alive && setEncrypted(r.subscriptions[0]?.encrypted === true))
      .catch(() => alive && setEncrypted(false));
    return () => {
      alive = false;
    };
  }, [open, sub]);

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
      url: initialUrl,
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
      insecureByProvider: false,
      allowProviderConfigs: false,
    });
  }, [open, sub, initialUrl]);

  // A typed `happ://` address is read by the backend before it can name anything.
  const typedUrl = d?.url.trim() ?? "";
  useEffect(() => {
    if (!isHappLink(typedUrl)) return;
    let alive = true;
    const timer = window.setTimeout(async () => {
      const check = await checkSubscriptionUrl(typedUrl, bridge);
      if (alive) setUrlCheck({ url: typedUrl, check });
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [typedUrl]);

  if (!open || !d) return null;
  const set = <K extends keyof Subscription>(k: K, v: Subscription[K]) =>
    setD((s) => (s ? { ...s, [k]: v } : s));
  // The saved encrypted link, unless the user typed another address.
  const keepsLink = !!sub && encrypted === true && d.url === sub.url;
  const encryptedName = t("add.encryptedName");
  // The name the subscription gets when the field is left empty.
  const defaultName =
    d.provider?.title ||
    (keepsLink
      ? encryptedName
      : subscriptionNameFrom(
          d.url,
          urlCheck?.url === typedUrl ? urlCheck.check : null,
          encryptedName,
        ));
  const name = d.remarks.trim() || defaultName;
  const providerHours = d.providerIntervalHours ?? null;
  const ownInterval = providerHours == null || d.intervalOverride;
  const submit = async () => {
    const nextErrors: Record<string, string> = {};
    let url = d.url.trim();
    let saveName = name;
    // A new address is read the way the add sheet reads it.
    if (url && url !== sub?.url.trim()) {
      setSaving(true);
      const checked = await checkSubscriptionUrl(url, bridge);
      setSaving(false);
      if (checked.kind === "routing") nextErrors.url = t("subs.edit.routingLink");
      else if (checked.kind === "unsupported") nextErrors.url = t(UNSUPPORTED_TEXT[checked.reason]);
      else if (checked.kind === "url") {
        url = checked.url;
        if (!d.remarks.trim())
          saveName = d.provider?.title || subscriptionNameFrom(url, checked, encryptedName);
      }
    }
    if (!url) nextErrors.url = t("subs.edit.validationUrl");
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
    if (!groupChoiceReady(group, saveName)) nextErrors.group = t("groups.picker.needName");
    setErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;
    setSaving(true);
    try {
      // TLS verification is skipped only for localhost / private hosts (self-signed
      // certs are normal there); public URLs are always verified strictly.
      await onSave(
        {
          ...d,
          url,
          ...savedName(d.remarks, sub, saveName, defaultName),
          // An accepted provider `insecure` stays until the user turns it off below.
          allowInsecure: d.insecureByProvider ? d.allowInsecure : isLocalOrPrivateHost(url),
        },
        group,
      );
    } finally {
      setSaving(false);
    }
  };

  // Refused full Xray configs with no question left open: the user rejected it once.
  const configsRefused =
    !d.allowProviderConfigs &&
    d.lastErrorKind?.kind === "unsupportedPayload" &&
    !(d.pendingChanges ?? []).some((p) => p.action.kind === "allowProviderConfigs");
  // Saving the withdrawal removes the configs the provider already sent.
  const withdrawConfigs = async () => {
    const count = sub ? providerConfigsOf(profiles, sub).length : 0;
    const ok =
      count === 0 ||
      (await confirm({
        icon: "data_object",
        title: t("subs.edit.withdrawConfigsTitle"),
        body: t("subs.edit.withdrawConfigsBody", { count }),
        confirmLabel: t("subs.edit.stopUsing"),
      }));
    if (ok) set("allowProviderConfigs", false);
  };
  const reveal = async () => {
    if (!sub) return;
    try {
      setRevealed(await bridge.revealSubscriptionUrl(sub.url));
    } catch {
      notify(t("add.unsupported.urlDecrypt"));
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
      {sub && encrypted === true ? (
        <EncryptedUrl
          revealed={revealed}
          url={d.url === sub.url ? (revealed ?? "") : d.url}
          changed={d.url !== sub.url}
          error={errors.url}
          onReveal={() => void reveal()}
          // Typing the revealed address back keeps the encrypted link.
          onChange={(v) => set("url", revealed !== null && v.trim() === revealed ? sub.url : v)}
        />
      ) : encrypted === false ? (
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
      ) : null}
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
      <div style={{ marginBottom: 14, marginTop: 14 }}>
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
      {(d.fallbackUrl || d.insecureByProvider || d.allowProviderConfigs) && (
        <SettingGroup>
          <div style={{ fontSize: 12.5, fontWeight: 500, color: "var(--on-surface-variant)" }}>
            {t("subs.edit.fromProvider")}
          </div>
          {d.fallbackUrl && (
            <ProviderSetting
              icon="link"
              title={t("subs.changes.key.fallbackUrl")}
              value={d.fallbackUrl}
              action={t("subs.edit.remove")}
              onAction={() => set("fallbackUrl", null)}
            />
          )}
          {d.insecureByProvider && (
            <ProviderSetting
              icon="gpp_maybe"
              title={t("subs.edit.insecureByProvider")}
              action={t("subs.edit.checkTls")}
              onAction={() =>
                setD((s) => (s ? { ...s, insecureByProvider: false, allowInsecure: false } : s))
              }
            />
          )}
          {d.allowProviderConfigs && (
            <ProviderSetting
              icon="data_object"
              title={t("subs.edit.providerConfigs")}
              action={t("subs.edit.stopUsing")}
              onAction={() => void withdrawConfigs()}
            />
          )}
        </SettingGroup>
      )}
      {configsRefused && (
        <SettingGroup>
          <ProviderSetting
            icon="data_object"
            title={t("subs.edit.providerConfigsOff")}
            action={t("subs.edit.allow")}
            onAction={() => set("allowProviderConfigs", true)}
          />
        </SettingGroup>
      )}
      <Disclosure
        label={
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <Icon name="fingerprint" style={{ fontSize: 18 }} />
            {t("subs.identity.title")}
          </span>
        }
      >
        <SubIdentitySection
          sub={d}
          saved={!!sub}
          defaults={identityDefaults}
          onChange={(patch) => setD((s) => (s ? { ...s, ...patch } : s))}
        />
      </Disclosure>
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

/** A setting an accepted provider change made, with the way to undo it. */
function ProviderSetting({
  icon,
  title,
  value,
  action,
  onAction,
}: {
  icon: string;
  title: string;
  value?: string;
  action: string;
  onAction: () => void;
}) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0" }}>
      <Icon
        name={icon}
        style={{ fontSize: 20, color: "var(--on-surface-variant)", flexShrink: 0 }}
      />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13.5 }}>{title}</div>
        {value && (
          <div
            className="mono"
            dir="auto"
            style={{ fontSize: 11.5, color: "var(--on-surface-variant)", overflowWrap: "anywhere" }}
          >
            {value}
          </div>
        )}
      </div>
      <Btn variant="text" sm onClick={onAction}>
        {action}
      </Btn>
    </div>
  );
}

/** The URL row of an encrypted link: the link stays hidden until the user reveals it,
 *  and is saved as it was unless the revealed address is edited. */
function EncryptedUrl({
  revealed,
  url,
  changed,
  error,
  onReveal,
  onChange,
}: {
  revealed: string | null;
  url: string;
  changed: boolean;
  error?: string;
  onReveal: () => void;
  onChange: (v: string) => void;
}) {
  const t = useT();
  return (
    <div className="field">
      <div className="field-label">{t("subs.edit.url")}</div>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          padding: "10px 8px 10px 12px",
          background: "var(--sc-high)",
          borderRadius: 12,
        }}
      >
        <Icon name="lock" style={{ fontSize: 20, color: "var(--primary)", flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13.5, fontWeight: 500 }}>{t("subs.edit.encrypted")}</div>
          <div style={{ fontSize: 12, color: "var(--on-surface-variant)", lineHeight: 1.4 }}>
            {t("subs.edit.encryptedSub")}
          </div>
        </div>
        {revealed === null && (
          <Btn variant="text" sm icon="visibility" onClick={onReveal}>
            {t("subs.edit.reveal")}
          </Btn>
        )}
      </div>
      {revealed !== null && (
        <div style={{ marginTop: 10 }}>
          <Field
            label={t("subs.edit.revealedLabel")}
            value={url}
            area
            mono={false}
            onChange={onChange}
            error={error}
            hint={changed ? t("subs.edit.replacesEncrypted") : t("subs.edit.revealedHint")}
          />
        </div>
      )}
    </div>
  );
}
