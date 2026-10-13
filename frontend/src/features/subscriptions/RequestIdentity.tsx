// The pieces of the request-identity UI shared by the subscription sheet and the
// Settings defaults: the HWID row, the switches, the device fields and the preview of
// the headers a fetch sends (as the backend builds them).
import { type ReactNode, useEffect, useRef, useState } from "react";
import { Field, Icon, IconBtn, Segmented, SettingRow, Switch } from "../../components";
import { type DictKey, useT } from "../../i18n";
import type { HwidSource, IdentityInput, ResolvedIdentity } from "../../lib/bridge";
import { bridge } from "../../lib/bridge-provider";
import { useAppStore } from "../../store/useAppStore";
import { copyText } from "../profiles/clipboard";
import { HWID_SOURCE_KEY, hwidRejected, providerAsks, typed } from "./identity";

/** The identity `input` resolves to, refreshed shortly after each edit. */
export function useResolvedIdentity(
  subId: string | undefined,
  input: IdentityInput,
): ResolvedIdentity | null {
  const [view, setView] = useState<ResolvedIdentity | null>(null);
  const latest = useRef(input);
  latest.current = input;
  const key = JSON.stringify(input);
  // biome-ignore lint/correctness/useExhaustiveDependencies: `key` stands for `input`'s contents.
  useEffect(() => {
    let live = true;
    const timer = setTimeout(() => {
      bridge
        .resolveRequestIdentity({ subId, input: latest.current })
        .then((v) => {
          if (live) setView(v);
        })
        .catch(() => {});
    }, 250);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [subId, key]);
  return view;
}

/** The HWID a fetch sends, where it comes from, and a field to type another. */
export function HwidRow({
  view,
  value,
  expected,
  placeholder,
  onChange,
  commitOnBlur,
}: {
  view: ResolvedIdentity | null;
  /** The HWID typed at this level, if any. */
  value: string | null | undefined;
  expected: HwidSource;
  placeholder: string;
  onChange: (v: string | undefined) => void;
  commitOnBlur?: boolean;
}) {
  const t = useT();
  const notify = useAppStore((s) => s.notify);
  const [editing, setEditing] = useState(false);
  const rejected = hwidRejected(value, expected, view);
  const copy = async () => {
    if (!view) return;
    notify((await copyText(view.hwid)) ? t("subs.identity.copied") : view.hwid);
  };
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 0" }}>
        <div className="lr-icon" style={{ flexShrink: 0 }}>
          <Icon name="fingerprint" />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="sr-title" style={{ fontSize: "var(--fs-title)", fontWeight: 500 }}>
            {t("subs.identity.hwid")}
          </div>
          <div className="mono" style={{ fontSize: 14, overflowWrap: "anywhere", marginTop: 2 }}>
            {view?.hwid ?? "…"}
          </div>
          {view && <div className="hint">{t(HWID_SOURCE_KEY[view.hwidSource])}</div>}
        </div>
        <IconBtn
          sm
          name="content_copy"
          title={t("subs.identity.copy")}
          onClick={() => void copy()}
        />
        <IconBtn
          sm
          name="edit"
          title={t("subs.identity.edit")}
          onClick={() => setEditing((v) => !v)}
        />
        {value?.trim() && (
          <IconBtn
            sm
            name="restart_alt"
            title={t("subs.identity.reset")}
            onClick={() => {
              onChange(undefined);
              setEditing(false);
            }}
          />
        )}
      </div>
      {(editing || rejected) && (
        <div style={{ marginBottom: 10 }}>
          <Field
            value={value ?? ""}
            placeholder={placeholder}
            commitOnBlur={commitOnBlur}
            onChange={(v) => onChange(typed(v))}
            error={rejected ? t("subs.identity.hwidInvalid") : undefined}
          />
        </div>
      )}
    </>
  );
}

/** A switch that is either inherited (`value` unset) or set at this level. */
export function OverrideSwitch({
  title,
  hint,
  value,
  inherited,
  onChange,
}: {
  title: string;
  hint: string;
  value: boolean | null | undefined;
  inherited: boolean;
  onChange: (v: boolean | undefined) => void;
}) {
  const t = useT();
  const own = value != null;
  return (
    <SettingRow
      title={title}
      hint={`${hint} · ${own ? t("subs.identity.thisSub") : t("subs.identity.fromSettings")}`}
    >
      {own && (
        <IconBtn
          sm
          name="restart_alt"
          title={t("subs.identity.reset")}
          onClick={() => onChange(undefined)}
        />
      )}
      <Switch on={value ?? inherited} onChange={onChange} label={title} />
    </SettingRow>
  );
}

/** User-Agent: the default one or the user's own. */
export function UserAgentControl({
  value,
  defaultLabel,
  sent,
  onChange,
  commitOnBlur,
}: {
  value: string;
  defaultLabel: string;
  /** The User-Agent the preview shows going out. */
  sent: string | undefined;
  onChange: (v: string) => void;
  commitOnBlur?: boolean;
}) {
  const t = useT();
  const [custom, setCustom] = useState(value.trim() !== "");
  return (
    <div className="field">
      <Segmented
        label={t("subs.identity.ua")}
        options={[
          { value: "default", label: defaultLabel },
          { value: "custom", label: t("subs.identity.uaCustom") },
        ]}
        value={custom ? "custom" : "default"}
        onChange={(v) => {
          setCustom(v === "custom");
          if (v === "default") onChange("");
        }}
      />
      {custom ? (
        <div style={{ marginTop: 10 }}>
          <Field
            value={value}
            mono
            commitOnBlur={commitOnBlur}
            placeholder={sent}
            onChange={onChange}
            hint={t("subs.identity.uaHint")}
          />
        </div>
      ) : (
        sent && (
          <div className="hint mono" style={{ marginTop: 6, overflowWrap: "anywhere" }}>
            {sent}
          </div>
        )
      )}
    </div>
  );
}

export type DeviceField = "deviceOs" | "osVersion" | "deviceModel" | "locale";

const DEVICE_FIELDS: { key: DeviceField; label: DictKey }[] = [
  { key: "deviceOs", label: "subs.identity.deviceOs" },
  { key: "osVersion", label: "subs.identity.osVersion" },
  { key: "deviceModel", label: "subs.identity.model" },
  { key: "locale", label: "subs.identity.locale" },
];

/** OS, version, model and language; a blank field inherits its placeholder. */
export function DeviceFields({
  values,
  placeholders,
  onChange,
  commitOnBlur,
}: {
  values: Partial<Record<DeviceField, string | null>>;
  placeholders: Record<DeviceField, string>;
  onChange: (key: DeviceField, v: string | undefined) => void;
  commitOnBlur?: boolean;
}) {
  const t = useT();
  const rows = [DEVICE_FIELDS.slice(0, 2), DEVICE_FIELDS.slice(2)];
  return (
    <>
      {rows.map((row) => (
        <div className="input-row" key={row[0].key} style={{ marginBottom: 10 }}>
          {row.map((f) => (
            <Field
              key={f.key}
              label={t(f.label)}
              value={values[f.key] ?? ""}
              mono={false}
              commitOnBlur={commitOnBlur}
              placeholder={placeholders[f.key]}
              onChange={(v) => onChange(f.key, typed(v))}
            />
          ))}
        </div>
      ))}
    </>
  );
}

/** The detected device, as placeholders for [`DeviceFields`]. */
export function detectedPlaceholders(view: ResolvedIdentity | null): Record<DeviceField, string> {
  return {
    deviceOs: view?.facts.os ?? "",
    osVersion: view?.facts.osVersion ?? "",
    deviceModel: view?.facts.model ?? "",
    locale: view?.facts.locale ?? "",
  };
}

/** What the provider's keys ask for; the switches above still decide. */
export function ProviderAsks({ view }: { view: ResolvedIdentity | null }) {
  const t = useT();
  const asks = providerAsks(view);
  if (!asks.length) return null;
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        padding: "10px 12px",
        margin: "4px 0 8px",
        background: "var(--primary-container)",
        color: "var(--on-primary-container)",
        border: "1px solid transparent",
        borderRadius: 12,
        fontSize: 13,
        lineHeight: 1.45,
      }}
    >
      <Icon name="campaign" style={{ fontSize: 18, color: "var(--primary)", flexShrink: 0 }} />
      <div style={{ minWidth: 0 }}>
        {asks.map((k) => (
          <div key={k}>{t(k)}</div>
        ))}
        <div style={{ opacity: 0.8, marginTop: 2 }}>{t("subs.identity.providerYouDecide")}</div>
      </div>
    </div>
  );
}

/** The headers a fetch sends, in order, exactly as the backend built them. */
export function HeaderPreview({ view }: { view: ResolvedIdentity | null }) {
  const t = useT();
  return (
    <div className="field" style={{ marginTop: 6 }}>
      <div className="field-label">{t("subs.identity.headers")}</div>
      <div
        className="mono"
        dir="ltr"
        style={{
          background: "var(--sc)",
          borderRadius: 10,
          padding: "8px 10px",
          fontSize: 12,
          lineHeight: 1.6,
          minHeight: 40,
        }}
      >
        {view?.headers.map((h) => (
          <div key={h.name} style={{ overflowWrap: "anywhere" }}>
            <span style={{ color: "var(--primary)" }}>{h.name}</span>: {h.value}
          </div>
        ))}
      </div>
      <div className="hint" style={{ marginTop: 6 }}>
        {t("subs.identity.headersNote")}
        {view?.cookieJar ? ` ${t("subs.identity.cookieJarOn")}` : ""}
      </div>
    </div>
  );
}

/** Which Happ release the identity matches, and what sending it means. */
export function IdentityFootnote({ extra }: { extra?: ReactNode }) {
  const t = useT();
  return (
    <div
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        marginTop: 10,
        fontSize: 12.5,
        color: "var(--on-surface-variant)",
        lineHeight: 1.5,
      }}
    >
      <Icon name="info" style={{ fontSize: 18, color: "var(--on-surface-faint)", flexShrink: 0 }} />
      <div>
        {t("subs.identity.compat")} {t("subs.identity.privacy")}
        {extra}
      </div>
    </div>
  );
}
