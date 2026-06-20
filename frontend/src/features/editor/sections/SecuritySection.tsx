import { Field, SectionLabel, Select, Switch } from "../../../components";
import type { Security, Tls } from "../../../generated/bindings";
import { FINGERPRINT_OPTS, SECURITY_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import type { FieldErrors, TlsSetter } from "../types";

const fromList = (list?: string[]) => (list ?? []).join(", ");
const toList = (s: string) => s.split(/[\s,]+/).filter(Boolean);

export function SecuritySection({
  tls,
  setTls,
  errors,
  isTls,
  isReality,
  isQuic,
}: {
  tls: Tls;
  setTls: TlsSetter;
  errors: FieldErrors;
  isTls: boolean;
  isReality: boolean;
  isQuic: boolean;
}) {
  const t = useT();

  return (
    <>
      <SectionLabel>{t("editor.security")}</SectionLabel>
      {!isQuic && (
        <Select
          label={t("editor.tlsSecurity")}
          value={tls.security ?? "none"}
          options={SECURITY_OPTS}
          onChange={(value) => setTls({ security: value as Security })}
        />
      )}
      {(isTls || isReality || isQuic) && (
        <>
          <Field
            label={t("editor.sni")}
            value={tls.sni ?? ""}
            onChange={(value) => setTls({ sni: value })}
            error={errors.sni}
          />
          <Select
            label={t("editor.fingerprint")}
            value={tls.fingerprint ?? "chrome"}
            options={FINGERPRINT_OPTS}
            onChange={(value) => setTls({ fingerprint: value })}
          />
          <Field
            label={t("editor.alpn")}
            value={fromList(tls.alpn)}
            onChange={(value) => setTls({ alpn: toList(value) })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.tlsMinVersion")}
              mono={false}
              value={tls.tlsMinVersion ?? ""}
              onChange={(value) => setTls({ tlsMinVersion: value })}
            />
            <Field
              label={t("editor.tlsMaxVersion")}
              mono={false}
              value={tls.tlsMaxVersion ?? ""}
              onChange={(value) => setTls({ tlsMaxVersion: value })}
            />
          </div>
          <Field
            label={t("editor.tlsCipherSuites")}
            mono={false}
            value={fromList(tls.tlsCipherSuites)}
            onChange={(value) => setTls({ tlsCipherSuites: toList(value) })}
          />
          <Field
            label={t("editor.tlsCurvePreferences")}
            mono={false}
            value={fromList(tls.tlsCurvePreferences)}
            onChange={(value) => setTls({ tlsCurvePreferences: toList(value) })}
          />
          <Field
            area
            label={t("editor.tlsCertChain")}
            mono={false}
            value={tls.cert ?? ""}
            onChange={(value) => setTls({ cert: value })}
          />
        </>
      )}
      {isTls && (
        <>
          <Field
            label={t("settings.pinnedCert")}
            value={tls.pcs ?? ""}
            placeholder={t("settings.pinnedCertPh")}
            onChange={(value) => setTls({ pcs: value })}
            hint={t("settings.pinnedCertHint")}
          />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.allowInsecure")}
            </span>
            <Switch
              on={!!tls.allowInsecure}
              onChange={(value) => setTls({ allowInsecure: value })}
            />
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.tlsDisableSni")}
            </span>
            <Switch on={!!tls.disableSni} onChange={(value) => setTls({ disableSni: value })} />
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.tlsDisableSystemRoot")}
            </span>
            <Switch
              on={!!tls.disableSystemRoot}
              onChange={(value) => setTls({ disableSystemRoot: value })}
            />
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.tlsRejectUnknownSni")}
            </span>
            <Switch
              on={!!tls.rejectUnknownSni}
              onChange={(value) => setTls({ rejectUnknownSni: value })}
            />
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 0",
            }}
          >
            <span style={{ fontSize: 14, color: "var(--on-surface)" }}>
              {t("editor.tlsEnableSessionResumption")}
            </span>
            <Switch
              on={!!tls.enableSessionResumption}
              onChange={(value) => setTls({ enableSessionResumption: value })}
            />
          </div>
        </>
      )}
      {isReality && (
        <>
          <Field
            label={t("editor.publicKey")}
            value={tls.publicKey ?? ""}
            onChange={(value) => setTls({ publicKey: value })}
            error={errors.publicKey}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.shortId")}
              value={tls.shortId ?? ""}
              onChange={(value) => setTls({ shortId: value })}
            />
            <Field
              label={t("editor.spiderX")}
              value={tls.spiderX ?? ""}
              onChange={(value) => setTls({ spiderX: value })}
            />
          </div>
        </>
      )}
    </>
  );
}
