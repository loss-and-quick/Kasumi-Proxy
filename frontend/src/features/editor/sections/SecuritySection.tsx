import { Field, SectionLabel, Segmented, Select, SettingRow, Switch } from "../../../components";
import type { Security, Tls } from "../../../generated/bindings";
import { FINGERPRINT_OPTS, SECURITY_OPTS } from "../../../generated/defaults";
import { useT } from "../../../i18n";
import { normalizeList, toText } from "../../../lib/utils";
import type { FieldErrors, TlsSetter } from "../types";

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
        <Segmented
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
            area
            label={t("editor.alpn")}
            value={toText(tls.alpn)}
            onChange={(value) => setTls({ alpn: normalizeList(value) })}
            hint={t("editor.alpnHint")}
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
            area
            label={t("editor.tlsCipherSuites")}
            mono={false}
            value={toText(tls.tlsCipherSuites)}
            onChange={(value) => setTls({ tlsCipherSuites: normalizeList(value) })}
            hint={t("editor.tlsCipherSuitesHint")}
          />
          <Field
            area
            label={t("editor.tlsCurvePreferences")}
            mono={false}
            value={toText(tls.tlsCurvePreferences)}
            onChange={(value) => setTls({ tlsCurvePreferences: normalizeList(value) })}
            hint={t("editor.tlsCurvePreferencesHint")}
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
          <SettingRow title={t("editor.allowInsecure")}>
            <Switch
              on={!!tls.allowInsecure}
              onChange={(value) => setTls({ allowInsecure: value })}
            />
          </SettingRow>
          <SettingRow title={t("editor.tlsDisableSni")}>
            <Switch on={!!tls.disableSni} onChange={(value) => setTls({ disableSni: value })} />
          </SettingRow>
          <SettingRow title={t("editor.tlsDisableSystemRoot")}>
            <Switch
              on={!!tls.disableSystemRoot}
              onChange={(value) => setTls({ disableSystemRoot: value })}
            />
          </SettingRow>
          <SettingRow title={t("editor.tlsRejectUnknownSni")}>
            <Switch
              on={!!tls.rejectUnknownSni}
              onChange={(value) => setTls({ rejectUnknownSni: value })}
            />
          </SettingRow>
          <SettingRow title={t("editor.tlsEnableSessionResumption")}>
            <Switch
              on={!!tls.enableSessionResumption}
              onChange={(value) => setTls({ enableSessionResumption: value })}
            />
          </SettingRow>
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
