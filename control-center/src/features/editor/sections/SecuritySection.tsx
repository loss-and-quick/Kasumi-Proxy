import { Field, SectionLabel, Select, Switch } from "../../../components";
import { useT } from "../../../i18n";
import { Fingerprint, Security } from "../../../lib/schema";
import type { FieldErrors, ProfileSetter, ProfileView } from "../types";

export function SecuritySection({
  v,
  set,
  errors,
  isTls,
  isReality,
  isQuic,
}: {
  v: ProfileView;
  set: ProfileSetter;
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
          value={v.security ?? "none"}
          options={Security.options}
          onChange={(value) => set({ security: value })}
        />
      )}
      {(isTls || isReality || isQuic) && (
        <>
          <Field
            label={t("editor.sni")}
            value={v.sni ?? ""}
            onChange={(value) => set({ sni: value })}
            error={errors.sni}
          />
          <Select
            label={t("editor.fingerprint")}
            value={v.fingerprint ?? "chrome"}
            options={Fingerprint.options}
            onChange={(value) => set({ fingerprint: value })}
          />
          <Field
            label={t("editor.alpn")}
            value={v.alpn ?? ""}
            onChange={(value) => set({ alpn: value })}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.tlsMinVersion")}
              mono={false}
              value={v.tlsMinVersion ?? ""}
              onChange={(value) => set({ tlsMinVersion: value })}
            />
            <Field
              label={t("editor.tlsMaxVersion")}
              mono={false}
              value={v.tlsMaxVersion ?? ""}
              onChange={(value) => set({ tlsMaxVersion: value })}
            />
          </div>
          <Field
            label={t("editor.tlsCipherSuites")}
            mono={false}
            value={v.tlsCipherSuites ?? ""}
            onChange={(value) => set({ tlsCipherSuites: value })}
          />
          <Field
            label={t("editor.tlsCurvePreferences")}
            mono={false}
            value={v.tlsCurvePreferences ?? ""}
            onChange={(value) => set({ tlsCurvePreferences: value })}
          />
          <Field
            area
            label={t("editor.tlsCertChain")}
            mono={false}
            value={v.cert ?? ""}
            onChange={(value) => set({ cert: value })}
          />
        </>
      )}
      {isTls && (
        <>
          <Field
            label={t("settings.pinnedCert")}
            value={v.pcs ?? ""}
            placeholder={t("settings.pinnedCertPh")}
            onChange={(value) => set({ pcs: value })}
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
            <Switch on={!!v.allowInsecure} onChange={(value) => set({ allowInsecure: value })} />
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
            <Switch on={!!v.disableSni} onChange={(value) => set({ disableSni: value })} />
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
              on={!!v.disableSystemRoot}
              onChange={(value) => set({ disableSystemRoot: value })}
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
              on={!!v.rejectUnknownSni}
              onChange={(value) => set({ rejectUnknownSni: value })}
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
              on={!!v.enableSessionResumption}
              onChange={(value) => set({ enableSessionResumption: value })}
            />
          </div>
        </>
      )}
      {isReality && (
        <>
          <Field
            label={t("editor.publicKey")}
            value={v.publicKey ?? ""}
            onChange={(value) => set({ publicKey: value })}
            error={errors.publicKey}
          />
          <div className="input-row" style={{ marginBottom: 14 }}>
            <Field
              label={t("editor.shortId")}
              value={v.shortId ?? ""}
              onChange={(value) => set({ shortId: value })}
            />
            <Field
              label={t("editor.spiderX")}
              value={v.spiderX ?? ""}
              onChange={(value) => set({ spiderX: value })}
            />
          </div>
        </>
      )}
    </>
  );
}
