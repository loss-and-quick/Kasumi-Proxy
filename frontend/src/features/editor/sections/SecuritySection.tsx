import { useState } from "react";
import {
  Btn,
  Dialog,
  Field,
  IconBtn,
  SectionLabel,
  Segmented,
  Select,
  SettingRow,
  Switch,
} from "../../../components";
import type { Endpoint, Security, Tls, TlsCertInfo } from "../../../generated/bindings";
import { FINGERPRINT_OPTS, SECURITY_OPTS } from "../../../generated/defaults";
import { useFormatters, useT } from "../../../i18n";
import { bridge } from "../../../lib/bridge-provider";
import { normalizeList, toText } from "../../../lib/utils";
import { useAppStore } from "../../../store/useAppStore";
import type { FieldErrors, TlsSetter } from "../types";

export function SecuritySection({
  tls,
  setTls,
  errors,
  isTls,
  isReality,
  isQuic,
  endpoint,
}: {
  tls: Tls;
  setTls: TlsSetter;
  errors: FieldErrors;
  isTls: boolean;
  isReality: boolean;
  isQuic: boolean;
  endpoint?: Endpoint;
}) {
  const t = useT();
  const { formatDateTime } = useFormatters();
  const notify = useAppStore((s) => s.notify);
  const [probing, setProbing] = useState(false);
  const [probed, setProbed] = useState<{
    cert: TlsCertInfo;
    host: string;
    port: number;
    sni: string | null;
    // Kept apart from `sni`: a profile with no SNI text and `disableSni` off sends
    // the server's own name, which is a different certificate than the probe without
    // one reaches.
    disableSni: boolean;
  } | null>(null);

  const handleProbeCert = async () => {
    const host = endpoint?.address?.trim();
    const port = endpoint?.port;
    if (!host || !port) {
      notify(t("editor.fetchCertMissingEndpoint"));
      return;
    }
    const disableSni = !!tls.disableSni;
    const sni = tls.disableSni ? null : tls.sni?.trim() || null;
    setProbing(true);
    try {
      const cert = await bridge.probeTlsCert({
        host,
        port,
        sni,
        insecure: true,
        disableSni: !!tls.disableSni,
      });
      setProbed({ cert, host, port, sni, disableSni });
    } catch (e) {
      notify(e instanceof Error ? e.message : t("editor.fetchCertFailed"));
    } finally {
      setProbing(false);
    }
  };

  const handleApply = () => {
    if (!probed) return;
    const currentHost = endpoint?.address?.trim() ?? "";
    const currentPort = endpoint?.port ?? 0;
    const currentDisableSni = !!tls.disableSni;
    const currentSni = tls.disableSni ? null : tls.sni?.trim() || null;
    if (
      currentHost !== probed.host ||
      currentPort !== probed.port ||
      currentSni !== probed.sni ||
      currentDisableSni !== probed.disableSni
    ) {
      notify(t("editor.tofu.targetMismatch"));
      setProbed(null);
      return;
    }
    setTls({ pcs: probed.cert.sha256Hex });
    setProbed(null);
  };

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
          <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <div style={{ flex: 1 }}>
              <Field
                label={t("settings.pinnedCert")}
                value={tls.pcs ?? ""}
                placeholder={t("settings.pinnedCertPh")}
                onChange={(value) => setTls({ pcs: value })}
                hint={t("settings.pinnedCertHint")}
              />
            </div>
            <div style={{ marginTop: 22 }}>
              <IconBtn
                name="download"
                title={t("editor.fetchCert")}
                spinning={probing}
                disabled={probing}
                onClick={handleProbeCert}
              />
            </div>
          </div>
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

      <Dialog
        open={!!probed}
        icon="fingerprint"
        iconColor={{ bg: "var(--primary-container)", fg: "var(--primary)" }}
        title={t("editor.tofu.title")}
        onClose={() => setProbed(null)}
        actions={
          <>
            <Btn variant="text" onClick={() => setProbed(null)}>
              {t("editor.tofu.cancel")}
            </Btn>
            <Btn variant="filled" onClick={handleApply}>
              {t("editor.tofu.apply")}
            </Btn>
          </>
        }
      >
        {probed && (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            <p style={{ margin: 0, fontSize: 13, color: "var(--on-surface-variant)" }}>
              {t("editor.tofu.description")}
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 13 }}>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: "var(--on-surface-variant)",
                    fontSize: 11,
                    textTransform: "uppercase",
                  }}
                >
                  {t("editor.tofu.endpoint")}
                </div>
                <div
                  style={{
                    color: "var(--on-surface)",
                    fontFamily: "var(--font-mono, monospace)",
                    fontSize: 12,
                    wordBreak: "break-all",
                  }}
                >
                  {probed.host}:{probed.port}
                  {probed.sni ? ` (${probed.sni})` : ""}
                </div>
              </div>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: "var(--on-surface-variant)",
                    fontSize: 11,
                    textTransform: "uppercase",
                  }}
                >
                  {t("editor.tofu.subject")}
                </div>
                <div style={{ color: "var(--on-surface)", wordBreak: "break-all" }}>
                  {probed.cert.subject}
                </div>
              </div>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: "var(--on-surface-variant)",
                    fontSize: 11,
                    textTransform: "uppercase",
                  }}
                >
                  {t("editor.tofu.issuer")}
                </div>
                <div style={{ color: "var(--on-surface)", wordBreak: "break-all" }}>
                  {probed.cert.issuer}
                </div>
              </div>
              {probed.cert.validUntil && (
                <div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: "var(--on-surface-variant)",
                      fontSize: 11,
                      textTransform: "uppercase",
                    }}
                  >
                    {t("editor.tofu.validUntil")}
                  </div>
                  <div style={{ color: "var(--on-surface)" }}>
                    {formatDateTime(new Date(probed.cert.validUntil))}
                  </div>
                </div>
              )}
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: "var(--on-surface-variant)",
                    fontSize: 11,
                    textTransform: "uppercase",
                  }}
                >
                  {t("editor.tofu.fingerprint")}
                </div>
                <div
                  style={{
                    fontFamily: "var(--font-mono, monospace)",
                    fontSize: 11,
                    color: "var(--primary)",
                    background: "var(--sc-lowest)",
                    padding: "6px 8px",
                    borderRadius: 6,
                    wordBreak: "break-all",
                    userSelect: "all",
                  }}
                >
                  {probed.cert.sha256Hex}
                </div>
              </div>
            </div>
          </div>
        )}
      </Dialog>
    </>
  );
}
