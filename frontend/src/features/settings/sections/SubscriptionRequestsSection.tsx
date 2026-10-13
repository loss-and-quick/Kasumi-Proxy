import { Card, NumberInput, RowToggle, SectionLabel, SettingRow } from "../../../components";
import { useT } from "../../../i18n";
import type { AdvancedSettings, RequestIdentityDefaults } from "../../../lib/bridge";
import { getRuntimeBridgeMode } from "../../../lib/ksu-webui";
import {
  DeviceFields,
  detectedPlaceholders,
  HeaderPreview,
  HwidRow,
  IdentityFootnote,
  UserAgentControl,
  useResolvedIdentity,
} from "../../subscriptions/RequestIdentity";

/** What every subscription fetch sends unless the subscription says otherwise. */
export function SubscriptionRequestsSection({
  settings,
  set,
}: {
  settings: AdvancedSettings;
  set: <K extends keyof AdvancedSettings>(key: K, value: AdvancedSettings[K]) => void;
}) {
  const t = useT();
  const id = settings.requestIdentity;
  const view = useResolvedIdentity(undefined, { defaults: id, request: {}, userAgent: "" });
  const patch = (p: Partial<RequestIdentityDefaults>) => set("requestIdentity", { ...id, ...p });
  const desktop = getRuntimeBridgeMode() === "tauri";
  const sentUa = view?.headers.find((h) => h.name.toLowerCase() === "user-agent")?.value;

  return (
    <>
      <SectionLabel>{t("settings.identity.title")}</SectionLabel>
      <Card style={{ padding: "6px 14px 14px" }}>
        <div className="hint" style={{ padding: "6px 0 2px" }}>
          {t("settings.identity.sub")}
        </div>
        <HwidRow
          view={view}
          value={id.hwid}
          expected="settings"
          placeholder={view?.autoHwid ?? ""}
          commitOnBlur
          onChange={(hwid) => patch({ hwid })}
        />
        <UserAgentControl
          value={id.userAgent}
          defaultLabel={t("subs.identity.uaHapp")}
          sent={sentUa}
          commitOnBlur
          onChange={(userAgent) => patch({ userAgent })}
        />
        <RowToggle
          icon="devices"
          title={t("subs.identity.sendHwid")}
          sub={t("subs.identity.sendHwidSub")}
          on={id.sendHwid}
          onChange={(sendHwid) => patch({ sendHwid })}
        />
        <RowToggle
          icon="fingerprint"
          title={t("subs.identity.hwidInCookie")}
          sub={t("subs.identity.hwidInCookieSub")}
          on={id.hwidInCookie}
          onChange={(hwidInCookie) => patch({ hwidInCookie })}
        />
        <RowToggle
          icon="cookie"
          title={t("settings.identity.cookieJar")}
          sub={t("settings.identity.cookieJarSub")}
          on={id.cookieJar}
          onChange={(cookieJar) => patch({ cookieJar })}
        />
        <div style={{ height: 8 }} />
        <DeviceFields
          values={id}
          placeholders={detectedPlaceholders(view)}
          commitOnBlur
          onChange={(key, v) => patch({ [key]: v })}
        />
        {!desktop && (
          <SettingRow
            title={t("settings.identity.androidUser")}
            hint={t("settings.identity.androidUserSub")}
          >
            <NumberInput
              value={id.androidUser}
              ariaLabel={t("settings.identity.androidUser")}
              style={{ width: 72 }}
              onCommit={(n) => patch({ androidUser: Math.max(0, Math.trunc(n)) })}
            />
          </SettingRow>
        )}
        <HeaderPreview view={view} />
        <IdentityFootnote extra={desktop ? ` ${t("settings.identity.desktopInferred")}` : null} />
      </Card>
    </>
  );
}
