import { useT } from "../../i18n";
import type { RequestIdentityDefaults, SubRequestOverrides, Subscription } from "../../lib/bridge";
import {
  type DeviceField,
  DeviceFields,
  detectedPlaceholders,
  HeaderPreview,
  HwidRow,
  IdentityFootnote,
  OverrideSwitch,
  ProviderAsks,
  UserAgentControl,
  useResolvedIdentity,
} from "./RequestIdentity";

/** One subscription's request identity: inherits Settings, overrides any part. */
export function SubIdentitySection({
  sub,
  saved,
  defaults,
  onChange,
}: {
  sub: Subscription;
  /** Whether `sub` is stored, so the provider's keys for it apply. */
  saved: boolean;
  defaults: RequestIdentityDefaults;
  onChange: (patch: Pick<Subscription, "request" | "userAgent">) => void;
}) {
  const t = useT();
  const request = sub.request ?? {};
  const view = useResolvedIdentity(saved ? sub.id : undefined, {
    defaults,
    request,
    userAgent: sub.userAgent,
  });
  const setRequest = (patch: Partial<SubRequestOverrides>) =>
    onChange({ request: { ...request, ...patch }, userAgent: sub.userAgent });
  const detected = detectedPlaceholders(view);
  // A blank field shows what it inherits: the Settings value, else the detected one.
  const inherited: Record<DeviceField, string> = {
    deviceOs: defaults.deviceOs || detected.deviceOs,
    osVersion: defaults.osVersion || detected.osVersion,
    deviceModel: defaults.deviceModel || detected.deviceModel,
    locale: defaults.locale || detected.locale,
  };
  const sentUa = view?.headers.find((h) => h.name.toLowerCase() === "user-agent")?.value;

  return (
    <>
      <ProviderAsks view={view} />
      <HwidRow
        view={view}
        value={request.hwid}
        expected="subscription"
        placeholder={defaults.hwid || view?.autoHwid || ""}
        onChange={(hwid) => setRequest({ hwid })}
      />
      <UserAgentControl
        value={sub.userAgent}
        defaultLabel={t("subs.identity.uaDefault")}
        sent={sentUa}
        onChange={(userAgent) => onChange({ request: sub.request, userAgent })}
      />
      <OverrideSwitch
        title={t("subs.identity.sendHwid")}
        hint={t("subs.identity.sendHwidSub")}
        value={request.sendHwid}
        inherited={defaults.sendHwid}
        onChange={(sendHwid) => setRequest({ sendHwid })}
      />
      <OverrideSwitch
        title={t("subs.identity.hwidInCookie")}
        hint={t("subs.identity.hwidInCookieSub")}
        value={request.hwidInCookie}
        inherited={defaults.hwidInCookie}
        onChange={(hwidInCookie) => setRequest({ hwidInCookie })}
      />
      <div style={{ height: 8 }} />
      <DeviceFields
        values={request}
        placeholders={inherited}
        onChange={(key, v) => setRequest({ [key]: v })}
      />
      <HeaderPreview view={view} />
      <IdentityFootnote />
    </>
  );
}
