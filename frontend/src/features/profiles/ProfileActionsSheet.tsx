import { Sheet, SheetAction } from "../../components";
import type { Profile } from "../../generated/bindings";
import { useT } from "../../i18n";

export function ProfileActionsSheet({
  profile,
  onClose,
  onUse,
  onEdit,
  onClone,
  onShare,
  onShowQr,
  onPing,
  onRealPing,
  onSpeedTest,
  onDelete,
  pinging,
  speedTesting,
}: {
  profile: Profile | null;
  onClose: () => void;
  onUse: (profile: Profile) => void;
  onEdit: (profile: Profile) => void;
  onClone: (profile: Profile) => void;
  onShare: (profile: Profile) => void;
  onShowQr: (profile: Profile) => void;
  onPing: (profile: Profile) => void;
  onRealPing: (profile: Profile) => void;
  onSpeedTest: (profile: Profile) => void;
  onDelete: (profile: Profile) => void;
  pinging: boolean;
  speedTesting: boolean;
}) {
  const t = useT();
  // Any test in progress contends for a core / the exec channel, so block every
  // test action while one runs — not just the matching category.
  const busy = pinging || speedTesting;

  return (
    <Sheet open={!!profile} title={profile?.meta.remarks} onClose={onClose}>
      {profile && (
        <div style={{ display: "flex", flexDirection: "column" }}>
          <SheetAction
            icon="check_circle"
            label={t("profiles.sheet.useProfile")}
            onClick={() => onUse(profile)}
          />
          <SheetAction
            icon="edit"
            label={t("profiles.sheet.edit")}
            onClick={() => onEdit(profile)}
          />
          <SheetAction
            icon="content_copy"
            label={t("profiles.sheet.clone")}
            onClick={() => onClone(profile)}
          />
          <SheetAction
            icon="ios_share"
            label={t("profiles.sheet.share")}
            onClick={() => onShare(profile)}
          />
          <SheetAction
            icon="qr_code_2"
            label={t("profiles.sheet.qr")}
            onClick={() => onShowQr(profile)}
          />
          <SheetAction
            icon="lan"
            label={t("profiles.sheet.latency")}
            onClick={() => onPing(profile)}
            disabled={busy}
          />
          <SheetAction
            icon="travel_explore"
            label={t("profiles.sheet.realLatency")}
            onClick={() => onRealPing(profile)}
            disabled={busy}
          />
          <SheetAction
            icon="speed"
            label={t("profiles.sheet.speedtest")}
            onClick={() => onSpeedTest(profile)}
            disabled={busy}
          />
          <div className="divider" />
          <SheetAction
            icon="delete"
            label={t("profiles.sheet.delete")}
            danger
            onClick={() => onDelete(profile)}
          />
        </div>
      )}
    </Sheet>
  );
}
