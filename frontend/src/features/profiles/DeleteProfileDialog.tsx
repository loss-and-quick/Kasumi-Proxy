import { Btn, Dialog } from "../../components";
import type { Profile } from "../../generated/bindings";
import { useT } from "../../i18n";

export function DeleteProfileDialog({
  profile,
  onClose,
  onConfirm,
}: {
  profile: Profile | null;
  onClose: () => void;
  onConfirm: (profile: Profile) => void;
}) {
  const t = useT();

  return (
    <Dialog
      open={!!profile}
      icon="delete"
      iconColor={{ bg: "var(--error-container)", fg: "oklch(0.92 0.04 25)" }}
      title={t("profiles.confirmDel.title")}
      onClose={onClose}
      actions={
        <>
          <Btn variant="text" onClick={onClose}>
            {t("profiles.confirmDel.cancel")}
          </Btn>
          <Btn variant="error" onClick={() => profile && onConfirm(profile)}>
            {t("profiles.confirmDel.delete")}
          </Btn>
        </>
      }
    >
      <b style={{ color: "var(--on-surface)" }}>{profile?.meta.remarks}</b>{" "}
      {t("profiles.confirmDel.body")}
    </Dialog>
  );
}
