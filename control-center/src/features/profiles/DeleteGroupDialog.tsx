import { Btn, Dialog } from "../../components";
import { useT } from "../../i18n";
import type { Group } from "../../lib/schema";

export function DeleteGroupDialog({
  group,
  count,
  onClose,
  onConfirm,
}: {
  group: Group | null;
  count: number;
  onClose: () => void;
  onConfirm: (group: Group) => void;
}) {
  const t = useT();

  return (
    <Dialog
      open={!!group}
      icon="delete"
      iconColor={{ bg: "var(--error-container)", fg: "oklch(0.92 0.04 25)" }}
      title={t("profiles.confirmDelGroup.title")}
      onClose={onClose}
      actions={
        <>
          <Btn variant="text" onClick={onClose}>
            {t("profiles.confirmDelGroup.cancel")}
          </Btn>
          <Btn variant="error" onClick={() => group && onConfirm(group)}>
            {t("profiles.confirmDelGroup.delete")}
          </Btn>
        </>
      }
    >
      <b style={{ color: "var(--on-surface)" }}>{group?.name}</b>{" "}
      {t("profiles.confirmDelGroup.body", { count })}
    </Dialog>
  );
}
