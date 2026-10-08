import { Btn, Dialog } from "../../components";
import type { Group } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";

export function DeleteGroupDialog({
  group,
  count,
  subs = [],
  onClose,
  onConfirm,
}: {
  group: Group | null;
  count: number;
  /** Names of the subscriptions that fetch into the group; they move to Main. */
  subs?: string[];
  onClose: () => void;
  onConfirm: (group: Group) => void;
}) {
  const t = useT();
  const { formatList } = useFormatters();

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
      {subs.length > 0 && (
        <div style={{ marginTop: 8 }}>
          {t("profiles.confirmDelGroup.subsMoved", {
            count: subs.length,
            names: formatList(subs),
          })}
        </div>
      )}
    </Dialog>
  );
}
