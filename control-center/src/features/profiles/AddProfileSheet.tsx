import { Sheet, SheetAction } from "../../components";
import { useT } from "../../i18n";

export function AddProfileSheet({
  open,
  onClose,
  onManual,
  onPaste,
  onScanQr,
  onNewGroup,
}: {
  open: boolean;
  onClose: () => void;
  onManual: () => void;
  onPaste: () => void;
  onScanQr: () => void;
  onNewGroup: () => void;
}) {
  const t = useT();

  return (
    <Sheet open={open} title={t("profiles.add.title")} onClose={onClose}>
      <div style={{ display: "flex", flexDirection: "column" }}>
        <SheetAction
          icon="edit_note"
          label={t("profiles.add.manual")}
          sub={t("profiles.add.manualSub")}
          onClick={onManual}
        />
        <SheetAction
          icon="content_paste"
          label={t("profiles.add.paste")}
          sub={t("profiles.add.pasteSub")}
          onClick={onPaste}
        />
        <SheetAction
          icon="qr_code_scanner"
          label={t("profiles.add.scanQr")}
          sub={t("profiles.add.scanQrSub")}
          onClick={onScanQr}
        />
        <SheetAction
          icon="create_new_folder"
          label={t("profiles.add.newGroup")}
          onClick={onNewGroup}
        />
      </div>
    </Sheet>
  );
}
