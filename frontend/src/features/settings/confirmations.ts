// Questions asked before settings actions that can't be undone.
import { confirm } from "../../components";
import { translateCurrent } from "../../i18n";

/** Whether to delete the resource file named `name` (from the list and its sheet alike). */
export function confirmAssetDelete(name: string): Promise<boolean> {
  return confirm({
    title: translateCurrent("confirm.assetDelete.title"),
    body: name || undefined,
    confirmLabel: translateCurrent("assetSheet.delete"),
  });
}
