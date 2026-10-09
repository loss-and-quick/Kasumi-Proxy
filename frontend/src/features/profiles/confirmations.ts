// Questions asked before profile actions that can't be undone.
import { confirm } from "../../components";
import { translateCurrent } from "../../i18n";
import { unreachableIds, useAppStore } from "../../store/useAppStore";

/** Whether to go on with deleting the group's unreachable profiles. With none
 *  there is nothing to ask; the store reports that itself. */
export async function askRemoveUnreachable(groupId?: string): Promise<boolean> {
  const { profiles, testResults } = useAppStore.getState();
  const count = unreachableIds(profiles, testResults, groupId).size;
  if (!count) return true;
  return confirm({
    icon: "wifi_off",
    title: translateCurrent("confirm.unreachable.title", { count }),
    body: translateCurrent("confirm.unreachable.body"),
    confirmLabel: translateCurrent("profiles.confirmDel.delete"),
  });
}
