import type { Subscription } from "../../lib/bridge";

/** The name the edit sheet saves and whether the user typed it. An untouched name
 *  goes back as it was opened, so the save leaves the stored one alone and a
 *  provider title that arrived meanwhile stands. */
export function savedName(
  typed: string,
  opened: Subscription | null,
  name: string,
  defaultName: string,
): Pick<Subscription, "remarks" | "manualTitle"> {
  if (opened && typed === opened.remarks)
    return { remarks: opened.remarks, manualTitle: opened.manualTitle };
  const own = typed.trim();
  // A name the user typed survives the provider's title; the default does not.
  return { remarks: name, manualTitle: own !== "" && own !== defaultName };
}
