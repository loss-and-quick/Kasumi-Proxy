import type { DictKey } from "../../i18n";

/** Settings categories, in list order. Each opens its own page; the id doubles as
 *  the `#settings/<id>` hash so a page can be linked to and left with Back. */
export const SETTINGS_PAGES = [
  { id: "routing", icon: "alt_route", titleKey: "settings.page.routing" },
  { id: "cores", icon: "memory", titleKey: "settings.page.cores" },
  { id: "network", icon: "dns", titleKey: "settings.page.network" },
  { id: "resources", icon: "folder_managed", titleKey: "settings.page.resources" },
  { id: "app", icon: "tune", titleKey: "settings.page.app" },
  { id: "about", icon: "info", titleKey: "settings.page.about" },
] as const satisfies readonly { id: string; icon: string; titleKey: DictKey }[];

export type SettingsPage = (typeof SETTINGS_PAGES)[number]["id"];

const isPage = (id: string): id is SettingsPage => SETTINGS_PAGES.some((p) => p.id === id);

/** The page named by the location hash (`#settings/<id>`), if any. */
export function pageFromHash(hash: string): SettingsPage | null {
  const id = hash.replace(/^#/, "").split("/")[1] ?? "";
  return isPage(id) ? id : null;
}
