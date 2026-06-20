import type { DictKey } from "../../i18n";

export type ResourceLinkId =
  | "geoip-loyal"
  | "geosite-loyal"
  | "geoip-ru"
  | "geosite-ru"
  | "geoip-ir"
  | "geosite-ir";

export type ResourceLink = {
  id: ResourceLinkId;
  labelKey: DictKey;
  noteKey: DictKey;
  remarks: string;
  url: string;
};

export const RESOURCE_LINKS = [
  {
    id: "geoip-loyal",
    labelKey: "settings.link.geoip-loyal.label",
    noteKey: "settings.link.geoip-loyal.note",
    remarks: "geoip.dat",
    url: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
  },
  {
    id: "geosite-loyal",
    labelKey: "settings.link.geosite-loyal.label",
    noteKey: "settings.link.geosite-loyal.note",
    remarks: "geosite.dat",
    url: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
  },
  {
    id: "geoip-ru",
    labelKey: "settings.link.geoip-ru.label",
    noteKey: "settings.link.geoip-ru.note",
    remarks: "geoip.dat",
    url: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
  },
  {
    id: "geosite-ru",
    labelKey: "settings.link.geosite-ru.label",
    noteKey: "settings.link.geosite-ru.note",
    remarks: "geosite.dat",
    url: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
  },
  {
    id: "geoip-ir",
    labelKey: "settings.link.geoip-ir.label",
    noteKey: "settings.link.geoip-ir.note",
    remarks: "geoip.dat",
    url: "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat",
  },
  {
    id: "geosite-ir",
    labelKey: "settings.link.geosite-ir.label",
    noteKey: "settings.link.geosite-ir.note",
    remarks: "geosite.dat",
    url: "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat",
  },
] satisfies ResourceLink[];
