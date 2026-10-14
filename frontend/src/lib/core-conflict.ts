import type { CoreConflict } from "../generated/bindings";
import type { Translate } from "../i18n";

/** Why a profile can't start, naming what to change in its editor. */
export function coreConflictText(t: Translate, conflict: CoreConflict): string {
  switch (conflict.kind) {
    case "unpinnedInsecureTls":
      return t("profiles.conflict.unpinnedInsecureTls", {
        pin: t("settings.pinnedCert"),
        insecure: t("editor.allowInsecure"),
      });
    case "customAllowInsecure":
      // Xray JSON keys, shown as the user finds them in the raw config.
      return t("profiles.conflict.customAllowInsecure", {
        insecure: "allowInsecure",
        pin: "pinnedPeerCertSha256",
      });
    case "chainCoreConflict":
      return t("editor.engineChainConflict", {
        xray: conflict.xray,
        singBox: conflict.singBox,
      });
  }
}
