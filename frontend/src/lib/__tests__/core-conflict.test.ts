import { describe, expect, it } from "vitest";
import { translate } from "../../i18n";
import { coreConflictText } from "../core-conflict";

describe("coreConflictText", () => {
  it("names the editor fields that fix an unpinned insecure profile", () => {
    const text = coreConflictText((key, vars) => translate("en", key, vars), {
      kind: "unpinnedInsecureTls",
    });
    expect(text).toContain("“Pinned certificate (SHA-256)”");
    expect(text).toContain("“Allow insecure”");
  });
});
