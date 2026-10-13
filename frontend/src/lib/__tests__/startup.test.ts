import { describe, expect, it } from "vitest";
import { loadLocale, translate } from "../../i18n";
import type { Vars } from "../../i18n/runtime";
import type { DictKey } from "../../i18n/types";
import { startupProblem, startupProblemText } from "../startup";

const en = (key: DictKey, vars?: Vars) => translate("en", key, vars);

describe("startupProblemText", () => {
  it("names both protocol versions of an outdated helper", () => {
    const text = startupProblemText(
      { kind: "helperOutdated", appProtocol: 2, helperProtocol: 1 },
      en,
    );
    expect(text.title).toBe("The helper is from another version");
    expect(text.body).toContain("reinstall");
    expect(text.detail).toBe("App protocol 2, helper protocol 1");
  });

  it("says so when the helper predates the versioned handshake", () => {
    const text = startupProblemText(
      { kind: "helperOutdated", appProtocol: 1, helperProtocol: null },
      en,
    );
    expect(text.detail).toBe("App protocol 1, helper protocol none");
  });

  it("is translated", async () => {
    await loadLocale("ru");
    const text = startupProblemText(
      { kind: "helperOutdated", appProtocol: 1, helperProtocol: null },
      (key, vars) => translate("ru", key, vars),
    );
    expect(text.detail).toBe("Протокол приложения: 1, компонента: не указан");
  });
});

describe("startupProblem", () => {
  it("reports nothing outside the desktop shell", async () => {
    await expect(startupProblem()).resolves.toBeNull();
  });
});
