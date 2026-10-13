// ============================================================
// src/lib/startup.ts
// Desktop startup problems the shell reports instead of a usable data-path
// (Rust `StartupProblem`), and the quit the problem screen offers. Only the
// Tauri shell has these commands; the Android daemon is up before its UI.
// ============================================================

import type { StartupProblem } from "../generated/bindings";
import type { Vars } from "../i18n/runtime";
import type { DictKey } from "../i18n/types";

export type { StartupProblem };

function inTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

/** Resolves once startup is over: null when the data-path is ready. */
export async function startupProblem(): Promise<StartupProblem | null> {
  if (!inTauri()) return null;
  const { commands } = await import("../generated/bindings");
  return commands.startupProblem();
}

export async function quitApp(): Promise<void> {
  if (!inTauri()) return;
  const { commands } = await import("../generated/bindings");
  await commands.quit();
}

export interface StartupProblemText {
  title: string;
  body: string;
  detail: string;
}

export function startupProblemText(
  problem: StartupProblem,
  t: (key: DictKey, vars?: Vars) => string,
): StartupProblemText {
  switch (problem.kind) {
    case "helperOutdated":
      return {
        title: t("startup.helperOutdated.title"),
        body: t("startup.helperOutdated.body"),
        detail: t("startup.helperOutdated.detail", {
          app: problem.appProtocol,
          helper: problem.helperProtocol ?? t("startup.helperOutdated.noVersion"),
        }),
      };
  }
}
