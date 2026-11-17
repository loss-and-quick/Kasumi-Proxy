import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { UpdatePolicy } from "../../../lib/updater";
import { AboutCard, type UpdateStatus } from "../sections/AboutSection";

function renderAbout(opts: {
  version?: string;
  policy: UpdatePolicy | null;
  status?: UpdateStatus;
  availableVersion?: string | null;
  percent?: number;
}) {
  return renderToStaticMarkup(
    <AboutCard
      version={opts.version ?? "0.4.6"}
      policy={opts.policy}
      status={opts.status ?? "idle"}
      availableVersion={opts.availableVersion ?? null}
      percent={opts.percent ?? 0}
      onCheck={() => {}}
      onInstall={() => {}}
    />,
  );
}

describe("AboutCard", () => {
  it("shows a passive package-manager notice without an update action when externally managed", () => {
    const html = renderAbout({ policy: "externallyManaged" });
    expect(html).toContain("0.4.6");
    expect(html).toContain("settings.updateManagedExternally");
    expect(html).not.toContain("settings.checkUpdates");
    expect(html).not.toContain("settings.updateInstall");
    expect(html).not.toContain("<button");
  });

  it("shows a passive portable notice without an update action on portable builds", () => {
    const html = renderAbout({ policy: "portable" });
    expect(html).toContain("0.4.6");
    expect(html).toContain("settings.updatePortable");
    expect(html).not.toContain("settings.checkUpdates");
    expect(html).not.toContain("<button");
  });

  it("shows only the version when updates are unsupported or policy is still loading", () => {
    for (const policy of ["unsupported", null] as const) {
      const html = renderAbout({ policy });
      expect(html).toContain("0.4.6");
      expect(html).not.toContain("settings.checkUpdates");
      expect(html).not.toContain("settings.updateManagedExternally");
      expect(html).not.toContain("settings.updatePortable");
      expect(html).not.toContain("<button");
    }
  });

  it("renders interactive check and install controls for self-updating builds", () => {
    const checking = renderAbout({ policy: "selfUpdate", status: "checking" });
    expect(checking).toContain("settings.checkUpdates");
    expect(checking).toContain("settings.updateChecking");
    expect(checking).not.toContain("settings.updateInstall");

    const available = renderAbout({
      policy: "selfUpdate",
      status: "available",
      availableVersion: "0.5.0",
    });
    expect(available).toContain("settings.updateInstall");
    expect(available).toContain("<button");

    const checkFailed = renderAbout({ policy: "selfUpdate", status: "error" });
    expect(checkFailed).toContain("settings.updateError");
    expect(checkFailed).not.toContain("settings.updateInstall");

    const installFailed = renderAbout({
      policy: "selfUpdate",
      status: "installError",
      availableVersion: "0.5.0",
    });
    expect(installFailed).toContain("settings.updateInstallError");
    expect(installFailed).toContain("settings.updateInstall");
  });
});
