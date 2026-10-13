import { describe, expect, it } from "vitest";
import type { Route } from "../../../generated/bindings";
import type { ChangeAction, PendingChange } from "../../../lib/bridge";
import { DEFAULT_ROUTE_ID, newRoute } from "../../../lib/routes";
import {
  boolValue,
  currentGroupRoute,
  domainMove,
  groupChanges,
  keyLabel,
  safeDigests,
  tunnelKeys,
} from "../proposals";

const change = (
  key: string,
  action: ChangeAction,
  risk: PendingChange["risk"] = "trustBoundary",
): PendingChange => ({
  key,
  value: "v",
  risk,
  action,
  digest: `d-${key}`,
  seenAt: "2026-10-13T00:00:00Z",
});

const mux = change(
  "mux-enable",
  { kind: "tunnelSetting", setting: { kind: "mux", on: true } },
  "tunnelBehaviour",
);
const noises = change("noises-enable", { kind: "unsupported" }, "tunnelBehaviour");
const perApp = change("per-app-proxy-list", { kind: "unsupported" });
const insecure = change("insecure", { kind: "setInsecure", on: true });
const newUrl = change("new-url", {
  kind: "replaceUrl",
  url: "https://b.example.net/s",
  fromHost: "a.example.org",
  toHost: "b.example.net",
  otherDomain: true,
});
const fallback = change("fallback-url", {
  kind: "setFallbackUrl",
  url: "https://f.example.org/s",
  host: "f.example.org",
});
const configs = change("provider-configs", { kind: "allowProviderConfigs" });

describe("groupChanges", () => {
  it("orders trust, tunnel, then unsupported, and the URL moves first", () => {
    const groups = groupChanges([noises, mux, insecure, configs, perApp, fallback, newUrl]);
    expect(groups.map((g) => g.group)).toEqual(["trust", "tunnel", "unsupported"]);
    expect(groups[0].items.map((c) => c.key)).toEqual([
      "new-url",
      "fallback-url",
      "provider-configs",
      "insecure",
    ]);
    expect(groups[1].items).toEqual([mux]);
    // An unsupported key is dismiss-only whatever its tier.
    expect(groups[2].items.map((c) => c.key)).toEqual(["noises-enable", "per-app-proxy-list"]);
  });

  it("leaves out empty groups", () => {
    expect(groupChanges([mux]).map((g) => g.group)).toEqual(["tunnel"]);
    expect(groupChanges([])).toEqual([]);
  });
});

describe("safeDigests", () => {
  it("takes only applicable tuning changes", () => {
    expect(safeDigests([mux, noises, insecure, newUrl, configs])).toEqual(["d-mux-enable"]);
    expect(tunnelKeys([mux, noises, insecure])).toEqual(["mux-enable"]);
  });
});

describe("domainMove", () => {
  it("reports the host move of a URL or domain change only", () => {
    expect(domainMove(newUrl.action)).toEqual({
      from: "a.example.org",
      to: "b.example.net",
      otherDomain: true,
    });
    expect(domainMove(fallback.action)).toBeNull();
  });
});

describe("labels and values", () => {
  it("labels known keys and leaves others raw", () => {
    expect(keyLabel("new-url")).toBe("subs.changes.key.newUrl");
    expect(keyLabel("mux-enable")).toBe("settings.mux");
    expect(keyLabel("provider-configs")).toBe("subs.changes.key.providerConfigs");
    expect(keyLabel("per-app-proxy-list")).toBeNull();
  });

  it("words on/off changes", () => {
    expect(boolValue(insecure.action)).toBe(true);
    expect(boolValue(mux.action)).toBe(true);
    expect(boolValue(newUrl.action)).toBeNull();
    expect(
      boolValue({ kind: "tunnelSetting", setting: { kind: "fragmentLength", value: "1-2" } }),
    ).toBeNull();
  });
});

describe("currentGroupRoute", () => {
  it("finds the enabled route listing the group, else the default", () => {
    const def = newRoute(DEFAULT_ROUTE_ID, "Default");
    const team: Route = { ...newRoute("team", "Team"), groups: ["g1"] };
    const off: Route = { ...newRoute("off", "Off"), groups: ["g2"], enabled: false };
    expect(currentGroupRoute([def, team, off], "g1")?.id).toBe("team");
    expect(currentGroupRoute([def, team, off], "g2")?.id).toBe(DEFAULT_ROUTE_ID);
  });
});
