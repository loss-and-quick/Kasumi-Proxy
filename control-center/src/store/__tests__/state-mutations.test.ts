import { describe, expect, it } from "vitest";
import type { AppState } from "../../lib/bridge";
import { emptyProfile, type Profile } from "../../lib/schema";
import {
  mapFetchedSubscriptionProfiles,
  nextActiveIdAfterSubscriptionUpdate,
} from "../state-mutations";

function vless(overrides: Partial<Extract<Profile, { protocol: "vless" }>>): Profile {
  return { ...(emptyProfile("vless") as Extract<Profile, { protocol: "vless" }>), ...overrides };
}

function stateWith(profiles: Profile[], activeId: string | null): AppState {
  return { profiles, activeId } as AppState;
}

const sub = { id: "s1", groupId: undefined } as never;

describe("nextActiveIdAfterSubscriptionUpdate", () => {
  it("keeps the active id when the active profile is not from this subscription", () => {
    const active = vless({ id: "p1", subId: "other" });
    const fresh = mapFetchedSubscriptionProfiles([vless({ remarks: "X" })], sub, null);
    expect(nextActiveIdAfterSubscriptionUpdate(stateWith([active], "p1"), "s1", fresh)).toBe("p1");
  });

  it("matches the re-created active profile by exact identity", () => {
    const active = vless({ id: "p1", subId: "s1", remarks: "Node", address: "ex.com", port: 443 });
    const fresh = mapFetchedSubscriptionProfiles(
      [vless({ remarks: "Node", address: "ex.com", port: 443 })],
      sub,
      null,
    );
    const next = nextActiveIdAfterSubscriptionUpdate(stateWith([active], "p1"), "s1", fresh);
    expect(next).toBe(fresh[0].id);
  });

  it("falls back to the same-name profile when the endpoint (port) changed", () => {
    const active = vless({ id: "p1", subId: "s1", remarks: "Node", address: "ex.com", port: 443 });
    const fresh = mapFetchedSubscriptionProfiles(
      [vless({ remarks: "Node", address: "ex.com", port: 8443 })],
      sub,
      null,
    );
    const next = nextActiveIdAfterSubscriptionUpdate(stateWith([active], "p1"), "s1", fresh);
    expect(next).toBe(fresh[0].id);
  });

  it("returns null when the active profile no longer exists in the update", () => {
    const active = vless({ id: "p1", subId: "s1", remarks: "Gone" });
    const fresh = mapFetchedSubscriptionProfiles([vless({ remarks: "Other" })], sub, null);
    expect(nextActiveIdAfterSubscriptionUpdate(stateWith([active], "p1"), "s1", fresh)).toBeNull();
  });
});
