import { describe, expect, it } from "vitest";
import type { Profile } from "../../generated/bindings";
import { emptyProfile, schemaFor } from "../profile-utils";

const issues = (p: Profile) => {
  const r = schemaFor(p.protocol).safeParse(p);
  return r.success ? [] : r.error.issues.map((i) => String(i.path[i.path.length - 1]));
};

describe("profile validation", () => {
  it("won't save a blank profile", () => {
    const p = emptyProfile("vless") as Extract<Profile, { protocol: "vless" }>;
    const blank = { ...p, meta: { ...p.meta, remarks: "" }, endpoint: { ...p.endpoint, port: 0 } };
    expect(issues(blank as Profile)).toEqual(
      expect.arrayContaining(["remarks", "address", "port", "uuid"]),
    );
  });

  it("accepts a filled-in profile", () => {
    const p = emptyProfile("trojan") as Extract<Profile, { protocol: "trojan" }>;
    const filled = {
      ...p,
      meta: { ...p.meta, remarks: "T" },
      endpoint: { ...p.endpoint, address: "h.example", port: 443 },
      password: "pw",
    };
    expect(issues(filled as Profile)).toEqual([]);
  });

  it("asks a ShadowTLS v1 profile for no password", () => {
    const p = emptyProfile("shadowtls") as Extract<Profile, { protocol: "shadowtls" }>;
    const v1 = {
      ...p,
      meta: { ...p.meta, remarks: "S" },
      endpoint: { ...p.endpoint, address: "h", port: 443 },
      version: 1,
    };
    expect(issues(v1 as Profile)).not.toContain("password");
  });
});
