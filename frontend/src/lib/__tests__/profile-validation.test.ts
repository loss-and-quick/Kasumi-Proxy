import { describe, expect, it } from "vitest";
import type { Profile } from "../../generated/bindings";
import { mockBridge } from "../mock-bridge";
import { emptyProfile, isProviderCustom, schemaFor, translateIssue } from "../profile-utils";

const issues = async (p: Profile) => {
  const r = await mockBridge.validateProfile(p);
  return r.map((i) => i.field);
};

describe("profile validation", () => {
  it("won't save a blank profile", async () => {
    const p = emptyProfile("vless") as Extract<Profile, { protocol: "vless" }>;
    const blank = { ...p, meta: { ...p.meta, remarks: "" }, endpoint: { ...p.endpoint, port: 0 } };
    expect(await issues(blank as Profile)).toEqual(
      expect.arrayContaining(["remarks", "address", "port", "uuid"]),
    );
  });

  it("accepts a filled-in profile", async () => {
    const p = emptyProfile("trojan") as Extract<Profile, { protocol: "trojan" }>;
    const filled = {
      ...p,
      meta: { ...p.meta, remarks: "T" },
      endpoint: { ...p.endpoint, address: "h.example", port: 443 },
      password: "pw",
    };
    expect(await issues(filled as Profile)).toEqual([]);
  });

  it("asks a ShadowTLS v1 profile for no password", async () => {
    const p = emptyProfile("shadowtls") as Extract<Profile, { protocol: "shadowtls" }>;
    const v1 = {
      ...p,
      meta: { ...p.meta, remarks: "S" },
      endpoint: { ...p.endpoint, address: "h", port: 443 },
      version: 1,
    };
    expect(await issues(v1 as Profile)).not.toContain("password");
  });
});

describe("translateIssue", () => {
  it("translates validation issues to localized error messages", () => {
    expect(translateIssue("remarksRequired")).toBe("Name required");
    expect(translateIssue("addressRequired")).toBe("Server address required");
    expect(translateIssue("portOutOfRange")).toBe("Port must be 1–65535");
    expect(translateIssue("uuidRequired")).toBe("UUID required");
    expect(translateIssue("passwordRequired")).toBe("Password required");
    expect(translateIssue("secretKeyRequired")).toBe("Private key required");
    expect(translateIssue("peerPublicKeyRequired")).toBe("Peer public key required");
    expect(translateIssue("pathRequired")).toBe("Path required");
    expect(translateIssue("realitySniRequired")).toBe("SNI required for Reality");
    expect(translateIssue("publicKeyRequired")).toBe("Public key required");
    expect(translateIssue("rawConfigRequired")).toBe("Config JSON required");
  });
});

describe("provider custom profiles", () => {
  const provider = {
    ...emptyProfile("custom"),
    meta: { ...emptyProfile("custom").meta, remarks: "P" },
    raw: '{ "outbounds": [] }',
    origin: "provider",
  } as Profile;

  it("keeps the origin through the editor's save validation", () => {
    // Dropping it would save the config as the user's own, which runs verbatim.
    const r = schemaFor("custom").safeParse(provider);
    expect(r.success && "origin" in r.data && r.data.origin).toBe("provider");
  });

  it("tells provider configs from the user's own", () => {
    expect(isProviderCustom(provider)).toBe(true);
    expect(isProviderCustom(emptyProfile("custom"))).toBe(false);
    expect(isProviderCustom(emptyProfile("vless"))).toBe(false);
  });
});

describe("switching protocol", () => {
  const tlsOf = (p: Profile) => ("tls" in p && p.tls ? p.tls : null);

  it("starts new profiles with TLS only where the protocol needs it", () => {
    for (const proto of ["vless", "vmess", "shadowsocks", "http"] as const) {
      expect(tlsOf(emptyProfile(proto))?.security, proto).toBe("none");
    }
    for (const proto of ["trojan", "hysteria2", "tuic", "anytls", "naive", "shadowtls"] as const) {
      expect(tlsOf(emptyProfile(proto))?.security, proto).toBe("tls");
    }
  });

  it("gives Trojan its TLS back when the draft had none", async () => {
    const fresh = emptyProfile("vless");
    expect(tlsOf(await mockBridge.switchProfileProtocol(fresh, "trojan"))?.security).toBe("tls");
    expect(tlsOf(await mockBridge.switchProfileProtocol(fresh, "vmess"))?.security).toBe("none");
    expect(tlsOf(await mockBridge.switchProfileProtocol(fresh, "http"))?.security).toBe("none");
  });

  it("keeps a TLS mode the user picked when switching to VMess", async () => {
    const vless = emptyProfile("vless");
    const draft = { ...vless, tls: { ...tlsOf(vless), security: "tls", sni: "s.example" } };
    expect(tlsOf(await mockBridge.switchProfileProtocol(draft as Profile, "vmess"))).toMatchObject({
      security: "tls",
      sni: "s.example",
    });
  });

  it("doesn't carry TLS into Shadowsocks, where it is a v2ray-plugin option", async () => {
    const vless = emptyProfile("vless");
    const draft = { ...vless, tls: { ...tlsOf(vless), security: "tls", sni: "s.example" } };
    const ss = await mockBridge.switchProfileProtocol(draft as Profile, "shadowsocks");
    expect(tlsOf(ss)).toMatchObject({ security: "none", sni: "s.example" });
  });

  it("carries the TLS mode between protocols that speak TLS themselves", async () => {
    const vless = emptyProfile("vless");
    const draft = { ...vless, tls: { ...tlsOf(vless), security: "reality", sni: "s.example" } };
    expect(
      tlsOf(await mockBridge.switchProfileProtocol(draft as Profile, "trojan"))?.security,
    ).toBe("reality");
  });
});
