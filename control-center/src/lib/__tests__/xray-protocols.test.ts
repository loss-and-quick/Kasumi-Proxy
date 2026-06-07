import { describe, expect, it } from "vitest";
import type { AdvancedSettings } from "../bridge";
import type { Profile } from "../schema";
import { emptyProfile, type ProfileOf } from "../schema";
import { buildOutbound, buildXrayConfig } from "../xray-config";

const settings: AdvancedSettings = {
  routingMode: "global",
  domainSniffing: true,
  routeOnly: false,
  domainStrategy: "IPIfNonMatch",
  domainStrategy4Singbox: "prefer_ipv4",
  dnsViaProxy: true,
  fakeDns: false,
  preferIpv6: false,
  mux: false,
  muxConcurrency: 8,
  fragment: false,
  fragmentPackets: "tlshello",
  mtu: 1350,
};

function mk<P extends Profile["protocol"]>(
  protocol: P,
  o: Partial<ProfileOf<P>> = {},
): ProfileOf<P> {
  return { ...(emptyProfile(protocol) as ProfileOf<P>), ...o };
}

// loose view for asserting nested config without `any`
const obj = (x: unknown): Record<string, unknown> => x as Record<string, unknown>;
const arr = (x: unknown): unknown[] => x as unknown[];

describe("buildOutbound — new protocols", () => {
  it("shadowsocks maps method/password into servers", () => {
    const o = obj(
      buildOutbound(
        mk("shadowsocks", {
          address: "ss.ex",
          port: 8388,
          password: "pw",
          method: "2022-blake3-aes-128-gcm",
        }),
        settings,
      ),
    );
    expect(o.protocol).toBe("shadowsocks");
    const srv = obj(arr(obj(o.settings).servers)[0]);
    expect(srv.method).toBe("2022-blake3-aes-128-gcm");
    expect(srv.password).toBe("pw");
  });

  it("socks carries no streamSettings and optional user", () => {
    const o = obj(
      buildOutbound(
        mk("socks", { address: "s.ex", port: 1080, username: "u", password: "p" }),
        settings,
      ),
    );
    expect(o.protocol).toBe("socks");
    expect(o.streamSettings).toBeUndefined();
    const srv = obj(arr(obj(o.settings).servers)[0]);
    expect(arr(srv.users)[0]).toMatchObject({ user: "u", pass: "p" });
  });

  it("http applies tls streamSettings when security=tls", () => {
    const o = obj(
      buildOutbound(
        mk("http", { address: "h.ex", port: 8080, security: "tls", sni: "h.ex" }),
        settings,
      ),
    );
    expect(o.protocol).toBe("http");
    expect(obj(o.streamSettings).security).toBe("tls");
    expect(obj(obj(o.streamSettings).tlsSettings).serverName).toBe("h.ex");
  });

  it("wireguard builds peer endpoint + reserved", () => {
    const o = obj(
      buildOutbound(
        mk("wireguard", {
          address: "wg.ex",
          port: 51820,
          secretKey: "sk",
          peerPublicKey: "pk",
          reserved: "1,2,3",
          localAddress: "10.0.0.2/32",
        }),
        settings,
      ),
    );
    expect(o.protocol).toBe("wireguard");
    const s = obj(o.settings);
    expect(s.secretKey).toBe("sk");
    expect(s.reserved).toEqual([1, 2, 3]);
    const peer = obj(arr(s.peers)[0]);
    expect(peer.publicKey).toBe("pk");
    expect(peer.endpoint).toBe("wg.ex:51820");
  });
});

describe("buildXrayConfig — DNS & routing", () => {
  const vless = () =>
    mk("vless", {
      address: "ex.com",
      uuid: "11111111-1111-1111-1111-111111111111",
      security: "tls",
      sni: "ex.com",
    });

  it("uses custom remote DNS and UseIP when ipv6 enabled", () => {
    const cfg = obj(
      buildXrayConfig(vless(), { ...settings, remoteDns: "9.9.9.9, 1.0.0.1", ipv6Enabled: true }),
    );
    const dns = obj(cfg.dns);
    expect(arr(dns.servers)).toContain("9.9.9.9");
    expect(dns.queryStrategy).toBe("UseIP");
  });

  it("parses dnsHosts host=ip lines", () => {
    const cfg = obj(
      buildXrayConfig(vless(), { ...settings, dnsHosts: "ex.com=1.2.3.4\nfoo.net=5.6.7.8" }),
    );
    expect(obj(obj(cfg.dns).hosts)["ex.com"]).toBe("1.2.3.4");
  });

  it("custom routing rules are wrapped by dns + final rules", () => {
    const custom = JSON.stringify([
      { type: "field", domain: ["geosite:ads"], outboundTag: "block" },
    ]);
    const cfg = obj(
      buildXrayConfig(vless(), { ...settings, routingMode: "custom", customRouting: custom }),
    );
    const rules = arr(obj(cfg.routing).rules).map((r) => obj(r));
    expect(
      rules.some((r) => Array.isArray(r.domain) && (r.domain as string[]).includes("geosite:ads")),
    ).toBe(true);
    // still has the trailing proxy rule
    expect(rules[rules.length - 1].outboundTag).toBe("proxy");
  });

  it("rules mode serializes structured routing rules", () => {
    const cfg = obj(
      buildXrayConfig(vless(), { ...settings, routingMode: "rules" }, [
        {
          id: "r1",
          remarks: "RU direct",
          enabled: true,
          outboundTag: "direct",
          domain: ["geosite:category-ru"],
          ip: ["geoip:ru"],
        },
        {
          id: "r2",
          remarks: "Disabled",
          enabled: false,
          outboundTag: "block",
          domain: ["geosite:ads"],
        },
      ]),
    );
    const rules = arr(obj(cfg.routing).rules).map((r) => obj(r));
    expect(
      rules.some(
        (r) =>
          Array.isArray(r.domain) &&
          (r.domain as string[]).includes("geosite:category-ru") &&
          r.outboundTag === "direct",
      ),
    ).toBe(true);
    expect(
      rules.some((r) => Array.isArray(r.domain) && (r.domain as string[]).includes("geosite:ads")),
    ).toBe(false);
    expect(rules[rules.length - 1].outboundTag).toBe("proxy");
  });
});

describe("buildXrayConfig — custom passthrough", () => {
  it("returns the raw config verbatim for custom profiles", () => {
    const raw = JSON.stringify({ inbounds: [], outbounds: [{ protocol: "freedom" }], marker: 42 });
    const cfg = obj(buildXrayConfig(mk("custom", { raw }), settings));
    expect(cfg.marker).toBe(42);
    expect(arr(cfg.outbounds)).toHaveLength(1);
  });

  it("throws on invalid custom JSON", () => {
    expect(() => buildXrayConfig(mk("custom", { raw: "{ not json" }), settings)).toThrow();
  });
});
