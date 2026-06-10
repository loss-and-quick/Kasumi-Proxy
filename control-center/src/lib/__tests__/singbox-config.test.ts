import { describe, expect, it } from "vitest";
import type { AdvancedSettings } from "../bridge";
import { emptyProfile, type Profile, type ProfileOf, resolveCore } from "../schema";
import { buildSingboxConfig, buildSingboxOutbound } from "../singbox-config";

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
  coreByProtocol: {},
};

function mk<P extends Profile["protocol"]>(
  protocol: P,
  o: Partial<ProfileOf<P>> = {},
): ProfileOf<P> {
  return { ...(emptyProfile(protocol) as ProfileOf<P>), ...o };
}

const obj = (x: unknown): Record<string, unknown> => x as Record<string, unknown>;
const arr = (x: unknown): unknown[] => x as unknown[];

describe("buildSingboxOutbound — QUIC protocols", () => {
  it("hysteria2 maps password, salamander obfs, bandwidth and tls", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("hysteria2", {
          address: "hy.ex",
          port: 443,
          password: "pw",
          obfsType: "salamander",
          obfsPassword: "obf",
          upMbps: 100,
          downMbps: 200,
          sni: "hy.ex",
          allowInsecure: true,
        }),
        settings,
      ),
    );
    expect(o.type).toBe("hysteria2");
    expect(o.password).toBe("pw");
    expect(obj(o.obfs)).toMatchObject({ type: "salamander", password: "obf" });
    expect(o.up_mbps).toBe(100);
    expect(o.down_mbps).toBe(200);
    expect(obj(o.tls).enabled).toBe(true);
    expect(obj(o.tls).server_name).toBe("hy.ex");
    expect(obj(o.tls).insecure).toBe(true);
  });

  it("hysteria2 port hopping produces server_ports + hop_interval", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("hysteria2", {
          address: "hy.ex",
          port: 443,
          password: "pw",
          ports: "20000-50000,60000",
          hopInterval: "30",
        }),
        settings,
      ),
    );
    expect(o.server_port).toBeUndefined();
    expect(o.server_ports).toEqual(["20000:50000", "60000:60000"]);
    expect(o.hop_interval).toBe("30s");
  });

  it("tuic maps uuid/password/congestion_control with tls", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("tuic", {
          address: "t.ex",
          port: 8443,
          uuid: "u-1",
          password: "pw",
          congestionControl: "bbr",
          udpRelayMode: "native",
          zeroRtt: true,
          sni: "t.ex",
        }),
        settings,
      ),
    );
    expect(o.type).toBe("tuic");
    expect(o.uuid).toBe("u-1");
    expect(o.password).toBe("pw");
    expect(o.congestion_control).toBe("bbr");
    expect(o.udp_relay_mode).toBe("native");
    expect(o.zero_rtt_handshake).toBe(true);
    expect(obj(o.tls).enabled).toBe(true);
  });

  it("tuic emits udp_over_stream and heartbeat", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("tuic", {
          address: "t.ex",
          port: 8443,
          uuid: "u-1",
          password: "pw",
          udpOverStream: true,
          heartbeat: "15s",
        }),
        settings,
      ),
    );
    expect(o.udp_over_stream).toBe(true);
    expect(o.heartbeat).toBe("15s");
  });

  it("anytls emits idle session fields and min_idle_session", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("anytls", {
          address: "a.ex",
          port: 443,
          password: "pw",
          idleSessionCheckInterval: "30s",
          idleSessionTimeout: "2m",
          minIdleSession: 2,
        }),
        settings,
      ),
    );
    expect(o.idle_session_check_interval).toBe("30s");
    expect(o.idle_session_timeout).toBe("2m");
    expect(o.min_idle_session).toBe(2);
  });

  it("hysteria2 maps certificate pin into sing-box tls pinning", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("hysteria2", {
          address: "hy.ex",
          port: 443,
          password: "pw",
          pinSha256: "abc123=",
        }),
        settings,
      ),
    );
    expect(obj(o.tls).certificate_public_key_sha256).toEqual(["abc123="]);
  });
});

describe("buildSingboxOutbound — stream protocols via sing-box", () => {
  it("vless carries packet_encoding, ws transport and utls", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("vless", {
          address: "v.ex",
          port: 443,
          uuid: "11111111-1111-1111-1111-111111111111",
          network: "ws",
          host: "v.ex",
          path: "/ray",
          wsEarlyData: 2048,
          wsEarlyDataHeader: "Sec-WebSocket-Protocol",
          security: "tls",
          sni: "v.ex",
          fingerprint: "chrome",
        }),
        settings,
      ),
    );
    expect(o.type).toBe("vless");
    expect(o.packet_encoding).toBe("xudp");
    expect(obj(o.transport)).toMatchObject({
      type: "ws",
      path: "/ray",
      max_early_data: 2048,
      early_data_header_name: "Sec-WebSocket-Protocol",
    });
    expect(obj(obj(o.tls).utls)).toMatchObject({ enabled: true, fingerprint: "chrome" });
  });

  it("grpc transport maps supported sing-box extra settings", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("vless", {
          address: "g.ex",
          port: 443,
          uuid: "11111111-1111-1111-1111-111111111111",
          network: "grpc",
          serviceName: "svc",
          grpcIdleTimeout: 30,
          grpcPingTimeout: 15,
          grpcPermitWithoutStream: true,
          security: "tls",
          sni: "g.ex",
        }),
        settings,
      ),
    );
    expect(obj(o.transport)).toMatchObject({
      type: "grpc",
      service_name: "svc",
      idle_timeout: "30s",
      ping_timeout: "15s",
      permit_without_stream: true,
    });
  });

  it("h2 transport emits idle_timeout and ping_timeout", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("vless", {
          address: "h.ex",
          port: 443,
          uuid: "11111111-1111-1111-1111-111111111111",
          network: "h2",
          host: "h.ex",
          path: "/h2",
          grpcIdleTimeout: 60,
          grpcPingTimeout: 20,
          security: "tls",
          sni: "h.ex",
        }),
        settings,
      ),
    );
    expect(obj(o.transport)).toMatchObject({
      type: "http",
      idle_timeout: "60s",
      ping_timeout: "20s",
    });
  });

  it("advanced TLS fields emitted in sing-box tls block", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("vless", {
          address: "v.ex",
          port: 443,
          uuid: "11111111-1111-1111-1111-111111111111",
          security: "tls",
          sni: "v.ex",
          disableSni: true,
          tlsMinVersion: "1.2",
          tlsMaxVersion: "1.3",
          tlsCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
          tlsCurvePreferences: "X25519",
          cert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        }),
        settings,
      ),
    );
    const tls = obj(o.tls);
    expect(tls.disable_sni).toBe(true);
    expect(tls.min_version).toBe("1.2");
    expect(tls.max_version).toBe("1.3");
    expect(tls.cipher_suites).toEqual(["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]);
    expect(tls.curve_preferences).toEqual(["X25519"]);
    expect(Array.isArray(tls.certificate)).toBe(true);
  });

  it("shadowsocks maps method/password without tls", () => {
    const o = obj(
      buildSingboxOutbound(
        mk("shadowsocks", {
          address: "ss.ex",
          port: 8388,
          method: "aes-256-gcm",
          password: "pw",
        }),
        settings,
      ),
    );
    expect(o.type).toBe("shadowsocks");
    expect(o.method).toBe("aes-256-gcm");
    expect(o.tls).toBeUndefined();
  });

  it("shadowsocks maps plugin-style transport fields into plugin_opts", () => {
    const ws = obj(
      buildSingboxOutbound(
        mk("shadowsocks", {
          address: "ss.ex",
          port: 8388,
          method: "aes-256-gcm",
          password: "pw",
          network: "ws",
          host: "cdn.ex.com",
          path: "/ws",
          security: "tls",
        }),
        settings,
      ),
    );
    expect(ws.plugin).toBe("v2ray-plugin");
    expect(ws.plugin_opts).toContain("mode=websocket;");
    expect(ws.plugin_opts).toContain("host=cdn.ex.com;");
    expect(ws.plugin_opts).toContain("path=/ws;");
    expect(ws.plugin_opts).toContain("tls;");

    const obfs = obj(
      buildSingboxOutbound(
        mk("shadowsocks", {
          address: "ss.ex",
          port: 8388,
          method: "aes-256-gcm",
          password: "pw",
          network: "tcp",
          headerType: "http",
          host: "cdn.ex.com",
        }),
        settings,
      ),
    );
    expect(obfs.plugin).toBe("obfs-local");
    expect(obfs.plugin_opts).toBe("obfs=http;obfs-host=cdn.ex.com;");
  });

  it("supports anytls, naive and shadowtls outbounds", () => {
    const anytls = obj(
      buildSingboxOutbound(
        mk("anytls", { address: "a.ex", port: 443, password: "pw", sni: "a.ex" }),
        settings,
      ),
    );
    expect(anytls.type).toBe("anytls");
    expect(anytls.password).toBe("pw");
    expect(obj(anytls.tls).server_name).toBe("a.ex");

    const naive = obj(
      buildSingboxOutbound(
        mk("naive", {
          address: "n.ex",
          port: 443,
          username: "user",
          password: "pw",
          naiveQuic: true,
          congestionControl: "bbr",
          insecureConcurrency: 8,
          sni: "n.ex",
        }),
        settings,
      ),
    );
    expect(naive.type).toBe("naive");
    expect(naive.username).toBe("user");
    expect(naive.quic).toBe(true);
    expect(naive.quic_congestion_control).toBe("bbr");
    expect(naive.insecure_concurrency).toBe(8);

    const shadowtls = obj(
      buildSingboxOutbound(
        mk("shadowtls", { address: "s.ex", port: 443, version: 3, password: "pw", sni: "s.ex" }),
        settings,
      ),
    );
    expect(shadowtls.type).toBe("shadowtls");
    expect(shadowtls.version).toBe(3);
    expect(shadowtls.password).toBe("pw");
  });
});

describe("buildSingboxConfig — full config", () => {
  it("emits mixed inbound on the socks port and proxy+direct outbounds", () => {
    const cfg = obj(
      buildSingboxConfig(mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }), {
        ...settings,
        localSocksPort: 10810,
      }),
    );
    const inbound = obj(arr(cfg.inbounds)[0]);
    expect(inbound.type).toBe("mixed");
    expect(inbound.listen_port).toBe(10810);
    const outbounds = arr(cfg.outbounds).map((x) => obj(x));
    expect(outbounds[0].tag).toBe("proxy");
    expect(outbounds.some((o) => o.type === "direct")).toBe(true);
    expect(obj(cfg.route).final).toBe("proxy");
  });

  it("keeps local DNS direct without detouring through an empty direct outbound", () => {
    const cfg = obj(
      buildSingboxConfig(
        mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }),
        settings,
      ),
    );
    const servers = arr(obj(cfg.dns).servers).map((x) => obj(x));
    expect(servers.find((s) => s.tag === "remote")?.detour).toBe("proxy");
    expect(servers.find((s) => s.tag === "local")?.detour).toBeUndefined();
  });

  it("honors dnsViaProxy when selecting the remote DNS detour", () => {
    const cfg = obj(
      buildSingboxConfig(mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }), {
        ...settings,
        dnsViaProxy: false,
      }),
    );
    const servers = arr(obj(cfg.dns).servers).map((x) => obj(x));
    expect(servers.find((s) => s.tag === "remote")?.detour).toBeUndefined();
  });

  it("adds hosts and fakeip DNS servers and rules", () => {
    const cfg = obj(
      buildSingboxConfig(mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }), {
        ...settings,
        fakeDns: true,
        dnsHosts: "ex.com=1.2.3.4\nlocalhost=127.0.0.1",
      }),
    );
    const dns = obj(cfg.dns);
    const servers = arr(dns.servers).map((x) => obj(x));
    const rules = arr(dns.rules).map((x) => obj(x));
    expect(servers.some((s) => s.tag === "hosts" && s.type === "hosts")).toBe(true);
    expect(servers.some((s) => s.tag === "fakeip" && s.type === "fakeip")).toBe(true);
    expect(rules.some((r) => r.server === "hosts" && r.ip_accept_any === true)).toBe(true);
    expect(
      rules.some(
        (r) =>
          r.server === "fakeip" &&
          Array.isArray(r.query_type) &&
          (r.query_type as string[]).includes("A"),
      ),
    ).toBe(true);
  });

  it("rules mode adds DNS domain routing for direct/proxy domains", () => {
    const cfg = obj(
      buildSingboxConfig(
        mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }),
        { ...settings, routingMode: "rules" },
        [
          {
            id: "d1",
            remarks: "direct domains",
            enabled: true,
            outboundTag: "direct",
            domain: ["full:lan.example", "domain:corp.local"],
          },
          {
            id: "p1",
            remarks: "proxy domains",
            enabled: true,
            outboundTag: "proxy",
            domain: ["geosite:geolocation-!cn"],
          },
        ],
      ),
    );
    const dns = obj(cfg.dns);
    const rules = arr(dns.rules).map((x) => obj(x));
    expect(
      rules.some(
        (r) =>
          r.server === "local" &&
          Array.isArray(r.domain) &&
          (r.domain as string[]).includes("lan.example"),
      ),
    ).toBe(true);
    expect(
      rules.some(
        (r) =>
          r.server === "local" &&
          Array.isArray(r.domain_suffix) &&
          (r.domain_suffix as string[]).includes("corp.local"),
      ),
    ).toBe(true);
    expect(
      rules.some(
        (r) =>
          r.server === "remote" &&
          Array.isArray(r.rule_set) &&
          (r.rule_set as string[]).includes("geosite-geolocation-!cn"),
      ),
    ).toBe(true);
    const route = obj(cfg.route);
    expect(arr(route.rule_set).some((r) => obj(r).tag === "geosite-geolocation-!cn")).toBe(true);
  });

  it("rules mode emits remote rule_set declarations for geo rules", () => {
    const cfg = obj(
      buildSingboxConfig(
        mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }),
        { ...settings, routingMode: "rules" },
        [
          {
            id: "r1",
            remarks: "RU",
            enabled: true,
            outboundTag: "direct",
            domain: ["geosite:category-ru"],
            ip: ["geoip:ru"],
          },
          {
            id: "r2",
            remarks: "disabled",
            enabled: false,
            outboundTag: "block",
            domain: ["geosite:ads"],
          },
        ],
      ),
    );
    const route = obj(cfg.route);
    const rules = arr(route.rules).map((x) => obj(x));
    const ruleSets = arr(route.rule_set).map((x) => obj(x));
    expect(
      rules.some(
        (r) =>
          Array.isArray(r.rule_set) &&
          (r.rule_set as string[]).includes("geosite-category-ru") &&
          r.outbound === "direct",
      ),
    ).toBe(true);
    expect(
      rules.some(
        (r) =>
          Array.isArray(r.rule_set) &&
          (r.rule_set as string[]).includes("geoip-ru") &&
          r.outbound === "direct",
      ),
    ).toBe(true);
    expect(
      rules.some(
        (r) => Array.isArray(r.rule_set) && (r.rule_set as string[]).includes("geosite-ads"),
      ),
    ).toBe(false);
    expect(ruleSets.some((r) => r.tag === "geosite-category-ru" && r.type === "local")).toBe(true);
    expect(ruleSets.some((r) => r.tag === "geoip-ru" && r.type === "local")).toBe(true);
  });

  it("maps domain strategy to sing-box resolve rules", () => {
    const cfg = obj(
      buildSingboxConfig(mk("hysteria2", { address: "hy.ex", port: 443, password: "pw" }), {
        ...settings,
        routingMode: "global",
        domainStrategy: "IPIfNonMatch",
        domainStrategy4Singbox: "prefer_ipv6",
      }),
    );
    const rules = arr(obj(cfg.route).rules).map((x) => obj(x));
    expect(rules[0]).toMatchObject({ ip_is_private: true, outbound: "direct" });
    expect(rules[1]).toMatchObject({ action: "resolve", strategy: "prefer_ipv6" });
    expect(rules[2]).toMatchObject({ ip_is_private: true, outbound: "direct" });
  });

  it("places wireguard in endpoints (1.12+) with peer endpoint, not outbounds", () => {
    const cfg = obj(
      buildSingboxConfig(
        mk("wireguard", {
          address: "wg.ex",
          port: 51820,
          secretKey: "sk",
          peerPublicKey: "pk",
          localAddress: "10.0.0.2/32",
          reserved: "1,2,3",
        }),
        settings,
      ),
    );
    const endpoints = arr(cfg.endpoints).map((x) => obj(x));
    expect(endpoints[0].type).toBe("wireguard");
    expect(endpoints[0].private_key).toBe("sk");
    const peer = obj(arr(endpoints[0].peers)[0]);
    expect(peer.address).toBe("wg.ex");
    expect(peer.port).toBe(51820);
    expect(peer.public_key).toBe("pk");
    expect(peer.reserved).toEqual([1, 2, 3]);
    // not duplicated as an outbound
    expect(arr(cfg.outbounds).every((o) => obj(o).type !== "wireguard")).toBe(true);
  });

  it("wireguard emits workers and persistent_keepalive_interval", () => {
    const cfg = obj(
      buildSingboxConfig(
        mk("wireguard", {
          address: "wg.ex",
          port: 51820,
          secretKey: "sk",
          peerPublicKey: "pk",
          localAddress: "10.0.0.2/32",
          workers: 4,
          persistentKeepalive: 25,
        }),
        settings,
      ),
    );
    const ep = obj(arr(cfg.endpoints)[0]);
    expect(ep.workers).toBe(4);
    expect(obj(arr(ep.peers)[0]).persistent_keepalive_interval).toBe(25);
  });

  it("throws for custom profiles", () => {
    expect(() => buildSingboxConfig(mk("custom", { raw: "{}" }), settings)).toThrow();
  });
});

describe("resolveCore — v2rayN-style engine resolution", () => {
  it("keeps hysteria2 user-selectable but forces sing-box-only protocols", () => {
    expect(resolveCore(mk("hysteria2", { coreType: "xray" }), settings)).toBe("xray");
    expect(resolveCore(mk("tuic", {}), settings)).toBe("sing-box");
    expect(resolveCore(mk("anytls", {}), settings)).toBe("sing-box");
    expect(resolveCore(mk("naive", {}), settings)).toBe("sing-box");
    expect(resolveCore(mk("shadowtls", {}), settings)).toBe("sing-box");
  });

  it("forces engine by transport capability when needed", () => {
    expect(resolveCore(mk("vless", { network: "h2" }), settings)).toBe("sing-box");
    expect(resolveCore(mk("vless", { network: "kcp" }), settings)).toBe("xray");
    expect(resolveCore(mk("shadowsocks", { network: "ws", security: "tls" }), settings)).toBe(
      "sing-box",
    );
    expect(resolveCore(mk("shadowsocks", { network: "tcp", headerType: "http" }), settings)).toBe(
      "sing-box",
    );
  });

  it("forces xray for xray-style custom gRPC paths (leading slash)", () => {
    // sing-box hardcodes the "/<service_name>/Tun" wire path, so xray's
    // custom-path serviceName convention is unrepresentable there.
    expect(
      resolveCore(
        mk("trojan", { network: "grpc", serviceName: "/26863/abc", coreType: "sing-box" }),
        settings,
      ),
    ).toBe("xray");
    expect(
      resolveCore(
        mk("trojan", { network: "grpc", serviceName: "svc", coreType: "sing-box" }),
        settings,
      ),
    ).toBe("sing-box");
  });

  it("custom always resolves to xray", () => {
    expect(resolveCore(mk("custom", { raw: "{}", coreType: "sing-box" }), settings)).toBe("xray");
  });

  it("per-profile override beats the table", () => {
    const s = { ...settings, coreByProtocol: { vless: "xray" as const } };
    expect(resolveCore(mk("vless", { coreType: "sing-box" }), s)).toBe("sing-box");
  });

  it("table default applies when override is global, else falls back to xray", () => {
    const s = { ...settings, coreByProtocol: { vmess: "sing-box" as const } };
    expect(resolveCore(mk("vmess", { coreType: "global" }), s)).toBe("sing-box");
    expect(resolveCore(mk("trojan", { coreType: "global" }), s)).toBe("xray");
  });
});

describe("buildSingboxConfig — multi-outbound", () => {
  it("routing rule targeting a profile id adds a tagged outbound and resolves the rule", () => {
    const active = mk("vless", { id: "active", uuid: "u1", address: "a.com", port: 443 });
    const other = mk("trojan", { id: "other", address: "b.com", port: 443, password: "pw" });
    const rules = [
      { id: "r1", remarks: "x", enabled: true, outboundTag: "other", domain: ["full:example.com"] },
    ];
    const cfg = obj(
      buildSingboxConfig(active, { ...settings, routingMode: "rules" }, rules, [active, other]),
    );
    const tags = arr(cfg.outbounds).map((o) => obj(o).tag);
    expect(tags).toContain("other");
    const ruleHit = arr(obj(cfg.route).rules).find((r) =>
      arr(obj(r).domain ?? []).includes("example.com"),
    );
    expect(obj(ruleHit).outbound).toBe("other");
  });

  it("routing rule targeting an unknown profile id falls back to proxy", () => {
    const active = mk("vless", { id: "active", uuid: "u1", address: "a.com", port: 443 });
    const rules = [
      { id: "r1", remarks: "x", enabled: true, outboundTag: "ghost", domain: ["full:example.com"] },
    ];
    const cfg = obj(
      buildSingboxConfig(active, { ...settings, routingMode: "rules" }, rules, [active]),
    );
    expect(arr(cfg.outbounds).map((o) => obj(o).tag)).not.toContain("ghost");
    const ruleHit = arr(obj(cfg.route).rules).find((r) =>
      arr(obj(r).domain ?? []).includes("example.com"),
    );
    expect(obj(ruleHit).outbound).toBe("proxy");
  });
});
