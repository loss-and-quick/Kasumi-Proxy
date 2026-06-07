import { describe, expect, it } from "vitest";
import type { AdvancedSettings } from "../bridge";
import type { Profile } from "../schema";
import { buildOutbound, buildXrayConfig } from "../xray-config";

type Vless = Extract<Profile, { protocol: "vless" }>;
type Vmess = Extract<Profile, { protocol: "vmess" }>;
type Trojan = Extract<Profile, { protocol: "trojan" }>;

interface OutboundView {
  protocol: string;
  settings: {
    vnext?: Array<{
      users: Array<{ id?: string; security?: string; flow?: string; alterId?: number }>;
    }>;
    servers?: Array<{ password: string; flow?: string }>;
  };
  streamSettings: {
    network?: Profile["network"];
    security: Profile["security"];
    realitySettings?: Record<string, unknown>;
    tlsSettings?: Record<string, unknown>;
    wsSettings?: { path: string; headers: { Host: string } };
    grpcSettings?: {
      serviceName: string;
      authority: string;
      multiMode?: boolean;
      idle_timeout?: number;
      health_check_timeout?: number;
      permit_without_stream?: boolean;
      initial_windows_size?: number;
      user_agent?: string;
    };
    xhttpSettings?: { host: string; path: string; mode?: string; extra?: unknown };
    kcpSettings?: { header: { type: string }; seed?: string };
    sockopt: { fragment?: { packets: string; length: string; interval: string } };
  };
  mux?: {
    enabled: boolean;
    concurrency: number;
    xudpConcurrency?: number;
    xudpProxyUDP443?: string;
  };
}

interface XrayConfigView {
  inbounds: Array<{ port: number }>;
  outbounds: Array<{ tag?: string; protocol: string }>;
  dns: { servers: Array<unknown> };
  routing: { domainStrategy?: string; rules: Array<{ ip?: string[] }> };
  log: { loglevel?: string };
}

function viewOutbound(outbound: ReturnType<typeof buildOutbound>): OutboundView {
  return outbound as OutboundView;
}

function viewConfig(config: ReturnType<typeof buildXrayConfig>): XrayConfigView {
  return config as XrayConfigView;
}

// Build profiles inline (avoid importing schema.ts → zod at test runtime).
const commonBase = {
  id: "p",
  remarks: "n",
  address: "ex.com",
  port: 443,
  groupId: "g-main",
  subId: null,
  ping: null,
  network: "tcp",
  headerType: "none",
  host: "",
  path: "",
  muxEnabled: false,
  grpcMode: "",
  serviceName: "",
  authority: "",
  xhttpMode: "",
  xhttpExtra: "",
  security: "tls",
  sni: "",
  disableSni: false,
  fingerprint: "chrome",
  alpn: "",
  allowInsecure: false,
  tlsMinVersion: "",
  tlsMaxVersion: "",
  tlsCipherSuites: "",
  tlsCurvePreferences: "",
  cert: "",
  disableSystemRoot: false,
  publicKey: "",
  shortId: "",
  spiderX: "",
  ech: "",
  vcn: "",
  pcs: "",
  pqv: "",
} as const;

function emptyProfile(protocol: "vless"): Vless;
function emptyProfile(protocol: "vmess"): Vmess;
function emptyProfile(protocol: "trojan"): Trojan;
function emptyProfile(protocol: Profile["protocol"]): Profile {
  switch (protocol) {
    case "vless":
      return { ...commonBase, protocol, uuid: "", flow: "", encryption: "none" };
    case "vmess":
      return { ...commonBase, protocol, uuid: "", encryption: "auto" };
    default:
      return { ...commonBase, protocol: "trojan", password: "", flow: "" };
  }
}

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

function vless(over: Partial<Vless> = {}): Vless {
  return {
    ...emptyProfile("vless"),
    uuid: "11111111-1111-1111-1111-111111111111",
    address: "ex.com",
    port: 443,
    ...over,
  };
}

function vmess(over: Partial<Vmess> = {}): Vmess {
  return {
    ...emptyProfile("vmess"),
    uuid: "22222222-2222-2222-2222-222222222222",
    address: "ex.com",
    port: 80,
    ...over,
  };
}

function trojan(over: Partial<Trojan> = {}): Trojan {
  return { ...emptyProfile("trojan"), address: "ex.com", port: 443, password: "secret", ...over };
}

describe("buildOutbound", () => {
  it("vless + reality maps publicKey/shortId/fingerprint", () => {
    const p = vless({
      security: "reality",
      sni: "www.apple.com",
      publicKey: "PBK",
      shortId: "ab12",
      spiderX: "/",
      fingerprint: "chrome",
      flow: "xtls-rprx-vision",
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.protocol).toBe("vless");
    expect(o.settings.vnext?.[0].users[0].id).toBe(p.uuid);
    expect(o.settings.vnext?.[0].users[0].flow).toBe("xtls-rprx-vision");
    expect(o.streamSettings.security).toBe("reality");
    expect(o.streamSettings.realitySettings?.publicKey).toBe("PBK");
    expect(o.streamSettings.realitySettings?.shortId).toBe("ab12");
    expect(o.streamSettings.realitySettings?.fingerprint).toBe("chrome");
  });

  it("vless + ws + tls maps wsSettings + tlsSettings", () => {
    const p = vless({
      network: "ws",
      host: "cdn.ex.com",
      path: "/ray",
      wsEarlyData: 2048,
      wsEarlyDataHeader: "Sec-WebSocket-Protocol",
      security: "tls",
      sni: "cdn.ex.com",
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.network).toBe("ws");
    expect(o.streamSettings.wsSettings?.path).toBe("/ray?ed=2048&eh=Sec-WebSocket-Protocol");
    expect(o.streamSettings.wsSettings?.host).toBe("cdn.ex.com");
    expect(o.streamSettings.tlsSettings?.serverName).toBe("cdn.ex.com");
  });

  it("ws heartbeatPeriod emitted in wsSettings", () => {
    const p = vless({ network: "ws", path: "/", wsHeartbeatPeriod: 30 });
    const o = viewOutbound(buildOutbound(p, settings));
    expect((o.streamSettings.wsSettings as Record<string, unknown>)?.heartbeatPeriod).toBe(30);
  });

  it("tls rejectUnknownSni and enableSessionResumption emitted", () => {
    const p = vless({
      security: "tls",
      sni: "ex.com",
      rejectUnknownSni: true,
      enableSessionResumption: true,
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.tlsSettings?.rejectUnknownSni).toBe(true);
    expect(o.streamSettings.tlsSettings?.enableSessionResumption).toBe(true);
  });

  it("vmess sets users security, alterId and grpc serviceName", () => {
    const p = vmess({
      alterId: 9,
      encryption: "auto",
      network: "grpc",
      serviceName: "gsvc",
      authority: "auth.ex.com",
      grpcMode: "multi",
      grpcIdleTimeout: 60,
      grpcHealthCheckTimeout: 20,
      grpcPermitWithoutStream: true,
      grpcInitialWindowsSize: 65536,
      userAgent: "grpc-agent",
      security: "none",
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.protocol).toBe("vmess");
    expect(o.settings.vnext?.[0].users[0].security).toBe("auto");
    expect(o.settings.vnext?.[0].users[0].alterId).toBe(9);
    expect(o.streamSettings.grpcSettings?.serviceName).toBe("gsvc");
    expect(o.streamSettings.grpcSettings?.authority).toBe("auth.ex.com");
    expect(o.streamSettings.grpcSettings?.multiMode).toBe(true);
    expect(o.streamSettings.grpcSettings).toMatchObject({
      idle_timeout: 60,
      health_check_timeout: 20,
      permit_without_stream: true,
      initial_windows_size: 65536,
      user_agent: "grpc-agent",
    });
  });

  it("trojan maps password and flow into servers", () => {
    const p = trojan({ flow: "xtls-rprx-vision", security: "tls", sni: "ex.com" });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.protocol).toBe("trojan");
    expect(o.settings.servers?.[0].password).toBe("secret");
    expect(o.settings.servers?.[0].flow).toBe("xtls-rprx-vision");
  });

  it("mux + xudp + fragment applied from profile/settings", () => {
    const p = vless({ security: "tls", sni: "ex.com", muxEnabled: true });
    const o = viewOutbound(
      buildOutbound(p, {
        ...settings,
        mux: false,
        muxConcurrency: 16,
        muxXudpConcurrency: 32,
        muxXudp443: "proxy",
        fragment: true,
        fragmentLength: "40-60",
        fragmentDelay: "5-10",
      }),
    );
    expect(o.mux?.enabled).toBe(true);
    expect(o.mux?.concurrency).toBe(16);
    expect(o.mux?.xudpConcurrency).toBe(32);
    expect(o.mux?.xudpProxyUDP443).toBe("proxy");
    expect(o.streamSettings.finalmask?.tcp).toEqual([
      { type: "fragment", settings: { packets: "tlshello", length: "40-60", delay: "5-10" } },
    ]);
  });

  it("grpc multiMode and authority emitted", () => {
    const p = vless({
      network: "grpc",
      serviceName: "gsvc",
      authority: "auth.ex.com",
      grpcMode: "multi",
      security: "none",
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.grpcSettings?.serviceName).toBe("gsvc");
    expect(o.streamSettings.grpcSettings?.authority).toBe("auth.ex.com");
    expect(o.streamSettings.grpcSettings?.multiMode).toBe(true);
  });

  it("xhttp mode and extra emitted", () => {
    const p = vless({
      network: "xhttp",
      host: "cdn.ex.com",
      path: "/xr",
      xhttpMode: "packet",
      xhttpExtra: '{"opt":"val"}',
      security: "none",
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.xhttpSettings?.host).toBe("cdn.ex.com");
    expect(o.streamSettings.xhttpSettings?.path).toBe("/xr");
    expect(o.streamSettings.xhttpSettings?.mode).toBe("packet");
    expect(o.streamSettings.xhttpSettings?.extra).toEqual({ opt: "val" });
  });

  it("kcp emits seed and advanced transport fields", () => {
    const p = vless({
      network: "kcp",
      headerType: "wechat-video",
      kcpSeed: "seed-1",
      kcpMtu: 1200,
      kcpTti: 50,
      kcpUplink: 8,
      kcpDownlink: 32,
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.kcpSettings).toEqual({
      mtu: 1200,
      tti: 50,
      uplinkCapacity: 8,
      downlinkCapacity: 32,
    });
  });

  it("tls extras (ech, vcn, pcs) emitted in tlsSettings", () => {
    const p = vless({
      security: "tls",
      sni: "ex.com",
      ech: "base64ech",
      vcn: "verify.name",
      pcs: "pin256value",
      tlsMinVersion: "1.2",
      tlsMaxVersion: "1.3",
      tlsCipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
      tlsCurvePreferences: "X25519,P-256",
      cert: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
      disableSystemRoot: true,
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.tlsSettings?.echConfigList).toBe("base64ech");
    expect(o.streamSettings.tlsSettings?.verifyPeerCertByName).toBe("verify.name");
    expect(o.streamSettings.tlsSettings?.pinnedPeerCertSha256).toBe("pin256value");
    expect(o.streamSettings.tlsSettings).toMatchObject({
      minVersion: "1.2",
      maxVersion: "1.3",
      cipherSuites: "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
      curvePreferences: ["X25519", "P-256"],
      disableSystemRoot: true,
    });
    expect(
      Array.isArray((o.streamSettings.tlsSettings as Record<string, unknown>)?.certificates),
    ).toBe(true);
  });

  it("reality extras (pqv) emitted in realitySettings", () => {
    const p = vless({
      security: "reality",
      sni: "ex.com",
      publicKey: "PBK",
      pqv: "mlsdaVal",
      ech: "should-not-emit",
      vcn: "verify.name",
      pcs: "pin256",
    });
    const o = viewOutbound(buildOutbound(p, settings));
    expect(o.streamSettings.realitySettings?.mldsa65Verify).toBe("mlsdaVal");
    expect(o.streamSettings.realitySettings?.echConfigList).toBeUndefined();
    expect(o.streamSettings.realitySettings?.verifyPeerCertByName).toBeUndefined();
    expect(o.streamSettings.realitySettings?.pinnedPeerCertSha256).toBeUndefined();
  });

  it("hysteria2 can be built for xray with finalmask settings", () => {
    const o = viewOutbound(
      buildOutbound(
        {
          id: "hy2",
          remarks: "hy2",
          groupId: "g-main",
          subId: null,
          ping: null,
          coreType: "xray",
          protocol: "hysteria2",
          address: "hy.ex",
          port: 443,
          password: "pw",
          obfsType: "salamander",
          obfsPassword: "obf",
          ports: "20000-50000",
          hopInterval: "30",
          upMbps: 100,
          downMbps: 200,
          security: "tls",
          sni: "hy.ex",
          fingerprint: "chrome",
          alpn: "h3",
          allowInsecure: false,
          publicKey: "",
          shortId: "",
          spiderX: "",
          ech: "",
          vcn: "",
          pcs: "",
          pqv: "",
        },
        settings,
      ),
    );
    expect(o.protocol).toBe("hysteria");
    expect(o.streamSettings.hysteriaSettings).toEqual({ version: 2, auth: "pw" });
    expect((o.streamSettings.finalmask as Record<string, unknown>)?.quicParams).toBeTruthy();
  });

  it("mux disabled emits no xudp fields", () => {
    const p = vless({ security: "tls", sni: "ex.com", muxEnabled: false });
    const o = viewOutbound(
      buildOutbound(p, { ...settings, mux: true, muxXudpConcurrency: 32, muxXudp443: "proxy" }),
    );
    expect(o.mux).toBeUndefined();
  });

  it("wireguard emits numWorkers and peer keepAlive", () => {
    const p: Extract<Profile, { protocol: "wireguard" }> = {
      id: "p",
      remarks: "wg",
      groupId: "g-main",
      subId: null,
      ping: null,
      protocol: "wireguard",
      address: "wg.ex",
      port: 51820,
      secretKey: "sk",
      peerPublicKey: "pk",
      preSharedKey: "",
      reserved: "",
      localAddress: "10.0.0.2/32",
      mtu: 1420,
      workers: 2,
      persistentKeepalive: 25,
    };
    const o = buildOutbound(p, settings) as unknown as {
      settings: { numWorkers: number; peers: Array<{ keepAlive: number }> };
    };
    expect(o.settings.numWorkers).toBe(2);
    expect(o.settings.peers[0].keepAlive).toBe(25);
  });
});

describe("buildXrayConfig", () => {
  it("produces socks/http inbounds and proxy/direct/block outbounds", () => {
    const cfg = viewConfig(buildXrayConfig(vless({ security: "tls", sni: "ex.com" }), settings));
    expect(cfg.inbounds.map((i) => i.port)).toEqual([10808, 10809]);
    expect(cfg.outbounds.map((o) => o.tag ?? o.protocol)).toContain("proxy");
    expect(cfg.outbounds.some((o) => o.protocol === "freedom")).toBe(true);
    expect(cfg.outbounds.some((o) => o.protocol === "blackhole")).toBe(true);
  });

  it("honors custom local ports and log level", () => {
    const cfg = viewConfig(
      buildXrayConfig(vless({ security: "tls" }), {
        ...settings,
        localSocksPort: 1080,
        localHttpPort: 1081,
        logLevel: "debug",
      }),
    );
    expect(cfg.inbounds[0].port).toBe(1080);
    expect(cfg.inbounds[1].port).toBe(1081);
    expect(cfg.log.loglevel).toBe("debug");
  });

  it("fakeDns adds fakeip server and routing rule", () => {
    const cfg = viewConfig(
      buildXrayConfig(vless({ security: "tls" }), { ...settings, fakeDns: true }),
    );
    expect(cfg.dns.servers[0]).toMatchObject({ address: "fakeip" });
    expect(cfg.routing.domainStrategy).toBe("IPIfNonMatch");
    expect(
      cfg.routing.rules.some((r) => Array.isArray(r.ip) && r.ip.includes("198.18.0.0/15")),
    ).toBe(true);
  });

  it("honors explicit domain strategy", () => {
    const cfg = viewConfig(
      buildXrayConfig(vless({ security: "tls" }), {
        ...settings,
        domainStrategy: "IPOnDemand",
      }),
    );
    expect(cfg.routing.domainStrategy).toBe("IPOnDemand");
  });

  it("routing rule targeting a profile id emits a tagged outbound", () => {
    const active = vless({ id: "active", security: "tls", sni: "a.com" });
    const other = vless({ id: "other", address: "other.com", security: "tls", sni: "b.com" });
    const rules = [
      { id: "r1", remarks: "x", enabled: true, outboundTag: "other", domain: ["example.com"] },
    ];
    const cfg = viewConfig(
      buildXrayConfig(active, { ...settings, routingMode: "rules" }, rules, [active, other]),
    );
    expect(cfg.outbounds.map((o) => o.tag)).toContain("other");
    const userRule = (cfg.routing.rules as Array<{ domain?: string[]; outboundTag?: string }>).find(
      (r) => r.domain?.includes("example.com"),
    );
    expect(userRule?.outboundTag).toBe("other");
  });

  it("routing rule targeting an unknown profile id falls back to proxy", () => {
    const active = vless({ id: "active", security: "tls", sni: "a.com" });
    const rules = [
      { id: "r1", remarks: "x", enabled: true, outboundTag: "ghost", ip: ["1.2.3.4"] },
    ];
    const cfg = viewConfig(
      buildXrayConfig(active, { ...settings, routingMode: "rules" }, rules, [active]),
    );
    expect(cfg.outbounds.map((o) => o.tag)).not.toContain("ghost");
    const userRule = (cfg.routing.rules as Array<{ ip?: string[]; outboundTag?: string }>).find(
      (r) => r.ip?.includes("1.2.3.4"),
    );
    expect(userRule?.outboundTag).toBe("proxy");
  });
});
