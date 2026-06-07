// ============================================================
// src/lib/xray-config.ts
// Build a complete Xray config.json from a structured Profile +
// AdvancedSettings. This is the production replacement for the
// legacy webroot/helper.js `convert_uri_to_xray_json`, but it
// works from typed data instead of re-parsing a share URI.
//
// Generation lives in the frontend (tested here) and the result
// is handed to `kasumi-proxyctl start` which only writes config.json
// and restarts the service — no JSON assembly in shell.
// ============================================================

import type { AdvancedSettings } from "./bridge";
import { buildWsPath, parsePemChain, splitCsv, splitList } from "./config-shared";
import type { Network, Profile, RoutingRule, Security } from "./schema";

type VlessProfile = Extract<Profile, { protocol: "vless" }>;
type VmessProfile = Extract<Profile, { protocol: "vmess" }>;
type TrojanProfile = Extract<Profile, { protocol: "trojan" }>;
type ShadowsocksProfile = Extract<Profile, { protocol: "shadowsocks" }>;
type SocksProfile = Extract<Profile, { protocol: "socks" }>;
type HttpProfile = Extract<Profile, { protocol: "http" }>;
type WireguardProfile = Extract<Profile, { protocol: "wireguard" }>;
type Hysteria2Profile = Extract<Profile, { protocol: "hysteria2" }>;
/** Profiles that carry stream transport settings. */
type StreamProfile = Extract<Profile, { network: Network }>;
/** Profiles that carry TLS/Reality settings (stream protocols + http). */
type TlsProfile = Extract<Profile, { security: Security }>;
type JsonObject = Record<string, unknown>;
type TransportKey =
  | "wsSettings"
  | "httpupgradeSettings"
  | "grpcSettings"
  | "xhttpSettings"
  | "tcpSettings"
  | "kcpSettings";
type TransportSetting = { key: TransportKey; value: JsonObject };

type StreamSettings = {
  network?: Network;
  security: Security;
  sockopt: {
    mark?: number;
    dialerProxy?: string;
    fragment?: JsonObject;
  };
  finalmask?: JsonObject;
  tlsSettings?: JsonObject;
  realitySettings?: JsonObject;
  hysteriaSettings?: JsonObject;
  wsSettings?: JsonObject;
  httpupgradeSettings?: JsonObject;
  grpcSettings?: JsonObject;
  xhttpSettings?: JsonObject;
  tcpSettings?: JsonObject;
  kcpSettings?: JsonObject;
};

type OutboundConfig = {
  tag: "proxy";
  protocol: Profile["protocol"] | "hysteria";
  settings: JsonObject;
  streamSettings?: StreamSettings;
  mux?: JsonObject;
};

/** Safely parse a JSON string, returning null on failure. */
function parseJsonSafe(s: string): unknown | null {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

/* ---------- outbound protocol builders ---------- */

function buildVmessOutbound(p: VmessProfile): OutboundConfig {
  return {
    tag: "proxy",
    protocol: "vmess",
    settings: {
      vnext: [
        {
          address: p.address,
          port: p.port,
          users: [{ id: p.uuid, alterId: p.alterId ?? 0, security: p.encryption || "auto" }],
        },
      ],
    },
  };
}

function buildVlessOutbound(p: VlessProfile): OutboundConfig {
  return {
    tag: "proxy",
    protocol: "vless",
    settings: {
      vnext: [
        {
          address: p.address,
          port: p.port,
          users: [
            {
              id: p.uuid,
              encryption: p.encryption || "none",
              ...(p.flow ? { flow: p.flow } : {}),
            },
          ],
        },
      ],
    },
  };
}

function buildTrojanOutbound(p: TrojanProfile): OutboundConfig {
  return {
    tag: "proxy",
    protocol: "trojan",
    settings: {
      servers: [
        {
          address: p.address,
          port: p.port,
          password: p.password,
          ...(p.flow ? { flow: p.flow } : {}),
        },
      ],
    },
  };
}

function buildShadowsocksOutbound(p: ShadowsocksProfile): OutboundConfig {
  return {
    tag: "proxy",
    protocol: "shadowsocks",
    settings: {
      servers: [
        { address: p.address, port: p.port, method: p.method, password: p.password, uot: true },
      ],
    },
  };
}

function buildSocksOutbound(p: SocksProfile): OutboundConfig {
  const user = p.username ? { users: [{ user: p.username, pass: p.password }] } : {};
  return {
    tag: "proxy",
    protocol: "socks",
    settings: { servers: [{ address: p.address, port: p.port, ...user }] },
  };
}

function buildHttpOutbound(p: HttpProfile): OutboundConfig {
  const user = p.username ? { users: [{ user: p.username, pass: p.password }] } : {};
  return {
    tag: "proxy",
    protocol: "http",
    settings: { servers: [{ address: p.address, port: p.port, ...user }] },
  };
}

function buildWireguardOutbound(p: WireguardProfile): OutboundConfig {
  const reserved = p.reserved
    ? p.reserved
        .split(",")
        .map((x) => Number(x.trim()))
        .filter((n) => !Number.isNaN(n))
    : undefined;
  return {
    tag: "proxy",
    protocol: "wireguard",
    settings: {
      secretKey: p.secretKey,
      address: p.localAddress ? p.localAddress.split(",").map((x) => x.trim()) : ["172.16.0.2/32"],
      mtu: p.mtu || 1420,
      ...(p.workers ? { numWorkers: p.workers } : {}),
      ...(reserved?.length ? { reserved } : {}),
      peers: [
        {
          publicKey: p.peerPublicKey,
          endpoint: `${p.address}:${p.port}`,
          ...(p.preSharedKey ? { preSharedKey: p.preSharedKey } : {}),
          ...(p.persistentKeepalive ? { keepAlive: p.persistentKeepalive } : {}),
          allowedIPs: ["0.0.0.0/0", "::/0"],
        },
      ],
    },
  };
}

function buildHysteria2Outbound(p: Hysteria2Profile): OutboundConfig {
  const quicParams: JsonObject = {};
  if (p.ports.trim() && /[:\-,]/.test(p.ports)) {
    const hop = Number(p.hopInterval);
    quicParams.udpHop = {
      ports: p.ports.replace(/:/g, "-"),
      interval: Number.isFinite(hop) && hop >= 5 ? String(hop) : "30",
    };
  }
  if (p.upMbps > 0 || p.downMbps > 0) {
    quicParams.congestion = "brutal";
    if (p.upMbps > 0) quicParams.brutalUp = `${p.upMbps}mbps`;
    if (p.downMbps > 0) quicParams.brutalDown = `${p.downMbps}mbps`;
  } else {
    quicParams.congestion = "bbr";
  }

  const finalmask: JsonObject = { quicParams };
  if (p.obfsType === "salamander" && p.obfsPassword) {
    finalmask.udp = [{ type: "salamander", settings: { password: p.obfsPassword } }];
  }

  return {
    tag: "proxy",
    protocol: "hysteria",
    settings: { version: 2, address: p.address, port: p.port },
    streamSettings: {
      security: "tls",
      sockopt: {},
      tlsSettings: buildTlsSecurity(p),
      hysteriaSettings: { version: 2, auth: p.password },
      finalmask,
    },
  };
}

/* ---------- stream settings builders ---------- */

function buildTlsSecurity(p: TlsProfile): JsonObject {
  const pin = p.pcs;
  const certs = parsePemChain(p.cert)?.map((cert) => ({
    certificate: cert.split(/\r?\n/).filter(Boolean),
  }));
  return {
    serverName: p.sni || ("host" in p ? p.host : "") || p.address,
    ...(p.fingerprint ? { fingerprint: p.fingerprint } : {}),
    ...(splitCsv(p.alpn) ? { alpn: splitCsv(p.alpn) } : {}),
    ...(p.allowInsecure ? { allowInsecure: true } : {}),
    ...(p.tlsMinVersion ? { minVersion: p.tlsMinVersion } : {}),
    ...(p.tlsMaxVersion ? { maxVersion: p.tlsMaxVersion } : {}),
    ...(p.tlsCipherSuites ? { cipherSuites: p.tlsCipherSuites } : {}),
    ...(splitCsv(p.tlsCurvePreferences)
      ? { curvePreferences: splitCsv(p.tlsCurvePreferences) }
      : {}),
    ...(certs?.length ? { certificates: certs } : {}),
    ...(p.disableSystemRoot || certs?.length ? { disableSystemRoot: true } : {}),
    ...(pin ? { pinnedPeerCertSha256: pin } : {}),
    ...(p.ech ? { echConfigList: p.ech } : {}),
    ...(p.vcn ? { verifyPeerCertByName: p.vcn } : {}),
    ...(p.rejectUnknownSni ? { rejectUnknownSni: true } : {}),
    ...(p.enableSessionResumption ? { enableSessionResumption: true } : {}),
  };
}

function buildRealitySecurity(p: TlsProfile): JsonObject {
  return {
    serverName: p.sni,
    ...(p.fingerprint ? { fingerprint: p.fingerprint } : {}),
    publicKey: p.publicKey,
    ...(p.shortId ? { shortId: p.shortId } : {}),
    ...(p.spiderX ? { spiderX: p.spiderX } : {}),
    ...(p.pqv ? { mldsa65Verify: p.pqv } : {}),
  };
}

function buildTransportSetting(p: StreamProfile): TransportSetting | undefined {
  switch (p.network) {
    case "ws":
      return {
        key: "wsSettings",
        value: {
          path: buildWsPath(p.path || "/", p.wsEarlyData, p.wsEarlyDataHeader),
          host: p.host || p.sni || "",
          ...(p.wsHeartbeatPeriod ? { heartbeatPeriod: p.wsHeartbeatPeriod } : {}),
        },
      };
    case "httpupgrade":
      return {
        key: "httpupgradeSettings",
        value: { path: p.path || "/", host: p.host || p.sni || "" },
      };
    case "grpc":
      return {
        key: "grpcSettings",
        value: {
          serviceName: p.serviceName || p.path || "",
          authority: p.authority || p.host || "",
          ...(p.grpcMode === "multi" ? { multiMode: true } : {}),
          ...(p.grpcIdleTimeout ? { idle_timeout: p.grpcIdleTimeout } : {}),
          ...(p.grpcHealthCheckTimeout ? { health_check_timeout: p.grpcHealthCheckTimeout } : {}),
          ...(p.grpcPermitWithoutStream ? { permit_without_stream: true } : {}),
          ...(p.grpcInitialWindowsSize ? { initial_windows_size: p.grpcInitialWindowsSize } : {}),
          ...(p.userAgent ? { user_agent: p.userAgent } : {}),
        },
      };
    case "xhttp":
      return {
        key: "xhttpSettings",
        value: {
          path: p.path || "/",
          host: p.host || p.sni || "",
          ...(p.xhttpMode ? { mode: p.xhttpMode } : {}),
          ...(p.xhttpExtra ? { extra: parseJsonSafe(p.xhttpExtra) ?? p.xhttpExtra } : {}),
        },
      };
    case "tcp":
      if (p.headerType !== "http") return undefined;
      return {
        key: "tcpSettings",
        value: {
          header: {
            type: "http",
            request: { path: [p.path || "/"], headers: p.host ? { Host: p.host.split(",") } : {} },
          },
        },
      };
    case "kcp":
      return {
        key: "kcpSettings",
        value: {
          ...(p.kcpMtu ? { mtu: p.kcpMtu } : {}),
          ...(p.kcpTti ? { tti: p.kcpTti } : {}),
          ...(p.kcpUplink ? { uplinkCapacity: p.kcpUplink } : {}),
          ...(p.kcpDownlink ? { downlinkCapacity: p.kcpDownlink } : {}),
        },
      };
    default:
      return undefined;
  }
}

function buildFragmentSettings(s: AdvancedSettings): JsonObject | undefined {
  if (!s.fragment) return undefined;
  return {
    packets: s.fragmentPackets || "tlshello",
    length: s.fragmentLength || "50-100",
    delay: s.fragmentDelay || "10-20",
  };
}

function buildMuxSettings(p: Profile, s: AdvancedSettings): JsonObject | undefined {
  const muxEnabled = "muxEnabled" in p ? p.muxEnabled : false;
  if (!muxEnabled) return undefined;
  return {
    enabled: true,
    concurrency: Number(s.muxConcurrency) || 8,
    ...(s.muxXudpConcurrency != null ? { xudpConcurrency: Number(s.muxXudpConcurrency) } : {}),
    ...(s.muxXudp443 ? { xudpProxyUDP443: s.muxXudp443 } : {}),
  };
}

/* ---------- main outbound builder ---------- */

const isStream = (p: Profile): p is StreamProfile => "network" in p;
const isTls = (p: Profile): p is TlsProfile => "security" in p;

/** Build the outbound `proxy` object for a profile. */
export function buildOutbound(p: Profile, s: AdvancedSettings): OutboundConfig {
  let outbound: OutboundConfig;
  switch (p.protocol) {
    case "vmess":
      outbound = buildVmessOutbound(p);
      break;
    case "vless":
      outbound = buildVlessOutbound(p);
      break;
    case "trojan":
      outbound = buildTrojanOutbound(p);
      break;
    case "shadowsocks":
      outbound = buildShadowsocksOutbound(p);
      break;
    case "socks":
      return buildSocksOutbound(p); // no stream settings
    case "http":
      outbound = buildHttpOutbound(p);
      break;
    case "wireguard":
      return buildWireguardOutbound(p); // no stream settings
    case "hysteria2":
      return buildHysteria2Outbound(p);
    case "tuic":
    case "anytls":
    case "naive":
    case "shadowtls":
      throw new Error(`${p.protocol} requires sing-box (use buildSingboxConfig)`);
    case "custom":
      throw new Error("custom profile has no outbound (use buildXrayConfig)");
    default:
      throw new Error(`unsupported protocol: ${String(p satisfies never)}`);
  }

  // TLS/Reality apply to stream protocols and http
  if (isTls(p)) {
    if (p.security === "tls")
      outbound.streamSettings = {
        ...(outbound.streamSettings ?? emptyStream(p)),
        tlsSettings: buildTlsSecurity(p),
      };
    else if (p.security === "reality")
      outbound.streamSettings = {
        ...(outbound.streamSettings ?? emptyStream(p)),
        realitySettings: buildRealitySecurity(p),
      };
  }

  // Transport + fragment + mux apply to stream protocols only
  if (isStream(p)) {
    const stream: StreamSettings = outbound.streamSettings ?? emptyStream(p);
    stream.network = p.network;
    const transport = buildTransportSetting(p);
    if (transport) stream[transport.key] = transport.value;
    const fragment = buildFragmentSettings(s);
    if (fragment) {
      stream.finalmask = { ...stream.finalmask, tcp: [{ type: "fragment", settings: fragment }] };
    }
    outbound.streamSettings = stream;

    const mux = buildMuxSettings(p, s);
    if (mux) outbound.mux = mux;
  }

  return outbound;
}

function emptyStream(p: TlsProfile): StreamSettings {
  // The core runs as root (uid 0); the iptables capture chain only marks
  // uid 1000 and 9999+, so the core's outbound is never pulled into the tun
  // and needs no `mark` to escape it. A blanket `dialerProxy: "direct"` also
  // breaks multiplexed transports (gRPC/H2), so we leave sockopt empty and
  // only attach `fragment` on demand below.
  return {
    network: "network" in p ? p.network : "tcp",
    security: p.security,
    sockopt: {},
  };
}

function buildRuleObject(
  rule: RoutingRule,
  resolveOutboundTag: (tag: string) => string,
): JsonObject {
  return {
    type: "field",
    ...(rule.domain?.length ? { domain: rule.domain } : {}),
    ...(rule.ip?.length ? { ip: rule.ip } : {}),
    ...(rule.port ? { port: rule.port } : {}),
    ...(rule.network ? { network: rule.network } : {}),
    ...(rule.protocol?.length ? { protocol: rule.protocol } : {}),
    outboundTag: resolveOutboundTag(rule.outboundTag),
  };
}

/** Built-in outbound tags that are not profile references. */
const SPECIAL_OUTBOUND_TAGS = new Set(["proxy", "direct", "block"]);

/**
 * Build extra outbounds for routing rules that target a specific profile (by id).
 * Returns the extra outbound objects plus a resolver mapping each rule tag to the
 * actual outbound tag in the config. Profiles incompatible with the active engine
 * (e.g. a different core) cannot be embedded and fall back to "proxy".
 */
function buildProfileOutbounds(
  active: Profile,
  s: AdvancedSettings,
  routingRules: RoutingRule[],
  profiles: Profile[],
  buildFor: (profile: Profile) => JsonObject,
): { outbounds: JsonObject[]; resolveOutboundTag: (tag: string) => string } {
  const resolved = new Map<string, string>();
  const outbounds: JsonObject[] = [];
  if (s.routingMode === "rules") {
    const referenced = new Set(
      routingRules
        .filter((rule) => rule.enabled && !SPECIAL_OUTBOUND_TAGS.has(rule.outboundTag))
        .map((rule) => rule.outboundTag),
    );
    for (const id of referenced) {
      if (id === active.id) {
        resolved.set(id, "proxy");
        continue;
      }
      const profile = profiles.find((item) => item.id === id);
      if (!profile) {
        resolved.set(id, "proxy");
        continue;
      }
      try {
        outbounds.push({ ...buildFor(profile), tag: id });
        resolved.set(id, id);
      } catch {
        // Profile cannot run on the active engine — route via the primary proxy instead.
        resolved.set(id, "proxy");
      }
    }
  }
  const resolveOutboundTag = (tag: string) =>
    SPECIAL_OUTBOUND_TAGS.has(tag) ? tag : (resolved.get(tag) ?? "proxy");
  return { outbounds, resolveOutboundTag };
}

/** Build the full Xray config object from a profile + settings. */
export function buildXrayConfig(
  p: Profile,
  s: AdvancedSettings,
  routingRules: RoutingRule[] = [],
  profiles: Profile[] = [],
): JsonObject {
  // A custom profile carries a complete config.json verbatim.
  if (p.protocol === "custom") {
    const parsed = parseJsonSafe(p.raw);
    if (parsed && typeof parsed === "object") return parsed as JsonObject;
    throw new Error("custom profile contains invalid JSON");
  }

  const outbound = buildOutbound(p, s);
  const { outbounds: profileOutbounds, resolveOutboundTag } = buildProfileOutbounds(
    p,
    s,
    routingRules,
    profiles,
    (profile) => buildOutbound(profile, s),
  );
  const socksPort = s.localSocksPort ?? 10808;
  const httpPort = s.localHttpPort ?? 10809;
  const forcePort = socksPort + 2;
  const hasForce = Object.values(s.appFilter ?? {}).some((m) => m === "force-proxy");
  const dnsOutboundTag = s.dnsViaProxy ? "proxy" : "direct";

  return {
    log: { loglevel: s.logLevel || "warning" },
    dns: buildDns(s),
    inbounds: [
      {
        tag: "socks-in",
        port: socksPort,
        listen: "127.0.0.1",
        protocol: "socks",
        settings: { auth: "noauth", udp: true },
        sniffing: {
          enabled: s.domainSniffing,
          destOverride: ["http", "tls", "quic"],
          routeOnly: s.routeOnly,
        },
      },
      {
        tag: "http-in",
        port: httpPort,
        listen: "127.0.0.1",
        protocol: "http",
        settings: { allowTransparent: false },
      },
      ...(hasForce
        ? [
            {
              tag: "force-in",
              port: forcePort,
              listen: "127.0.0.1",
              protocol: "socks",
              settings: { auth: "noauth", udp: true },
            },
          ]
        : []),
    ],
    outbounds: [
      outbound,
      ...profileOutbounds,
      { protocol: "freedom", tag: "direct" },
      { protocol: "blackhole", tag: "block" },
    ],
    routing: buildRouting(s, dnsOutboundTag, routingRules, resolveOutboundTag),
  };
}

/* ---------- DNS / inbound / routing builders ---------- */

/** Parse "host=ip" lines or a raw JSON object into a hosts map. */
function parseHosts(v: string | undefined): JsonObject | undefined {
  if (!v?.trim()) return undefined;
  const asJson = parseJsonSafe(v.trim());
  if (asJson && typeof asJson === "object" && !Array.isArray(asJson)) return asJson as JsonObject;
  const out: JsonObject = {};
  for (const line of v.split(/\r?\n/)) {
    const [host, ip] = line.split("=").map((x) => x.trim());
    if (host && ip) out[host] = ip;
  }
  return Object.keys(out).length ? out : undefined;
}

function buildDns(s: AdvancedSettings): JsonObject {
  const remote = splitList(s.remoteDns, ["1.1.1.1", "8.8.8.8"]);
  const servers: Array<string | JsonObject> = [...remote];
  const _routingMode = s.routingMode as string;
  if (s.fakeDns)
    servers.unshift({ address: "fakeip", domains: ["regexp:.+"], expectIPs: ["geoip:!private"] });
  const hosts = parseHosts(s.dnsHosts);
  const queryStrategy = s.ipv6Enabled ? "UseIP" : "UseIPv4";
  return { servers, queryStrategy, ...(hosts ? { hosts } : {}) };
}

function buildRouting(
  s: AdvancedSettings,
  dnsOutboundTag: string,
  routingRules: RoutingRule[],
  resolveOutboundTag: (tag: string) => string = (tag) => tag,
): JsonObject {
  const domainStrategy = s.domainStrategy;
  // force-in bypasses all routing rules — always proxied
  const forceRule = {
    type: "field",
    inboundTag: ["force-in"],
    network: "tcp,udp",
    outboundTag: "proxy",
  };
  const hasForceRule = Object.values(s.appFilter ?? {}).some((m) => m === "force-proxy");
  const dnsRule = {
    type: "field",
    inboundTag: ["socks-in", "http-in"],
    port: 53,
    outboundTag: dnsOutboundTag,
  };
  const finalRule = {
    type: "field",
    inboundTag: ["socks-in", "http-in"],
    network: "tcp,udp",
    outboundTag: "proxy",
  };
  const routingMode = s.routingMode as string;

  if (routingMode === "rules" && routingRules.length) {
    const userRules = routingRules
      .filter((rule) => rule.enabled)
      .map((rule) => buildRuleObject(rule, resolveOutboundTag));
    const pre = hasForceRule ? [forceRule] : [];
    return { domainStrategy, rules: [...pre, dnsRule, ...userRules, finalRule] };
  }

  // custom routing: user-provided JSON array of rules, wrapped by dns + final rules
  if (routingMode === "custom" && s.customRouting?.trim()) {
    const parsed = parseJsonSafe(s.customRouting);
    if (Array.isArray(parsed)) {
      const pre = hasForceRule ? [forceRule] : [];
      return { domainStrategy, rules: [...pre, dnsRule, ...parsed, finalRule] };
    }
  }

  const rules: JsonObject[] = hasForceRule ? [forceRule, dnsRule] : [dnsRule];
  if (s.fakeDns) rules.push({ type: "field", ip: ["198.18.0.0/15"], outboundTag: "proxy" });
  // LAN/private traffic is excluded unconditionally at the iptables layer
  // (append_local_ipv4/ipv6_exclusions in service.sh), so no routing rule is needed here.
  rules.push(finalRule);
  return { domainStrategy, rules };
}

/** Serialize the config for handing to `kasumi-proxyctl start`. */
export function buildXrayConfigJSON(
  p: Profile,
  s: AdvancedSettings,
  routingRules: RoutingRule[] = [],
  profiles: Profile[] = [],
): string {
  return JSON.stringify(buildXrayConfig(p, s, routingRules, profiles), null, 2);
}
