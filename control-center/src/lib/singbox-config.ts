// ============================================================
// src/lib/singbox-config.ts
// Build a complete sing-box config from a structured Profile +
// AdvancedSettings. This is the sing-box counterpart of
// xray-config.ts and is used for profiles whose resolved core is
// "sing-box" (always Hysteria2/TUIC; optionally others via the
// per-protocol core table).
//
// Routing rules are compiled from the same structured rule list as
// Xray, but translated into sing-box route rules + remote rule_set
// declarations for geo-based matches.
// ============================================================

import type { AdvancedSettings } from "./bridge";
import { parsePemChain, splitCsv, splitList } from "./config-shared";
import type { Profile, RoutingRule, Security } from "./schema";

type JsonObject = Record<string, unknown>;
const SRS_DIR = "/data/adb/kasumi-proxy";

const addStringList = (target: JsonObject, key: string, value: string) => {
  const current = Array.isArray(target[key]) ? (target[key] as string[]) : [];
  current.push(value);
  target[key] = current;
};

const addNumberList = (target: JsonObject, key: string, value: number) => {
  const current = Array.isArray(target[key]) ? (target[key] as number[]) : [];
  current.push(value);
  target[key] = current;
};

const hasMatchFields = (rule: JsonObject, keys: string[]) => keys.some((key) => key in rule);

/* ---------- protocol narrowing ---------- */
type P<K extends Profile["protocol"]> = Extract<Profile, { protocol: K }>;

type TlsProfile = Extract<Profile, { security: Security }>;
function hasTls(p: Profile): p is TlsProfile {
  return "security" in p;
}
function hasTransport(p: Profile): boolean {
  return "network" in p;
}

/* ---------- TLS ---------- */
function buildSingboxTls(p: Profile, force: boolean, s: AdvancedSettings): JsonObject | undefined {
  if (!hasTls(p)) return undefined;
  const tlsActive = force || p.security === "tls" || p.security === "reality";
  if (!tlsActive) return undefined;

  const host = "host" in p ? p.host : "";
  const authority = "authority" in p ? p.authority : "";
  const pin = ("pinSha256" in p && p.pinSha256) || p.pcs;
  const certs = parsePemChain(p.cert);
  const serverName = p.sni || authority || host || p.address;
  const tls: JsonObject = {
    enabled: true,
    server_name: serverName,
    insecure: p.allowInsecure,
    ...(p.disableSni ? { disable_sni: true } : {}),
    ...(p.tlsMinVersion ? { min_version: p.tlsMinVersion } : {}),
    ...(p.tlsMaxVersion ? { max_version: p.tlsMaxVersion } : {}),
    ...(splitCsv(p.tlsCipherSuites) ? { cipher_suites: splitCsv(p.tlsCipherSuites) } : {}),
    ...(splitCsv(p.tlsCurvePreferences)
      ? { curve_preferences: splitCsv(p.tlsCurvePreferences) }
      : {}),
    ...(certs?.length ? { certificate: certs } : {}),
    ...(s.fragment ? { record_fragment: true } : {}),
  };
  const alpn = splitCsv(p.alpn);
  if (alpn) tls.alpn = alpn;
  if (pin) tls.certificate_public_key_sha256 = [pin];
  if (p.ech) tls.ech = { enabled: true, config: [p.ech] };
  if (p.fingerprint) tls.utls = { enabled: true, fingerprint: p.fingerprint };
  if (p.security === "reality") {
    tls.reality = { enabled: true, public_key: p.publicKey, short_id: p.shortId };
    tls.insecure = false;
  }
  return tls;
}

/* ---------- transport ---------- */
function buildSingboxTransport(p: Profile): JsonObject | undefined {
  if (!hasTransport(p)) return undefined;
  const net = "network" in p ? p.network : "tcp";
  const host = "host" in p ? p.host : "";
  const path = "path" in p ? p.path : "";
  const serviceName = "serviceName" in p ? p.serviceName : "";
  const headerType = "headerType" in p ? p.headerType : "none";

  switch (net) {
    case "ws": {
      const t: JsonObject = { type: "ws" };
      if (path) t.path = path;
      if (host) t.headers = { Host: host };
      const wsEarlyData = "wsEarlyData" in p ? p.wsEarlyData : 0;
      const wsEarlyDataHeader = "wsEarlyDataHeader" in p ? p.wsEarlyDataHeader : "";
      if ((wsEarlyData || 0) > 0) {
        t.max_early_data = wsEarlyData;
        t.early_data_header_name = wsEarlyDataHeader || "Sec-WebSocket-Protocol";
      } else if (wsEarlyDataHeader) {
        t.early_data_header_name = wsEarlyDataHeader;
      }
      return t;
    }
    case "grpc": {
      const t: JsonObject = { type: "grpc", service_name: serviceName || path };
      const grpcIdleTimeout = "grpcIdleTimeout" in p ? p.grpcIdleTimeout : 0;
      const grpcPingTimeout = "grpcPingTimeout" in p ? p.grpcPingTimeout : 0;
      const grpcPermitWithoutStream =
        "grpcPermitWithoutStream" in p ? p.grpcPermitWithoutStream : false;
      if (grpcIdleTimeout) t.idle_timeout = `${grpcIdleTimeout}s`;
      if (grpcPingTimeout) t.ping_timeout = `${grpcPingTimeout}s`;
      if (grpcPermitWithoutStream) t.permit_without_stream = true;
      return t;
    }
    case "h2": {
      const t: JsonObject = { type: "http" };
      if (host) t.host = splitCsv(host);
      if (path) t.path = path;
      const h2Idle = "grpcIdleTimeout" in p ? p.grpcIdleTimeout : 0;
      const h2Ping = "grpcPingTimeout" in p ? p.grpcPingTimeout : 0;
      if (h2Idle) t.idle_timeout = `${h2Idle}s`;
      if (h2Ping) t.ping_timeout = `${h2Ping}s`;
      return t;
    }
    case "httpupgrade": {
      const t: JsonObject = { type: "httpupgrade" };
      if (path) t.path = path;
      if (host) t.host = host;
      return t;
    }
    case "quic":
      return { type: "quic" };
    case "tcp":
      if (headerType === "http") {
        const t: JsonObject = { type: "http" };
        if (host) t.host = splitCsv(host);
        if (path) t.path = path;
        return t;
      }
      return undefined;
    default:
      return undefined;
  }
}

function buildSingboxMux(p: Profile, s: AdvancedSettings): JsonObject | undefined {
  const enabled = "muxEnabled" in p ? p.muxEnabled : false;
  if (!enabled) return undefined;
  return { enabled: true, protocol: "h2mux", max_connections: s.muxConcurrency };
}

function buildServerPorts(ports: string): string[] {
  return (splitCsv(ports) ?? []).map((x) => {
    const port = x.replace(/-/g, ":");
    return port.includes(":") ? port : `${port}:${port}`;
  });
}

/* ---------- outbound per protocol ---------- */
export function buildSingboxOutbound(p: Profile, s: AdvancedSettings): JsonObject {
  const base: JsonObject = { tag: "proxy", type: p.protocol };
  if (p.protocol !== "custom") {
    base.server = p.address;
    base.server_port = p.port;
  }

  const applyTls = (force: boolean) => {
    const tls = buildSingboxTls(p, force, s);
    if (tls) base.tls = tls;
  };
  const applyTransport = () => {
    const tr = buildSingboxTransport(p);
    if (tr) base.transport = tr;
  };
  const applyMux = () => {
    const mux = buildSingboxMux(p, s);
    if (mux) base.multiplex = mux;
  };

  switch (p.protocol) {
    case "vmess": {
      const v = p as P<"vmess">;
      base.uuid = v.uuid;
      base.alter_id = v.alterId;
      base.security = v.encryption === "auto" ? "auto" : v.encryption;
      if (v.packetEncoding) base.packet_encoding = v.packetEncoding;
      applyMux();
      applyTransport();
      applyTls(false);
      break;
    }
    case "vless": {
      const v = p as P<"vless">;
      base.uuid = v.uuid;
      base.packet_encoding = v.packetEncoding || "xudp";
      if (v.flow) base.flow = v.flow;
      else applyMux();
      applyTransport();
      applyTls(false);
      break;
    }
    case "trojan": {
      const v = p as P<"trojan">;
      base.password = v.password;
      applyMux();
      applyTransport();
      applyTls(false);
      break;
    }
    case "shadowsocks": {
      const v = p as P<"shadowsocks">;
      base.method = v.method;
      base.password = v.password;
      if (v.network === "tcp" && v.headerType === "http") {
        base.plugin = "obfs-local";
        base.plugin_opts = `obfs=http;obfs-host=${v.host};`;
      } else {
        let pluginArgs = "";
        if (v.network === "ws") {
          pluginArgs += "mode=websocket;";
          pluginArgs += `host=${v.host};`;
          const path = (v.path || "")
            .replace(/\\/g, "\\\\")
            .replace(/=/g, "\\=")
            .replace(/,/g, "\\,");
          pluginArgs += `path=${path};`;
        } else if (v.network === "quic") {
          pluginArgs += "mode=quic;";
        }
        if (v.security === "tls") pluginArgs += "tls;";
        if (pluginArgs) {
          base.plugin = "v2ray-plugin";
          base.plugin_opts = `${pluginArgs}mux=0;`.replace(/;$/, "");
        }
      }
      applyMux();
      break;
    }
    case "socks": {
      const v = p as P<"socks">;
      base.version = "5";
      if (v.username && v.password) {
        base.username = v.username;
        base.password = v.password;
      }
      break;
    }
    case "http": {
      const v = p as P<"http">;
      if (v.username && v.password) {
        base.username = v.username;
        base.password = v.password;
      }
      applyTls(false);
      break;
    }
    case "wireguard": {
      const v = p as P<"wireguard">;
      const reserved = splitCsv(v.reserved)
        ?.map((n) => Number(n))
        .filter((n) => !Number.isNaN(n));
      const peer: JsonObject = {
        address: v.address,
        port: v.port,
        public_key: v.peerPublicKey,
        allowed_ips: ["0.0.0.0/0", "::/0"],
      };
      if (v.preSharedKey) peer.pre_shared_key = v.preSharedKey;
      if (v.persistentKeepalive) peer.persistent_keepalive_interval = v.persistentKeepalive;
      if (reserved?.length) peer.reserved = reserved;
      const wg: JsonObject = {
        type: "wireguard",
        tag: "proxy",
        address: splitCsv(v.localAddress) ?? [v.localAddress],
        private_key: v.secretKey,
        mtu: v.mtu || 1408,
        peers: [peer],
      };
      if (v.workers) wg.workers = v.workers;
      return wg;
    }
    case "hysteria2": {
      const v = p as P<"hysteria2">;
      base.password = v.password;
      if (v.obfsType === "salamander" && v.obfsPassword) {
        base.obfs = { type: "salamander", password: v.obfsPassword };
      }
      if (v.upMbps > 0) base.up_mbps = v.upMbps;
      if (v.downMbps > 0) base.down_mbps = v.downMbps;
      if (v.ports.trim() && /[:\-,]/.test(v.ports)) {
        delete base.server_port;
        base.server_ports = buildServerPorts(v.ports);
        const hop = Number(v.hopInterval);
        base.hop_interval = Number.isFinite(hop) && hop >= 5 ? `${hop}s` : "30s";
      }
      applyTls(true);
      break;
    }
    case "tuic": {
      const v = p as P<"tuic">;
      base.uuid = v.uuid;
      base.password = v.password;
      base.congestion_control = v.congestionControl;
      if (v.udpRelayMode) base.udp_relay_mode = v.udpRelayMode;
      if (v.zeroRtt) base.zero_rtt_handshake = true;
      if (v.udpOverStream) base.udp_over_stream = true;
      if (v.heartbeat) base.heartbeat = v.heartbeat;
      applyTls(true);
      break;
    }
    case "anytls": {
      const v = p as P<"anytls">;
      base.password = v.password;
      if (v.idleSessionCheckInterval) base.idle_session_check_interval = v.idleSessionCheckInterval;
      if (v.idleSessionTimeout) base.idle_session_timeout = v.idleSessionTimeout;
      if (v.minIdleSession) base.min_idle_session = v.minIdleSession;
      applyTls(true);
      break;
    }
    case "naive": {
      const v = p as P<"naive">;
      if (v.username) base.username = v.username;
      base.password = v.password;
      if (v.insecureConcurrency > 0) base.insecure_concurrency = v.insecureConcurrency;
      if (v.naiveQuic) base.quic = true;
      if (v.congestionControl) base.quic_congestion_control = v.congestionControl;
      applyTls(true);
      break;
    }
    case "shadowtls": {
      const v = p as P<"shadowtls">;
      base.version = v.version;
      if (v.password) base.password = v.password;
      applyTls(true);
      break;
    }
    case "custom":
      throw new Error("custom profile has no sing-box outbound");
  }

  return base;
}

/* ---------- DNS ---------- */
function parseHosts(v: string | undefined): JsonObject | undefined {
  if (!v?.trim()) return undefined;
  try {
    const asJson = JSON.parse(v.trim());
    if (asJson && typeof asJson === "object" && !Array.isArray(asJson)) return asJson as JsonObject;
  } catch {
    // fall through to host=ip lines
  }

  const out: JsonObject = {};
  for (const line of v.split(/\r?\n/)) {
    const [host, ip] = line.split("=").map((x) => x.trim());
    if (!host || !ip) continue;
    const cur = out[host];
    if (Array.isArray(cur)) out[host] = [...cur, ip];
    else if (typeof cur === "string") out[host] = [cur, ip];
    else out[host] = ip;
  }
  return Object.keys(out).length ? out : undefined;
}

function buildSingboxDnsRuleForDomains(
  domains: string[],
  server: "local" | "remote",
  ruleSetTags: Set<string>,
): JsonObject | null {
  const rule: JsonObject = { server };
  for (const domain of domains) parseSingboxDomain(domain, rule, ruleSetTags);
  return hasMatchFields(rule, [
    "rule_set",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
  ])
    ? rule
    : null;
}

function buildSingboxDns(
  s: AdvancedSettings,
  routingRules: RoutingRule[],
  extraRuleSetTags: Set<string>,
): JsonObject {
  const remote = splitList(s.remoteDns, ["1.1.1.1"])[0];
  const domestic = splitList(s.domesticDns, ["223.5.5.5"])[0];
  const hosts = parseHosts(s.dnsHosts);
  const servers: JsonObject[] = [
    { type: "udp", tag: "remote", server: remote, ...(s.dnsViaProxy ? { detour: "proxy" } : {}) },
    { type: "udp", tag: "local", server: domestic },
  ];
  const rules: JsonObject[] = [];
  const dnsRuleSetTags = new Set<string>();

  if (hosts) {
    servers.push({ type: "hosts", tag: "hosts", predefined: hosts });
    rules.push({ ip_accept_any: true, server: "hosts" });
  }

  if (s.fakeDns) {
    servers.push({
      type: "fakeip",
      tag: "fakeip",
      inet4_range: "198.18.0.0/15",
      inet6_range: "fc00::/18",
    });
    rules.push({ query_type: ["A", "AAAA"], server: "fakeip" });
  }

  if (s.routingMode === "rules") {
    for (const rule of routingRules) {
      if (!rule.enabled || !rule.domain?.length) continue;
      const server =
        rule.outboundTag === "direct" ? "local" : rule.outboundTag === "proxy" ? "remote" : null;
      if (!server) continue;
      const dnsRule = buildSingboxDnsRuleForDomains(rule.domain, server, dnsRuleSetTags);
      if (dnsRule) rules.push(dnsRule);
    }
  }

  // Resolve private/LAN names against the local DNS so the bypass above stays consistent.
  rules.push({ ip_is_private: true, server: "local" });

  const dns: JsonObject = {
    servers,
    ...(rules.length ? { rules } : {}),
    final: "remote",
    strategy: s.ipv6Enabled ? "prefer_ipv4" : "ipv4_only",
  };
  for (const tag of dnsRuleSetTags) extraRuleSetTags.add(tag);
  return dns;
}

/* ---------- structured routing → sing-box ---------- */
function buildBaseSingboxRule(
  rule: RoutingRule,
  resolveOutboundTag: (tag: string) => string,
): JsonObject {
  const out: JsonObject =
    rule.outboundTag === "block"
      ? { action: "reject" }
      : { outbound: resolveOutboundTag(rule.outboundTag || "proxy") };

  if (rule.port?.trim()) {
    for (const item of splitCsv(rule.port) ?? []) {
      if (item.includes("-")) addStringList(out, "port_range", item.replace(/-/g, ":"));
      else {
        const port = Number(item);
        if (Number.isFinite(port)) addNumberList(out, "port", port);
      }
    }
  }
  if (rule.network) out.network = splitCsv(rule.network) ?? [];
  if (rule.protocol?.length) out.protocol = [...rule.protocol];
  return out;
}

function parseSingboxDomain(value: string, rule: JsonObject, ruleSetTags: Set<string>): boolean {
  const domain = value.trim();
  if (
    !domain ||
    domain.startsWith("#") ||
    domain.startsWith("ext:") ||
    domain.startsWith("ext-domain:")
  )
    return false;
  if (domain.startsWith("geosite:")) {
    const tag = `geosite-${domain.slice(8).toLowerCase()}`;
    addStringList(rule, "rule_set", tag);
    ruleSetTags.add(tag);
    return true;
  }
  if (domain.startsWith("regexp:")) {
    addStringList(rule, "domain_regex", domain.slice(7).replace(/\\,/g, ","));
    return true;
  }
  if (domain.startsWith("domain:")) {
    addStringList(rule, "domain_suffix", domain.slice(7));
    return true;
  }
  if (domain.startsWith("full:")) {
    addStringList(rule, "domain", domain.slice(5));
    return true;
  }
  if (domain.startsWith("keyword:")) {
    addStringList(rule, "domain_keyword", domain.slice(8));
    return true;
  }
  if (domain.startsWith("dotless:")) {
    addStringList(rule, "domain_keyword", domain.slice(8));
    return true;
  }
  addStringList(rule, "domain_keyword", domain);
  return true;
}

function parseSingboxIp(value: string, rule: JsonObject, ruleSetTags: Set<string>): boolean {
  const ip = value.trim();
  if (!ip || ip.startsWith("ext:") || ip.startsWith("ext-ip:")) return false;
  if (ip === "geoip:private") {
    rule.ip_is_private = true;
    return true;
  }
  if (ip === "geoip:!private") {
    rule.ip_is_private = false;
    return true;
  }
  if (ip.startsWith("geoip:!")) {
    const tag = `geoip-${ip.slice(7).toLowerCase()}`;
    addStringList(rule, "rule_set", tag);
    rule.invert = true;
    ruleSetTags.add(tag);
    return true;
  }
  if (ip.startsWith("geoip:")) {
    const tag = `geoip-${ip.slice(6).toLowerCase()}`;
    addStringList(rule, "rule_set", tag);
    ruleSetTags.add(tag);
    return true;
  }
  addStringList(rule, "ip_cidr", ip);
  return true;
}

function buildRuleSetObjects(ruleSetTags: Set<string>): JsonObject[] | undefined {
  if (!ruleSetTags.size) return undefined;
  return [...ruleSetTags].map((tag) => ({
    type: "local",
    format: "binary",
    tag,
    path: `${SRS_DIR}/${tag}.srs`,
  }));
}

function buildStructuredSingboxRules(
  routingRules: RoutingRule[],
  resolveOutboundTag: (tag: string) => string,
): {
  rules: JsonObject[];
  ipRules: JsonObject[];
  ruleSetTags: Set<string>;
} {
  const rules: JsonObject[] = [];
  const ipRules: JsonObject[] = [];
  const ruleSetTags = new Set<string>();

  for (const item of routingRules) {
    if (!item.enabled) continue;
    const base = buildBaseSingboxRule(item, resolveOutboundTag);
    let emitted = false;

    if (item.domain?.length) {
      const domainRule: JsonObject = { ...base };
      for (const domain of item.domain) parseSingboxDomain(domain, domainRule, ruleSetTags);
      if (
        hasMatchFields(domainRule, [
          "rule_set",
          "domain",
          "domain_suffix",
          "domain_keyword",
          "domain_regex",
        ])
      ) {
        rules.push(domainRule);
        emitted = true;
      }
    }

    if (item.ip?.length) {
      const ipRule: JsonObject = { ...base };
      for (const ip of item.ip) parseSingboxIp(ip, ipRule, ruleSetTags);
      if (hasMatchFields(ipRule, ["rule_set", "ip_cidr", "ip_is_private"])) {
        rules.push(ipRule);
        ipRules.push({ ...ipRule });
        emitted = true;
      }
    }

    if (!emitted && hasMatchFields(base, ["port", "port_range", "network", "protocol"])) {
      rules.push(base);
    }
  }

  return { rules, ipRules, ruleSetTags };
}
function buildSingboxResolveRule(s: AdvancedSettings): JsonObject {
  return { action: "resolve", strategy: s.domainStrategy4Singbox };
}

/* ---------- tun inbounds ---------- */
function buildSingboxTunInbounds(s: AdvancedSettings): JsonObject[] {
  // Keys are "pkg:uid" — use numeric uid for per-profile accuracy
  const uidOf = (key: string) => Number(key.split(":")[1]);
  const forceUids = Object.entries(s.appFilter ?? {})
    .filter(([, mode]) => mode === "force-proxy")
    .map(([key]) => uidOf(key));
  const bypassUids = Object.entries(s.appFilter ?? {})
    .filter(([, mode]) => mode === "bypass")
    .map(([key]) => uidOf(key));

  const mainTun: JsonObject = {
    type: "tun",
    tag: "tun-in",
    address: ["198.18.0.1/15", "fdfe:dcba:9876::1/64"],
    mtu: 9000,
    auto_route: true,
    strict_route: true,
    stack: "system",
  };
  const excludeFromMain = [...bypassUids, ...forceUids];
  if (excludeFromMain.length) mainTun.exclude_uid = excludeFromMain;

  const inbounds: JsonObject[] = [mainTun];
  if (forceUids.length) {
    inbounds.push({
      type: "tun",
      tag: "tun-force",
      address: ["198.19.0.1/16", "fdfe:dcba:9877::1/64"],
      mtu: 9000,
      auto_route: true,
      strict_route: true,
      stack: "system",
      include_uid: forceUids,
    });
  }
  return inbounds;
}

/* ---------- route ---------- */
function buildSingboxRoute(
  s: AdvancedSettings,
  routingRules: RoutingRule[],
  extraRuleSetTags: Set<string>,
  resolveOutboundTag: (tag: string) => string = (tag) => tag,
): JsonObject {
  const rules: JsonObject[] = [];
  const ruleSetTags = new Set<string>();
  const routingMode = s.routingMode as string;
  const domainStrategy = s.domainStrategy;
  // LAN/private traffic always goes direct — local network access (router admin,
  // casting, NAS) must keep working regardless of routing mode. Unlike xray
  // (handled at the iptables layer in service.sh), sing-box runs via auto_route,
  // so the bypass has to live in the config.
  const privateRule = { ip_is_private: true, outbound: "direct" };
  let retryIpRules: JsonObject[] = [{ ...privateRule }];

  if (routingMode === "rules") {
    const structured = buildStructuredSingboxRules(routingRules, resolveOutboundTag);
    if (domainStrategy === "IPOnDemand") rules.push(buildSingboxResolveRule(s));
    rules.push(privateRule, ...structured.rules);
    retryIpRules = [{ ...privateRule }, ...structured.ipRules];
    for (const tag of structured.ruleSetTags) ruleSetTags.add(tag);
  } else {
    if (domainStrategy === "IPOnDemand") rules.push(buildSingboxResolveRule(s));
    rules.push(privateRule);
  }

  if (domainStrategy === "IPIfNonMatch") {
    rules.push(buildSingboxResolveRule(s), ...retryIpRules.map((rule) => ({ ...rule })));
  }

  // tun-force bypasses all routing rules — always proxied
  if (Object.values(s.appFilter ?? {}).some((m) => m === "force-proxy")) {
    rules.unshift({ inbound: ["tun-force"], outbound: "proxy" });
  }

  // Sniffing is a route action in sing-box (xray does it per-inbound). Without
  // it tun traffic is IP-only and every domain/geosite rule above is dead code.
  // hijack-dns answers client DNS queries through the dns section so its rules
  // (and fakeip) apply; it needs sniff to detect the dns protocol first.
  if (s.domainSniffing) {
    rules.unshift({ action: "sniff" }, { protocol: ["dns"], action: "hijack-dns" });
  }

  for (const tag of extraRuleSetTags) ruleSetTags.add(tag);

  const route: JsonObject = {
    rules,
    final: "proxy",
    auto_detect_interface: true,
    default_domain_resolver: { server: "local" },
  };
  const ruleSet = buildRuleSetObjects(ruleSetTags);
  if (ruleSet?.length) route.rule_set = ruleSet;
  return route;
}

/* ---------- full config ---------- */
/** Built-in outbound tags that are not profile references. */
const SPECIAL_OUTBOUND_TAGS = new Set(["proxy", "direct", "block"]);

/**
 * Build extra outbounds/endpoints for routing rules that target a specific profile
 * (by id), plus a resolver mapping each rule tag to the actual tag in the config.
 * Profiles that cannot be built for sing-box fall back to "proxy".
 */
function buildSingboxProfileTargets(
  active: Profile,
  s: AdvancedSettings,
  routingRules: RoutingRule[],
  profiles: Profile[],
): {
  outbounds: JsonObject[];
  endpoints: JsonObject[];
  resolveOutboundTag: (tag: string) => string;
} {
  const resolved = new Map<string, string>();
  const outbounds: JsonObject[] = [];
  const endpoints: JsonObject[] = [];
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
      if (!profile || profile.protocol === "custom") {
        resolved.set(id, "proxy");
        continue;
      }
      try {
        const target = { ...buildSingboxOutbound(profile, s), tag: id };
        if (profile.protocol === "wireguard") endpoints.push(target);
        else outbounds.push(target);
        resolved.set(id, id);
      } catch {
        resolved.set(id, "proxy");
      }
    }
  }
  const resolveOutboundTag = (tag: string) =>
    SPECIAL_OUTBOUND_TAGS.has(tag) ? tag : (resolved.get(tag) ?? "proxy");
  return { outbounds, endpoints, resolveOutboundTag };
}

export function buildSingboxConfig(
  p: Profile,
  s: AdvancedSettings,
  routingRules: RoutingRule[] = [],
  profiles: Profile[] = [],
  opts: { noTun?: boolean } = {},
): JsonObject {
  if (p.protocol === "custom") throw new Error("custom profiles run on Xray, not sing-box");
  const socksPort = s.localSocksPort ?? 10808;
  const proxy = buildSingboxOutbound(p, s);
  const isEndpoint = p.protocol === "wireguard";
  const targets = buildSingboxProfileTargets(p, s, routingRules, profiles);
  const sharedRuleSetTags = new Set<string>();
  const cfg: JsonObject = {
    log: { level: s.logLevel || "warning", timestamp: true },
    dns: buildSingboxDns(s, routingRules, sharedRuleSetTags),
    inbounds: [
      { type: "mixed", tag: "socks-in", listen: "127.0.0.1", listen_port: socksPort },
      ...(opts.noTun ? [] : buildSingboxTunInbounds(s)),
    ],
    outbounds: isEndpoint
      ? [...targets.outbounds, { type: "direct", tag: "direct" }]
      : [proxy, ...targets.outbounds, { type: "direct", tag: "direct" }],
    route: buildSingboxRoute(s, routingRules, sharedRuleSetTags, targets.resolveOutboundTag),
  };
  const endpoints = [...(isEndpoint ? [proxy] : []), ...targets.endpoints];
  if (endpoints.length) cfg.endpoints = endpoints;
  return cfg;
}

/** Serialize the config for handing to `kasumi-proxyctl start`. */
export function buildSingboxConfigJSON(
  p: Profile,
  s: AdvancedSettings,
  routingRules: RoutingRule[] = [],
  profiles: Profile[] = [],
  opts: { noTun?: boolean } = {},
): string {
  return JSON.stringify(buildSingboxConfig(p, s, routingRules, profiles, opts), null, 2);
}
