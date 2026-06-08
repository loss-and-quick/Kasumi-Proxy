// ============================================================
// src/lib/share.ts
// Parse and build share links (vless:// vmess:// trojan:// ss://).
// Pure, testable TS. Profiles are produced via emptyProfile() so
// every field stays in sync with the schema automatically.
// ============================================================
import { buildWsPath, parseWsEarlyData } from "./config-shared";
import {
  emptyProfile,
  type Fingerprint,
  type Network,
  type Profile,
  type ProfileOf,
  type Protocol,
  type Security,
  SsMethod,
} from "./schema";
import { uid } from "./utils";

/** Build a profile of a protocol with overrides (schema-synced base). */
function mk<P extends Protocol>(protocol: P, o: Partial<ProfileOf<P>>): ProfileOf<P> {
  return { ...(emptyProfile(protocol) as ProfileOf<P>), ...o, id: uid(), protocol };
}

/* ---------- unicode-safe base64 ---------- */
function b64decode(str: string): string | null {
  try {
    let s = str.trim().replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
  } catch {
    return null;
  }
}
function b64encode(str: string): string {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

/* ---------- enum coercion ---------- */
const NETWORKS: Network[] = ["tcp", "ws", "grpc", "httpupgrade", "xhttp", "h2", "kcp", "quic"];
const asNetwork = (v: string | null): Network =>
  NETWORKS.includes((v || "") as Network) ? (v as Network) : "tcp";
const asSecurity = (v: string | null): Security => (v === "tls" || v === "reality" ? v : "none");
const FPS: Fingerprint[] = [
  "chrome",
  "firefox",
  "safari",
  "ios",
  "android",
  "edge",
  "360",
  "qq",
  "random",
  "randomized",
];
const asFp = (v: string | null): Fingerprint =>
  FPS.includes((v || "") as Fingerprint) ? (v as Fingerprint) : "chrome";
const SS_METHODS = SsMethod.options;
const asSsMethod = (v: string): ProfileOf<"shadowsocks">["method"] =>
  (SS_METHODS as readonly string[]).includes(v)
    ? (v as ProfileOf<"shadowsocks">["method"])
    : "aes-256-gcm";

const splitFirst = (s: string, sep: string): [string, string] => {
  const i = s.indexOf(sep);
  return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + sep.length)];
};
const splitLast = (s: string, sep: string): [string, string] => {
  const i = s.lastIndexOf(sep);
  return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + sep.length)];
};
function parseHostPort(hp: string): [string, number] {
  const [h, p] = splitLast(hp, ":");
  return [h, Number(p) || 443];
}

/* ---------- vmess ---------- */
interface VmessPayload {
  ps?: string;
  add?: string;
  port?: string | number;
  id?: string;
  aid?: string | number;
  scy?: string;
  net?: string;
  type?: string;
  host?: string;
  path?: string;
  tls?: string;
  sni?: string;
  alpn?: string;
  fp?: string;
  allowInsecure?: boolean | number | string;
  insecure?: boolean | number | string;
}
const truthy = (v: boolean | number | string | undefined | null): boolean =>
  v === true || v === 1 || v === "1" || v === "true";
const queryTruthy = (q: URLSearchParams, ...keys: string[]): boolean =>
  keys.some((key) => truthy(q.get(key)));

function parseVmess(uri: string, groupId?: string): Profile | null {
  const json = b64decode(uri.slice("vmess://".length));
  if (!json) return null;
  let c: VmessPayload;
  try {
    c = JSON.parse(json) as VmessPayload;
  } catch {
    return null;
  }
  const net = asNetwork(c.net || null);
  const isGrpc = net === "grpc";
  const ws =
    net === "ws"
      ? parseWsEarlyData(c.path || "")
      : { path: c.path || "", wsEarlyData: 0, wsEarlyDataHeader: "" };
  return mk("vmess", {
    remarks: c.ps || c.add || "VMess",
    address: c.add || "",
    port: Number(c.port) || 443,
    uuid: c.id || "",
    alterId: Number(c.aid) || 0,
    encryption: (["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"].includes(c.scy || "")
      ? c.scy
      : "auto") as ProfileOf<"vmess">["encryption"],
    network: net,
    headerType: !isGrpc && c.type === "http" ? "http" : "none",
    host: isGrpc ? "" : c.host || "",
    path: isGrpc ? "" : ws.path,
    wsEarlyData: net === "ws" ? ws.wsEarlyData : 0,
    wsEarlyDataHeader: net === "ws" ? ws.wsEarlyDataHeader : "",
    serviceName: isGrpc ? c.path || "" : "",
    authority: isGrpc ? c.host || "" : "",
    grpcMode: isGrpc ? c.type || "" : "",
    security: asSecurity(c.tls ? c.tls : "none"),
    sni: c.sni || "",
    alpn: c.alpn || "",
    fingerprint: asFp(c.fp || null),
    allowInsecure: truthy(c.allowInsecure) || truthy(c.insecure),
    groupId: groupId ?? "g-main",
  });
}

/* ---------- vless / trojan (URL based) ---------- */
function parseUrlBased(uri: string, proto: "vless" | "trojan", groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  const cred = decodeURIComponent(u.username);
  const net = asNetwork(q.get("type"));
  const mode = q.get("mode") || "";
  const ws =
    net === "ws"
      ? parseWsEarlyData(q.get("path") || "")
      : { path: q.get("path") || "", wsEarlyData: 0, wsEarlyDataHeader: "" };
  const shared = {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 443,
    network: net,
    headerType: q.get("headerType") === "http" ? ("http" as const) : ("none" as const),
    host: q.get("host") || "",
    path: net === "ws" ? ws.path : q.get("path") || "",
    wsEarlyData: net === "ws" ? ws.wsEarlyData : 0,
    wsEarlyDataHeader: net === "ws" ? ws.wsEarlyDataHeader : "",
    serviceName: net === "grpc" ? q.get("serviceName") || q.get("path") || "" : "",
    authority: net === "grpc" ? q.get("authority") || q.get("host") || "" : "",
    grpcMode: net === "grpc" ? mode : "",
    xhttpMode: net === "xhttp" ? mode : "",
    xhttpExtra: net === "xhttp" ? q.get("extra") || "" : "",
    security: asSecurity(q.get("security")),
    sni: q.get("sni") || "",
    alpn: q.get("alpn") || "",
    fingerprint: asFp(q.get("fp")),
    allowInsecure: q.get("allowInsecure") === "1",
    publicKey: q.get("pbk") || "",
    shortId: q.get("sid") || "",
    spiderX: q.get("spx") || "",
    ech: q.get("ech") || "",
    vcn: q.get("vcn") || "",
    pcs: q.get("pcs") || "",
    pqv: q.get("pqv") || "",
    groupId: groupId ?? "g-main",
  };
  if (proto === "vless") {
    return mk("vless", {
      ...shared,
      uuid: cred,
      encryption: q.get("encryption") || "none",
      flow: (q.get("flow") as ProfileOf<"vless">["flow"]) || "",
    });
  }
  return mk("trojan", {
    ...shared,
    password: cred,
    flow: (q.get("flow") as ProfileOf<"trojan">["flow"]) || "",
  });
}

/* ---------- shadowsocks (SIP002 + legacy) ---------- */
function parseSs(uri: string, groupId?: string): Profile | null {
  let body = uri.slice("ss://".length);
  let tag = "";
  const h = body.indexOf("#");
  if (h >= 0) {
    tag = decodeURIComponent(body.slice(h + 1));
    body = body.slice(0, h);
  }
  let plugin = "";
  const qi = body.indexOf("?");
  if (qi >= 0) {
    plugin = new URLSearchParams(body.slice(qi + 1)).get("plugin") || "";
    body = body.slice(0, qi);
  }

  let method = "",
    password = "",
    host = "",
    port = 443;
  if (body.includes("@")) {
    const [userinfo, hostport] = splitLast(body, "@");
    let creds = userinfo;
    const dec = b64decode(userinfo);
    if (dec?.includes(":")) creds = dec;
    [method, password] = splitFirst(creds, ":");
    [host, port] = parseHostPort(hostport);
  } else {
    const dec = b64decode(body);
    if (!dec?.includes("@")) return null;
    const [creds, hostport] = splitLast(dec, "@");
    [method, password] = splitFirst(creds, ":");
    [host, port] = parseHostPort(hostport);
  }
  if (!host) return null;

  const profile = mk("shadowsocks", {
    remarks: tag || host,
    address: host,
    port,
    method: asSsMethod(method),
    password,
    groupId: groupId ?? "g-main",
  });

  if (plugin) {
    const pluginParts = plugin.split(";").filter(Boolean);
    let pluginName = pluginParts[0] || "";
    if (pluginName === "simple-obfs") pluginName = "obfs-local";

    if (pluginName === "obfs-local") {
      const obfsMode = pluginParts.find((part) => part.startsWith("obfs="));
      const obfsHost = pluginParts.find((part) => part.startsWith("obfs-host="));
      const obfsPath = pluginParts.find((part) => part.startsWith("path="));
      if (obfsMode === "obfs=http") {
        profile.network = "tcp";
        profile.headerType = "http";
        profile.host = obfsHost?.slice("obfs-host=".length) || "";
        profile.path = obfsPath?.slice("path=".length) || "";
      }
    } else if (pluginName === "v2ray-plugin") {
      const mode =
        pluginParts.find((part) => part.startsWith("mode="))?.slice("mode=".length) || "websocket";
      const hostPart = pluginParts.find((part) => part.startsWith("host="));
      const pathPart = pluginParts.find((part) => part.startsWith("path="));
      const tls = pluginParts.includes("tls");
      if (mode === "websocket") {
        profile.network = "ws";
        profile.host = hostPart?.slice("host=".length) || "";
        profile.path = (pathPart?.slice("path=".length) || "")
          .replace(/\\=/g, "=")
          .replace(/\\,/g, ",")
          .replace(/\\\\/g, "\\");
      } else if (mode === "quic") {
        profile.network = "quic";
      }
      if (tls) {
        profile.security = "tls";
        if (profile.host && !profile.sni) profile.sni = profile.host;
      }
    }
  }

  return profile;
}

/* ---------- hysteria2 / tuic (sing-box, URL based) ---------- */
const CCS: ProfileOf<"tuic">["congestionControl"][] = ["bbr", "cubic", "new_reno"];
const asCc = (v: string | null): ProfileOf<"tuic">["congestionControl"] =>
  (CCS as readonly string[]).includes(v || "")
    ? (v as ProfileOf<"tuic">["congestionControl"])
    : "bbr";

function parseHysteria2(uri: string, groupId?: string): Profile | null {
  let u: URL;
  // normalize hy2:// alias so the URL parser keeps the scheme stable
  try {
    u = new URL(uri.replace(/^hy2:\/\//, "hysteria2://"));
  } catch {
    return null;
  }
  const q = u.searchParams;
  return mk("hysteria2", {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 443,
    password: decodeURIComponent(u.username),
    obfsType: q.get("obfs") === "salamander" ? "salamander" : "",
    obfsPassword: q.get("obfs-password") || "",
    ports: q.get("mport") || "",
    pinSha256: q.get("pinSHA256") || "",
    security: "tls",
    sni: q.get("sni") || "",
    alpn: q.get("alpn") || "",
    allowInsecure: q.get("insecure") === "1",
    groupId: groupId ?? "g-main",
  });
}

function parseTuic(uri: string, groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  return mk("tuic", {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 443,
    uuid: decodeURIComponent(u.username),
    password: decodeURIComponent(u.password),
    congestionControl: asCc(q.get("congestion_control")),
    udpRelayMode: q.get("udp_relay_mode") || "",
    zeroRtt: queryTruthy(q, "zero_rtt_handshake"),
    security: "tls",
    sni: q.get("sni") || "",
    alpn: q.get("alpn") || "",
    allowInsecure: queryTruthy(q, "allow_insecure", "allowInsecure", "insecure"),
    groupId: groupId ?? "g-main",
  });
}

function parseAnytls(uri: string, groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  return mk("anytls", {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 443,
    password: decodeURIComponent(u.username || u.password),
    security: "tls",
    sni: q.get("sni") || "",
    alpn: q.get("alpn") || "",
    fingerprint: asFp(q.get("fp")),
    allowInsecure: queryTruthy(q, "allowInsecure", "allow_insecure", "insecure"),
    ech: q.get("ech") || "",
    pcs: q.get("pcs") || "",
    groupId: groupId ?? "g-main",
  });
}

function parseNaive(uri: string, groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  const userInfo = decodeURIComponent(u.username || "");
  const password = decodeURIComponent(u.password || "");
  return mk("naive", {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 443,
    username: userInfo,
    password,
    naiveQuic: u.protocol.startsWith("naive+quic"),
    congestionControl: asCc(q.get("congestion_control")),
    insecureConcurrency: Number(q.get("insecure-concurrency")) || 0,
    security: "tls",
    sni: q.get("sni") || "",
    alpn: q.get("alpn") || "",
    fingerprint: asFp(q.get("fp")),
    allowInsecure: queryTruthy(q, "allowInsecure", "allow_insecure", "insecure"),
    ech: q.get("ech") || "",
    pcs: q.get("pcs") || "",
    groupId: groupId ?? "g-main",
  });
}

function parseSsr(uri: string, groupId?: string): Profile | null {
  const dec = b64decode(uri.slice("ssr://".length));
  if (!dec) return null;
  const [main, query] = splitFirst(dec, "?");
  const parts = main.split(":");
  // parts: host, port, protocol, method, obfs, base64(password)
  if (parts.length < 6) return null;
  const [host, portStr, , method, , b64pass] = parts;
  const port = Number(portStr);
  if (!host || !port) return null;
  const password = b64decode(b64pass.split("/")[0]) ?? b64pass.split("/")[0];
  const params = new URLSearchParams(query ?? "");
  const remarksRaw = params.get("remarks");
  const groupRaw = params.get("group");
  const group = (groupRaw ? b64decode(groupRaw) : null) ?? undefined;
  const remarks = (remarksRaw ? b64decode(remarksRaw) : null) ?? host;
  return mk("shadowsocks", {
    remarks: remarks || host,
    address: host,
    port,
    method: asSsMethod(method),
    password,
    groupId: groupId ?? group ?? "g-main",
  });
}

/** Parse a single share URI into a Profile (or null). */
export function parseShareLink(uri: string, groupId?: string): Profile | null {
  const s = uri.trim();
  if (s.startsWith("vmess://")) return parseVmess(s, groupId);
  if (s.startsWith("vless://")) return parseUrlBased(s, "vless", groupId);
  if (s.startsWith("trojan://")) return parseUrlBased(s, "trojan", groupId);
  if (s.startsWith("ss://")) return parseSs(s, groupId);
  if (s.startsWith("ssr://")) return parseSsr(s, groupId);
  if (s.startsWith("hysteria2://") || s.startsWith("hy2://")) return parseHysteria2(s, groupId);
  if (s.startsWith("tuic://")) return parseTuic(s, groupId);
  if (s.startsWith("anytls://")) return parseAnytls(s, groupId);
  if (s.startsWith("naive+https://") || s.startsWith("naive+quic://"))
    return parseNaive(s, groupId);
  if (s.startsWith("shadowtls://")) return parseShadowtls(s, groupId);
  if (s.startsWith("wireguard://")) return parseWireguard(s, groupId);
  if (s.startsWith("socks://") || s.startsWith("socks5://"))
    return parseSocksOrHttp(s, "socks", groupId);
  if (s.startsWith("http://") || s.startsWith("https://"))
    return parseSocksOrHttp(s, "http", groupId);
  return null;
}

function parseSocksOrHttp(uri: string, proto: "socks" | "http", groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  return mk(proto, {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || (u.protocol === "https:" ? 443 : proto === "http" ? 80 : 1080),
    username: decodeURIComponent(u.username || ""),
    password: decodeURIComponent(u.password || ""),
    ...(proto === "http" && {
      security: (q.get("security") as "none" | "tls") || (u.protocol === "https:" ? "tls" : "none"),
      sni: q.get("sni") || "",
    }),
    groupId: groupId ?? "g-main",
  });
}

function parseWireguard(uri: string, groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  const secretKey = decodeURIComponent(u.username || "");
  if (!secretKey) return null;
  return mk("wireguard", {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 51820,
    secretKey,
    peerPublicKey: decodeURIComponent(q.get("publickey") || ""),
    preSharedKey: decodeURIComponent(q.get("presharedkey") || ""),
    reserved: decodeURIComponent(q.get("reserved") || ""),
    localAddress: decodeURIComponent(q.get("address") || "172.16.0.2/32"),
    mtu: Number(q.get("mtu")) || 1420,
    groupId: groupId ?? "g-main",
  });
}

function parseShadowtls(uri: string, groupId?: string): Profile | null {
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const q = u.searchParams;
  const ver = Number(q.get("version")) || 3;
  return mk("shadowtls", {
    remarks: u.hash ? decodeURIComponent(u.hash.slice(1)) : u.hostname,
    address: u.hostname,
    port: Number(u.port) || 443,
    password: decodeURIComponent(u.username || u.password || ""),
    version: Math.min(3, Math.max(1, ver)) as 1 | 2 | 3,
    security: "tls",
    sni: q.get("sni") || "",
    fingerprint: asFp(q.get("fp")),
    groupId: groupId ?? "g-main",
  });
}

function buildShadowtls(p: ProfileOf<"shadowtls">): string {
  const params = new URLSearchParams();
  params.set("version", String(p.version ?? 3));
  if (p.sni) params.set("sni", p.sni);
  if (p.fingerprint) params.set("fp", p.fingerprint);
  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  return `shadowtls://${encodeURIComponent(p.password)}@${p.address}:${p.port}?${params.toString()}${hash}`;
}

const URI_RE =
  /(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls|naive\+https|naive\+quic|shadowtls|wireguard|socks5?|https?):\/\/[^\s@]*@[^\s]+|(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls|naive\+https|naive\+quic|shadowtls|wireguard|socks5?):\/\/[^\s]+/;
const URI_RE_G =
  /(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls|naive\+https|naive\+quic|shadowtls|wireguard|socks5?|https?):\/\/[^\s@]*@[^\s]+|(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|anytls|naive\+https|naive\+quic|shadowtls|wireguard|socks5?):\/\/[^\s]+/g;

/** Extract every share URI from arbitrary text, decoding base64 blobs. */
export function extractUris(text: string, depth = 0): string[] {
  const out: string[] = [];
  const direct = text.match(URI_RE_G);
  if (direct) out.push(...direct);
  if (depth < 3) {
    const candidates = [text, ...text.split(/\r?\n/)].map((t) => t.trim()).filter(Boolean);
    for (const cand of candidates) {
      if (/^[A-Za-z0-9+/=_-]+$/.test(cand) && cand.length > 8) {
        const dec = b64decode(cand);
        if (dec && URI_RE.test(dec)) out.push(...extractUris(dec, depth + 1));
      }
    }
  }
  return Array.from(new Set(out));
}

/** Parse all share links found in text into Profiles. */
export function parseShareLinks(text: string, groupId?: string): Profile[] {
  return extractUris(text)
    .map((u) => parseShareLink(u, groupId))
    .filter((p): p is Profile => p !== null);
}

/* ---------- build ---------- */
function buildVmess(p: ProfileOf<"vmess">): string {
  const isGrpc = p.network === "grpc";
  const c = {
    v: "2",
    ps: p.remarks,
    add: p.address,
    port: String(p.port),
    id: p.uuid,
    aid: String(p.alterId ?? 0),
    scy: p.encryption || "auto",
    net: p.network,
    type: isGrpc ? p.grpcMode || "gun" : p.headerType,
    host: isGrpc ? p.authority : p.host,
    path: isGrpc
      ? p.serviceName
      : p.network === "ws"
        ? buildWsPath(p.path, p.wsEarlyData, p.wsEarlyDataHeader)
        : p.path,
    tls: p.security === "none" ? "" : p.security,
    sni: p.sni,
    alpn: p.alpn,
    fp: p.fingerprint,
  };
  return `vmess://${b64encode(JSON.stringify(c))}`;
}

function buildUrlBased(p: ProfileOf<"vless"> | ProfileOf<"trojan">): string {
  const params = new URLSearchParams();
  params.set("type", p.network);
  params.set("security", p.security);
  if (p.network === "grpc") {
    if (p.grpcMode) params.set("mode", p.grpcMode);
    if (p.authority) params.set("authority", p.authority);
    if (p.serviceName) params.set("serviceName", p.serviceName);
  } else if (p.network === "xhttp") {
    if (p.host) params.set("host", p.host);
    if (p.path) params.set("path", p.path);
    if (p.xhttpMode) params.set("mode", p.xhttpMode);
    if (p.xhttpExtra) params.set("extra", p.xhttpExtra);
  } else {
    if (p.host) params.set("host", p.host);
    const path =
      p.network === "ws" ? buildWsPath(p.path, p.wsEarlyData, p.wsEarlyDataHeader) : p.path;
    if (path) params.set("path", path);
  }
  if (p.sni) params.set("sni", p.sni);
  if (p.alpn) params.set("alpn", p.alpn);
  if (p.fingerprint) params.set("fp", p.fingerprint);
  if (p.allowInsecure) params.set("allowInsecure", "1");
  if (p.security === "reality") {
    if (p.publicKey) params.set("pbk", p.publicKey);
    if (p.shortId) params.set("sid", p.shortId);
    if (p.spiderX) params.set("spx", p.spiderX);
  }
  if (p.ech) params.set("ech", p.ech);
  if (p.vcn) params.set("vcn", p.vcn);
  if (p.pcs) params.set("pcs", p.pcs);
  if (p.pqv) params.set("pqv", p.pqv);
  if (p.flow) params.set("flow", p.flow);
  const cred = p.protocol === "vless" ? p.uuid : p.password;
  if (p.protocol === "vless") params.set("encryption", p.encryption || "none");
  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  return `${p.protocol}://${encodeURIComponent(cred)}@${p.address}:${p.port}?${params.toString()}${hash}`;
}

function buildSs(p: ProfileOf<"shadowsocks">): string {
  const userinfo = b64encode(`${p.method}:${p.password}`);
  const params = new URLSearchParams();

  if (p.network === "tcp" && p.headerType === "http") {
    const pluginParts = ["obfs-local", "obfs=http"];
    if (p.host) pluginParts.push(`obfs-host=${p.host}`);
    if (p.path) pluginParts.push(`path=${p.path}`);
    params.set("plugin", pluginParts.join(";"));
  } else if (p.network === "ws" || p.network === "quic" || p.security === "tls") {
    const pluginParts: string[] = ["v2ray-plugin"];
    if (p.network === "ws") {
      pluginParts.push("mode=websocket");
      if (p.host) pluginParts.push(`host=${p.host}`);
      if (p.path) {
        const path = p.path.replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/,/g, "\\,");
        pluginParts.push(`path=${path}`);
      }
    } else if (p.network === "quic") {
      pluginParts.push("mode=quic");
    }
    if (p.security === "tls") pluginParts.push("tls");
    pluginParts.push("mux=0");
    params.set("plugin", pluginParts.join(";"));
  }

  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  const qs = params.toString();
  return `ss://${userinfo}@${p.address}:${p.port}${qs ? `?${qs}` : ""}${hash}`;
}

function buildHysteria2(p: ProfileOf<"hysteria2">): string {
  const params = new URLSearchParams();
  if (p.sni) params.set("sni", p.sni);
  if (p.alpn) params.set("alpn", p.alpn);
  if (p.allowInsecure) params.set("insecure", "1");
  if (p.obfsType === "salamander" && p.obfsPassword) {
    params.set("obfs", "salamander");
    params.set("obfs-password", p.obfsPassword);
  }
  if (p.ports) params.set("mport", p.ports.replace(/:/g, "-"));
  if (p.pinSha256) params.set("pinSHA256", p.pinSha256);
  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  const qs = params.toString();
  return `hysteria2://${encodeURIComponent(p.password)}@${p.address}:${p.port}${qs ? `?${qs}` : ""}${hash}`;
}

function buildTuic(p: ProfileOf<"tuic">): string {
  const params = new URLSearchParams();
  params.set("congestion_control", p.congestionControl);
  if (p.udpRelayMode) params.set("udp_relay_mode", p.udpRelayMode);
  if (p.zeroRtt) params.set("zero_rtt_handshake", "1");
  if (p.sni) params.set("sni", p.sni);
  if (p.alpn) params.set("alpn", p.alpn);
  if (p.allowInsecure) params.set("allow_insecure", "1");
  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  return `tuic://${encodeURIComponent(p.uuid)}:${encodeURIComponent(p.password)}@${p.address}:${p.port}?${params.toString()}${hash}`;
}

function buildAnytls(p: ProfileOf<"anytls">): string {
  const params = new URLSearchParams();
  if (p.sni) params.set("sni", p.sni);
  if (p.alpn) params.set("alpn", p.alpn);
  if (p.fingerprint) params.set("fp", p.fingerprint);
  if (p.allowInsecure) params.set("allowInsecure", "1");
  if (p.ech) params.set("ech", p.ech);
  if (p.pcs) params.set("pcs", p.pcs);
  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  const qs = params.toString();
  return `anytls://${encodeURIComponent(p.password)}@${p.address}:${p.port}${qs ? `?${qs}` : ""}${hash}`;
}

function buildNaive(p: ProfileOf<"naive">): string {
  const params = new URLSearchParams();
  if (p.congestionControl) params.set("congestion_control", p.congestionControl);
  if (p.insecureConcurrency) params.set("insecure-concurrency", String(p.insecureConcurrency));
  if (p.sni) params.set("sni", p.sni);
  if (p.alpn) params.set("alpn", p.alpn);
  if (p.fingerprint) params.set("fp", p.fingerprint);
  if (p.allowInsecure) params.set("allowInsecure", "1");
  if (p.ech) params.set("ech", p.ech);
  if (p.pcs) params.set("pcs", p.pcs);
  const hash = p.remarks ? `#${encodeURIComponent(p.remarks)}` : "";
  const qs = params.toString();
  const userinfo = p.username
    ? `${encodeURIComponent(p.username)}:${encodeURIComponent(p.password)}`
    : encodeURIComponent(p.password);
  const scheme = p.naiveQuic ? "naive+quic" : "naive+https";
  return `${scheme}://${userinfo}@${p.address}:${p.port}${qs ? `?${qs}` : ""}${hash}`;
}

/** Build a share link from a structured Profile ("" if not shareable). */
export function buildShareLink(p: Profile): string {
  switch (p.protocol) {
    case "vmess":
      return buildVmess(p);
    case "vless":
    case "trojan":
      return buildUrlBased(p);
    case "shadowsocks":
      return buildSs(p);
    case "hysteria2":
      return buildHysteria2(p);
    case "tuic":
      return buildTuic(p);
    case "anytls":
      return buildAnytls(p);
    case "naive":
      return buildNaive(p);
    case "shadowtls":
      return buildShadowtls(p);
    default:
      return ""; // socks/http/wireguard/custom: no standard share URI
  }
}
