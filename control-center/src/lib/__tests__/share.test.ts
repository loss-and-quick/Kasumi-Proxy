import { describe, expect, it } from "vitest";
import type { Profile } from "../schema";
import { buildShareLink, extractUris, parseShareLink, parseShareLinks } from "../share";

type Vless = Extract<Profile, { protocol: "vless" }>;
type Vmess = Extract<Profile, { protocol: "vmess" }>;
type Trojan = Extract<Profile, { protocol: "trojan" }>;
type Hysteria2 = Extract<Profile, { protocol: "hysteria2" }>;
type Tuic = Extract<Profile, { protocol: "tuic" }>;
type Anytls = Extract<Profile, { protocol: "anytls" }>;
type Naive = Extract<Profile, { protocol: "naive" }>;

function mustParse<T extends Profile>(uri: string): T {
  const parsed = parseShareLink(uri);
  expect(parsed).not.toBeNull();
  return parsed as T;
}

describe("parseShareLink", () => {
  it("parses a vless reality link", () => {
    const uri =
      "vless://11111111-1111-1111-1111-111111111111@ex.com:443?type=tcp&security=reality&sni=www.apple.com&fp=chrome&pbk=PBK&sid=ab12&flow=xtls-rprx-vision#DE%20Node";
    const p = parseShareLink(uri) as Vless;
    expect(p.protocol).toBe("vless");
    expect(p.uuid).toBe("11111111-1111-1111-1111-111111111111");
    expect(p.address).toBe("ex.com");
    expect(p.port).toBe(443);
    expect(p.security).toBe("reality");
    expect(p.sni).toBe("www.apple.com");
    expect(p.publicKey).toBe("PBK");
    expect(p.shortId).toBe("ab12");
    expect(p.flow).toBe("xtls-rprx-vision");
    expect(p.remarks).toBe("DE Node");
  });

  it("parses a trojan link", () => {
    const p = parseShareLink(
      "trojan://secret@ex.com:8443?security=tls&sni=ex.com&flow=xtls-rprx-vision#T",
    ) as Trojan;
    expect(p.protocol).toBe("trojan");
    expect(p.password).toBe("secret");
    expect(p.port).toBe(8443);
    expect(p.security).toBe("tls");
    expect(p.flow).toBe("xtls-rprx-vision");
  });

  it("parses a vmess (base64 json) link", () => {
    const json = JSON.stringify({
      v: "2",
      ps: "VM",
      add: "ex.com",
      port: "443",
      id: "22222222-2222-2222-2222-222222222222",
      aid: "0",
      net: "ws",
      host: "ex.com",
      path: "/vm?ed=2048&eh=Sec-WebSocket-Protocol",
      tls: "tls",
      sni: "ex.com",
      allowInsecure: 1,
    });
    const uri = `vmess://${btoa(json)}`;
    const p = parseShareLink(uri) as Vmess;
    expect(p.protocol).toBe("vmess");
    expect(p.address).toBe("ex.com");
    expect(p.network).toBe("ws");
    expect(p.path).toBe("/vm");
    expect(p.wsEarlyData).toBe(2048);
    expect(p.wsEarlyDataHeader).toBe("Sec-WebSocket-Protocol");
    expect(p.security).toBe("tls");
    expect(p.allowInsecure).toBe(true);
    expect(p.remarks).toBe("VM");
  });

  it("parses a vmess grpc link with mode/authority", () => {
    const json = JSON.stringify({
      v: "2",
      ps: "GRPC-VM",
      add: "ex.com",
      port: "443",
      id: "33333333-3333-3333-3333-333333333333",
      aid: "0",
      net: "grpc",
      type: "multi",
      host: "auth.ex.com",
      path: "my-service",
      tls: "tls",
      sni: "ex.com",
    });
    const uri = `vmess://${btoa(json)}`;
    const p = parseShareLink(uri) as Vmess;
    expect(p.protocol).toBe("vmess");
    expect(p.network).toBe("grpc");
    expect(p.grpcMode).toBe("multi");
    expect(p.authority).toBe("auth.ex.com");
    expect(p.serviceName).toBe("my-service");
  });

  it("parses xhttp mode/extra from URI", () => {
    const uri =
      "vless://uuid@ex.com:443?type=xhttp&security=tls&host=cdn.ex.com&path=/stream&mode=packet&extra=%7B%22key%22%3A%22val%22%7D#XH";
    const p = parseShareLink(uri) as Vless;
    expect(p.protocol).toBe("vless");
    expect(p.network).toBe("xhttp");
    expect(p.host).toBe("cdn.ex.com");
    expect(p.path).toBe("/stream");
    expect(p.xhttpMode).toBe("packet");
    expect(p.xhttpExtra).toBe('{"key":"val"}');
  });

  it("parses TLS extras (ech, vcn, pcs, pqv) from URI", () => {
    const uri =
      "vless://uuid@ex.com:443?type=tcp&security=tls&ech=base64ech&vcn=verify.name&pcs=abc123sha256&pqv=mlsdaVerifyVal#EX";
    const p = parseShareLink(uri) as Vless;
    expect(p.ech).toBe("base64ech");
    expect(p.vcn).toBe("verify.name");
    expect(p.pcs).toBe("abc123sha256");
    expect(p.pqv).toBe("mlsdaVerifyVal");
  });

  it("parses shadowsocks SIP002 plugin modes", () => {
    const ws = parseShareLink(
      "ss://YWVzLTI1Ni1nY206cHc=@ss.ex:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.ex.com%3Bpath%3D%2Fws%3Btls#SSWS",
    ) as Extract<Profile, { protocol: "shadowsocks" }>;
    expect(ws.protocol).toBe("shadowsocks");
    expect(ws.network).toBe("ws");
    expect(ws.host).toBe("cdn.ex.com");
    expect(ws.path).toBe("/ws");
    expect(ws.security).toBe("tls");

    const obfs = parseShareLink(
      "ss://YWVzLTI1Ni1nY206cHc=@ss.ex:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.ex.com#SSOBFS",
    ) as Extract<Profile, { protocol: "shadowsocks" }>;
    expect(obfs.network).toBe("tcp");
    expect(obfs.headerType).toBe("http");
    expect(obfs.host).toBe("cdn.ex.com");
  });

  it("returns null for unsupported scheme", () => {
    expect(parseShareLink("ss://whatever")).toBeNull();
  });
});

describe("round-trip build → parse", () => {
  it("vless reality survives round-trip on key fields", () => {
    const original =
      "vless://11111111-1111-1111-1111-111111111111@ex.com:443?type=grpc&security=reality&sni=www.apple.com&fp=chrome&pbk=PBK&sid=ab12&serviceName=gsvc#N";
    const p = mustParse<Vless>(original);
    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Vless>(rebuilt);
    expect(p2.protocol).toBe("vless");
    expect(p2.address).toBe("ex.com");
    expect(p2.security).toBe("reality");
    expect(p2.publicKey).toBe("PBK");
    expect(p2.serviceName).toBe("gsvc");
  });

  it("trojan flow survives round-trip", () => {
    const original = "trojan://secret@ex.com:443?security=tls&sni=ex.com&flow=xtls-rprx-vision#TR";
    const p = mustParse<Trojan>(original);
    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Trojan>(rebuilt);
    expect(p2.protocol).toBe("trojan");
    expect(p2.flow).toBe("xtls-rprx-vision");
  });

  it("vless grpc with mode/authority survives round-trip", () => {
    const original =
      "vless://uuid@ex.com:443?type=grpc&security=tls&mode=multi&authority=auth.ex.com&serviceName=gsvc#GRPC";
    const p = mustParse<Vless>(original);
    expect(p.grpcMode).toBe("multi");
    expect(p.authority).toBe("auth.ex.com");
    expect(p.serviceName).toBe("gsvc");

    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Vless>(rebuilt);
    expect(p2.network).toBe("grpc");
    expect(p2.grpcMode).toBe("multi");
    expect(p2.authority).toBe("auth.ex.com");
    expect(p2.serviceName).toBe("gsvc");
  });

  it("xhttp with mode/extra survives round-trip", () => {
    const original =
      "vless://uuid@ex.com:443?type=xhttp&security=tls&host=cdn.ex.com&path=/xray&mode=packet&extra=%7B%22opt%22%3A%22val%22%7D#XH";
    const p = mustParse<Vless>(original);
    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Vless>(rebuilt);
    expect(p2.network).toBe("xhttp");
    expect(p2.host).toBe("cdn.ex.com");
    expect(p2.path).toBe("/xray");
    expect(p2.xhttpMode).toBe("packet");
    expect(p2.xhttpExtra).toBe('{"opt":"val"}');
  });

  it("ws early-data survives round-trip", () => {
    const original =
      "vless://uuid@ex.com:443?type=ws&security=tls&host=cdn.ex.com&path=%2Fws%3Fed%3D2048%26eh%3DSec-WebSocket-Protocol#WS";
    const p = mustParse<Vless>(original);
    expect(p.path).toBe("/ws");
    expect(p.wsEarlyData).toBe(2048);
    expect(p.wsEarlyDataHeader).toBe("Sec-WebSocket-Protocol");

    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Vless>(rebuilt);
    expect(p2.path).toBe("/ws");
    expect(p2.wsEarlyData).toBe(2048);
    expect(p2.wsEarlyDataHeader).toBe("Sec-WebSocket-Protocol");
  });

  it("TLS extras survive round-trip", () => {
    const original =
      "vless://uuid@ex.com:443?type=tcp&security=tls&ech=abc&vcn=chk.name&pcs=pin256abc&pqv=mlsdaVal#EX";
    const p = mustParse<Vless>(original);
    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Vless>(rebuilt);
    expect(p2.ech).toBe("abc");
    expect(p2.vcn).toBe("chk.name");
    expect(p2.pcs).toBe("pin256abc");
    expect(p2.pqv).toBe("mlsdaVal");
  });

  it("vmess vmessAEAD gRPC round-trip preserves grpc fields", () => {
    const json = {
      v: "2",
      ps: "gRPC-VM",
      add: "ex.com",
      port: "443",
      id: "44444444-4444-4444-4444-444444444444",
      net: "grpc",
      type: "multi",
      host: "auth.ex.com",
      path: "svc-name",
      tls: "tls",
      sni: "ex.com",
      fp: "chrome",
    };
    const uri = `vmess://${btoa(JSON.stringify(json))}`;
    const p = mustParse<Vmess>(uri);
    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Vmess>(rebuilt);
    expect(p2.protocol).toBe("vmess");
    expect(p2.network).toBe("grpc");
    expect(p2.grpcMode).toBe("multi");
    expect(p2.authority).toBe("auth.ex.com");
    expect(p2.serviceName).toBe("svc-name");
  });
});

describe("hysteria2 / tuic (sing-box)", () => {
  it("parses a hysteria2 link with obfs, mport and pin", () => {
    const uri =
      "hysteria2://secret@hy.ex:443?sni=hy.ex&obfs=salamander&obfs-password=obf&mport=20000-50000&pinSHA256=AA%3DBB&insecure=1#FI%20Node";
    const p = parseShareLink(uri) as Hysteria2;
    expect(p.protocol).toBe("hysteria2");
    expect(p.password).toBe("secret");
    expect(p.obfsType).toBe("salamander");
    expect(p.obfsPassword).toBe("obf");
    expect(p.ports).toBe("20000-50000");
    expect(p.allowInsecure).toBe(true);
    expect(p.remarks).toBe("FI Node");
  });

  it("accepts the hy2:// alias", () => {
    const p = parseShareLink("hy2://pw@hy.ex:8443?sni=hy.ex") as Hysteria2;
    expect(p?.protocol).toBe("hysteria2");
    expect(p.port).toBe(8443);
  });

  it("round-trips a hysteria2 profile", () => {
    const uri =
      "hysteria2://secret@hy.ex:443?sni=hy.ex&obfs=salamander&obfs-password=obf&mport=20000-50000#N";
    const p = parseShareLink(uri) as Hysteria2;
    const p2 = parseShareLink(buildShareLink(p)) as Hysteria2;
    expect(p2.password).toBe("secret");
    expect(p2.obfsPassword).toBe("obf");
    expect(p2.ports).toBe("20000-50000");
  });

  it("parses a tuic link (uuid:password + congestion control)", () => {
    const uri =
      "tuic://u-1:pw@t.ex:8443?congestion_control=bbr&udp_relay_mode=native&zero_rtt_handshake=1&sni=t.ex&alpn=h3#JP";
    const p = parseShareLink(uri) as Tuic;
    expect(p.protocol).toBe("tuic");
    expect(p.uuid).toBe("u-1");
    expect(p.password).toBe("pw");
    expect(p.congestionControl).toBe("bbr");
    expect(p.udpRelayMode).toBe("native");
    expect(p.zeroRtt).toBe(true);
    const p2 = parseShareLink(buildShareLink(p)) as Tuic;
    expect(p2.uuid).toBe("u-1");
    expect(p2.congestionControl).toBe("bbr");
    expect(p2.udpRelayMode).toBe("native");
    expect(p2.zeroRtt).toBe(true);
  });

  it("parses and round-trips anytls links", () => {
    const uri = "anytls://secret@a.ex:443?sni=a.ex&alpn=h2&allowInsecure=1&pcs=pin#AT";
    const p = parseShareLink(uri) as Anytls;
    expect(p.protocol).toBe("anytls");
    expect(p.password).toBe("secret");
    expect(p.sni).toBe("a.ex");
    expect(p.pcs).toBe("pin");
    const p2 = parseShareLink(buildShareLink(p)) as Anytls;
    expect(p2.password).toBe("secret");
    expect(p2.pcs).toBe("pin");
  });

  it("parses and round-trips naive links", () => {
    const uri =
      "naive+quic://user:pw@n.ex:443?congestion_control=bbr&insecure-concurrency=8&sni=n.ex#NV";
    const p = parseShareLink(uri) as Naive;
    expect(p.protocol).toBe("naive");
    expect(p.username).toBe("user");
    expect(p.password).toBe("pw");
    expect(p.naiveQuic).toBe(true);
    expect(p.insecureConcurrency).toBe(8);
    const p2 = parseShareLink(buildShareLink(p)) as Naive;
    expect(p2.username).toBe("user");
    expect(p2.naiveQuic).toBe(true);
    expect(p2.insecureConcurrency).toBe(8);
  });

  it("round-trips shadowsocks plugin links", () => {
    const original =
      "ss://YWVzLTI1Ni1nY206cHc=@ss.ex:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.ex.com%3Bpath%3D%2Fws%3Btls#SSWS";
    const p = mustParse<Extract<Profile, { protocol: "shadowsocks" }>>(original);
    const rebuilt = buildShareLink(p);
    const p2 = mustParse<Extract<Profile, { protocol: "shadowsocks" }>>(rebuilt);
    expect(p2.network).toBe("ws");
    expect(p2.host).toBe("cdn.ex.com");
    expect(p2.path).toBe("/ws");
    expect(p2.security).toBe("tls");
  });
});

describe("extractUris", () => {
  it("extracts multiple raw uris", () => {
    const text = "vless://a@h:1?type=tcp#x\ntrojan://p@h:2#y\nnoise";
    expect(extractUris(text).length).toBe(2);
  });

  it("decodes a base64-wrapped subscription body", () => {
    const inner = "vless://a@h:1?type=tcp#x\ntrojan://p@h:2#y";
    const wrapped = btoa(inner);
    const got = parseShareLinks(wrapped);
    expect(got.length).toBe(2);
  });
});

describe("shadowtls share link", () => {
  type Shadowtls = Extract<Profile, { protocol: "shadowtls" }>;

  it("parses a shadowtls link", () => {
    const uri = "shadowtls://secret@s.ex:8443?version=3&sni=s.ex&fp=chrome#ST";
    const p = parseShareLink(uri) as Shadowtls;
    expect(p.protocol).toBe("shadowtls");
    expect(p.password).toBe("secret");
    expect(p.address).toBe("s.ex");
    expect(p.port).toBe(8443);
    expect(p.version).toBe(3);
    expect(p.sni).toBe("s.ex");
    expect(p.fingerprint).toBe("chrome");
    expect(p.remarks).toBe("ST");
  });

  it("round-trips a shadowtls profile", () => {
    const uri = "shadowtls://pw%40x@s.ex:443?version=2&sni=s.ex#SL";
    const p = parseShareLink(uri) as Shadowtls;
    const built = buildShareLink(p);
    const p2 = parseShareLink(built) as Shadowtls;
    expect(p2.protocol).toBe("shadowtls");
    expect(p2.password).toBe("pw@x");
    expect(p2.version).toBe(2);
    expect(p2.sni).toBe("s.ex");
    expect(p2.remarks).toBe("SL");
  });

  it("extractUris picks up shadowtls:// links", () => {
    const text = "shadowtls://pw@s.ex:443?version=3&sni=s.ex vless://u@v.ex:443#V";
    const uris = extractUris(text);
    expect(uris.some((u) => u.startsWith("shadowtls://"))).toBe(true);
    expect(uris.length).toBe(2);
  });
});

describe("wireguard share link", () => {
  type Wireguard = Extract<Profile, { protocol: "wireguard" }>;

  it("parses a wireguard link", () => {
    const uri =
      "wireguard://QPibxMMkZne460g8gkEbCXM1bw7Z0Hob2YmnS0NV0Xg%3D@127.0.0.1:9000?address=10.8.1.3%2F32&presharedkey=khXtV6Anbg31qus546FmJ31xytmg0%2Bp80gp3uTNS6o4%3D&reserved=0%2C0%2C0&publickey=gB5Yvngw%2FhoCgZkcMVI9%2B6t6P1H7qZPRwC%2FzwOGT%2FlI%3D&mtu=1420#sanya-wg-tunnel";
    const p = parseShareLink(uri) as Wireguard;
    expect(p.protocol).toBe("wireguard");
    expect(p.address).toBe("127.0.0.1");
    expect(p.port).toBe(9000);
    expect(p.secretKey).toBe("QPibxMMkZne460g8gkEbCXM1bw7Z0Hob2YmnS0NV0Xg=");
    expect(p.peerPublicKey).toBe("gB5Yvngw/hoCgZkcMVI9+6t6P1H7qZPRwC/zwOGT/lI=");
    expect(p.preSharedKey).toBe("khXtV6Anbg31qus546FmJ31xytmg0+p80gp3uTNS6o4=");
    expect(p.reserved).toBe("0,0,0");
    expect(p.localAddress).toBe("10.8.1.3/32");
    expect(p.mtu).toBe(1420);
    expect(p.remarks).toBe("sanya-wg-tunnel");
  });

  it("returns null if secretKey is missing", () => {
    expect(parseShareLink("wireguard://1.2.3.4:51820")).toBeNull();
  });

  it("extractUris picks up wireguard:// links", () => {
    const text =
      "wireguard://key%3D@1.2.3.4:51820?publickey=pub%3D&address=10.0.0.2%2F32#wg vless://u@v.ex:443#V";
    const uris = extractUris(text);
    expect(uris.some((u) => u.startsWith("wireguard://"))).toBe(true);
    expect(uris.length).toBe(2);
  });
});

describe("socks share link", () => {
  type Socks = Extract<Profile, { protocol: "socks" }>;

  it("parses a socks:// link", () => {
    const p = parseShareLink("socks://user:pass@1.2.3.4:1080#my-socks") as Socks;
    expect(p.protocol).toBe("socks");
    expect(p.address).toBe("1.2.3.4");
    expect(p.port).toBe(1080);
    expect(p.username).toBe("user");
    expect(p.password).toBe("pass");
    expect(p.remarks).toBe("my-socks");
  });

  it("parses a socks5:// link", () => {
    const p = parseShareLink("socks5://u:p@1.2.3.4:1080#s5") as Socks;
    expect(p.protocol).toBe("socks");
    expect(p.port).toBe(1080);
  });

  it("extractUris picks up socks:// links", () => {
    const text = "socks://u:p@1.2.3.4:1080#s vless://u@v.ex:443#V";
    const uris = extractUris(text);
    expect(uris.some((u) => u.startsWith("socks://"))).toBe(true);
    expect(uris.length).toBe(2);
  });
});

describe("http/https proxy share link", () => {
  type Http = Extract<Profile, { protocol: "http" }>;

  it("parses an http:// proxy link", () => {
    const p = parseShareLink("http://user:pass@1.2.3.4:8080#my-http") as Http;
    expect(p.protocol).toBe("http");
    expect(p.address).toBe("1.2.3.4");
    expect(p.port).toBe(8080);
    expect(p.username).toBe("user");
    expect(p.password).toBe("pass");
    expect(p.remarks).toBe("my-http");
  });

  it("parses an https:// proxy link and sets tls security", () => {
    const p = parseShareLink("https://user:pass@1.2.3.4:443#my-https") as Http;
    expect(p.protocol).toBe("http");
    expect(p.security).toBe("tls");
    expect(p.port).toBe(443);
  });

  it("extractUris picks up http:// proxy links (with @) but not plain URLs", () => {
    const text =
      "http://user:pass@1.2.3.4:8080#proxy vless://u@v.ex:443#V https://example.com/page";
    const uris = extractUris(text);
    expect(uris.some((u) => u.startsWith("http://user:"))).toBe(true);
    expect(uris.some((u) => u === "https://example.com/page")).toBe(false);
    expect(uris.some((u) => u.startsWith("vless://"))).toBe(true);
  });
});

describe("URI_RE: fragment with spaces", () => {
  it("captures full remarks containing spaces after flag emoji", () => {
    const uri =
      "trojan://password@ex.com:443?fp=chrome&security=tls&sni=ex.com&type=tcp#🇦🇹 23 - AT - Trojan/TLS/UTLS - 443";
    const p = parseShareLink(uri);
    expect(p?.remarks).toBe("🇦🇹 23 - AT - Trojan/TLS/UTLS - 443");
  });

  it("does not bleed into the next URI on a separate line", () => {
    const text = "vless://u@a.com:443#🇩🇪 first name\ntrojan://p@b.com:443#🇷🇺 second name";
    const uris = extractUris(text);
    expect(uris).toHaveLength(2);
    expect(uris[0]).toContain("first name");
    expect(uris[1]).toContain("second name");
  });

  it("extracts all profiles with full remarks from a real-world subscription", () => {
    const lines = [
      "vless://id@1.2.3.4:443?type=tcp#🇷🇺 3 - RU - VLESS/REALITY - 443",
      "trojan://pw@5.6.7.8:443?security=tls#🇩🇪 8 - DE - Trojan - 443",
    ];
    const uris = extractUris(lines.join("\n"));
    expect(uris[0]).toMatch(/🇷🇺 3 - RU/);
    expect(uris[1]).toMatch(/🇩🇪 8 - DE/);
  });
});
