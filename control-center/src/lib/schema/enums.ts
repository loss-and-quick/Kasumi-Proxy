// ============================================================
// src/lib/schema/enums.ts
// Fixed value sets used across protocols. Always z.enum (never bare
// strings) so the UI can reuse `.options` and TS gets literal unions.
// ============================================================
import { z } from "zod";

export const Network = z.enum(["tcp", "ws", "grpc", "httpupgrade", "xhttp", "h2", "kcp", "quic"]);
export const Security = z.enum(["none", "tls", "reality"]);
export const Fingerprint = z.enum([
  "",
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
]);
export const PacketEncoding = z.enum(["", "xudp", "packetaddr"]);
export const Flow = z.enum(["", "xtls-rprx-vision", "xtls-rprx-vision-udp443"]);
export const VmessEnc = z.enum(["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"]);
export const HeaderType = z.enum([
  "none",
  "http",
  "srtp",
  "utp",
  "wechat-video",
  "dtls",
  "wireguard",
  "dns",
]);
export const SsMethod = z.enum([
  "aes-256-gcm",
  "aes-128-gcm",
  "chacha20-poly1305",
  "chacha20-ietf-poly1305",
  "xchacha20-poly1305",
  "none",
  "plain",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
]);

/* ---------- core engine selection ---------- */
export const CoreEngine = z.enum(["xray", "sing-box"]); // an actual core
export const CoreSel = z.enum(["global", "xray", "sing-box"]); // per-profile override ("global" = resolve by protocol/global settings)
export const CongestionControl = z.enum(["bbr", "cubic", "new_reno"]); // TUIC / QUIC
export const Hysteria2Obfs = z.enum(["", "salamander"]); // Hysteria2 obfuscation

export type Network = z.infer<typeof Network>;
export type Security = z.infer<typeof Security>;
export type Fingerprint = z.infer<typeof Fingerprint>;
export type CoreEngineT = z.infer<typeof CoreEngine>;
export type CoreSelT = z.infer<typeof CoreSel>;
