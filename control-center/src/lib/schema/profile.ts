// ============================================================
// src/lib/schema/profile.ts
// Assembles the per-protocol objects into the discriminated union,
// cross-field refinement, the protocol registry and the emptyProfile
// factory. Profiles are backend-agnostic: which core runs a profile
// is a separate dimension (see ./core).
// ============================================================
import { z } from "zod";
import {
  AnytlsObj,
  CustomObj,
  emptyAnytls,
  emptyCustom,
  emptyHttp,
  emptyHysteria2,
  emptyNaive,
  emptyShadowsocks,
  emptyShadowtls,
  emptySocks,
  emptyTrojan,
  emptyTuic,
  emptyVless,
  emptyVmess,
  emptyWireguard,
  HttpObj,
  Hysteria2Obj,
  NaiveObj,
  ShadowsocksObj,
  ShadowtlsObj,
  SocksObj,
  TrojanObj,
  TuicObj,
  VlessObj,
  VmessObj,
  WireguardObj,
} from "./protocols";

type RawProfile =
  | z.infer<typeof VlessObj>
  | z.infer<typeof VmessObj>
  | z.infer<typeof TrojanObj>
  | z.infer<typeof ShadowsocksObj>
  | z.infer<typeof SocksObj>
  | z.infer<typeof HttpObj>
  | z.infer<typeof WireguardObj>
  | z.infer<typeof Hysteria2Obj>
  | z.infer<typeof TuicObj>
  | z.infer<typeof AnytlsObj>
  | z.infer<typeof NaiveObj>
  | z.infer<typeof ShadowtlsObj>
  | z.infer<typeof CustomObj>;

/* ---------- cross-field rules ---------- */
const TRANSPORT_NEEDS_PATH = ["ws", "grpc", "httpupgrade", "xhttp"];

function refineProfile(p: RawProfile, ctx: z.RefinementCtx) {
  if ("network" in p && TRANSPORT_NEEDS_PATH.includes(p.network)) {
    const pathish = p.network === "grpc" ? p.serviceName || p.path : p.path;
    if (!pathish) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [p.network === "grpc" ? "serviceName" : "path"],
        message: p.network === "grpc" ? "serviceName required" : "Path required",
      });
    }
  }
  if ("security" in p && p.security === "reality") {
    if (!p.sni)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sni"],
        message: "SNI required for Reality",
      });
    if (!p.publicKey)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["publicKey"],
        message: "Public key required",
      });
  }
  if (p.protocol === "custom" && !p.raw.trim()) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["raw"], message: "Config JSON required" });
  }
}

/* ---------- protocol registry ---------- */
export const PROTOCOLS = [
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "socks",
  "http",
  "wireguard",
  "hysteria2",
  "tuic",
  "anytls",
  "naive",
  "shadowtls",
  "custom",
] as const;
/** Protocols that carry stream transport + TLS/Reality settings. */
export const STREAM_PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks"] as const;

const PROTOCOL_OBJ = {
  vless: VlessObj,
  vmess: VmessObj,
  trojan: TrojanObj,
  shadowsocks: ShadowsocksObj,
  socks: SocksObj,
  http: HttpObj,
  wireguard: WireguardObj,
  hysteria2: Hysteria2Obj,
  tuic: TuicObj,
  anytls: AnytlsObj,
  naive: NaiveObj,
  shadowtls: ShadowtlsObj,
  custom: CustomObj,
} as const;

/** Discriminated union for parsing arbitrary profiles (import, restore). */
export const ProfileSchema = z
  .discriminatedUnion("protocol", [
    VlessObj,
    VmessObj,
    TrojanObj,
    ShadowsocksObj,
    SocksObj,
    HttpObj,
    WireguardObj,
    Hysteria2Obj,
    TuicObj,
    AnytlsObj,
    NaiveObj,
    ShadowtlsObj,
    CustomObj,
  ])
  .superRefine(refineProfile);

export type Profile = z.infer<typeof ProfileSchema>;
export type Protocol = Profile["protocol"];

/** Pick the right single-protocol schema for the editor form resolver. */
export const schemaFor = (p: Protocol) => PROTOCOL_OBJ[p].superRefine(refineProfile);

/* ---------- protocol type helpers ---------- */
export type ProfileOf<P extends Protocol> = Extract<Profile, { protocol: P }>;

/* ---------- factory (delegates to each protocol's empty()) ---------- */
export function emptyProfile(protocol: Protocol, groupId = "g-main"): Profile {
  switch (protocol) {
    case "vless":
      return emptyVless(groupId);
    case "vmess":
      return emptyVmess(groupId);
    case "trojan":
      return emptyTrojan(groupId);
    case "shadowsocks":
      return emptyShadowsocks(groupId);
    case "socks":
      return emptySocks(groupId);
    case "http":
      return emptyHttp(groupId);
    case "wireguard":
      return emptyWireguard(groupId);
    case "hysteria2":
      return emptyHysteria2(groupId);
    case "tuic":
      return emptyTuic(groupId);
    case "anytls":
      return emptyAnytls(groupId);
    case "naive":
      return emptyNaive(groupId);
    case "shadowtls":
      return emptyShadowtls(groupId);
    case "custom":
      return emptyCustom(groupId);
  }
}
