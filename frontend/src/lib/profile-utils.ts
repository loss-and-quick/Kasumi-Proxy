// ============================================================
// src/lib/profile-utils.ts
// Thin synchronous helpers the UI needs over the generated, nested Profile
// model (src/generated/bindings.ts): safe accessors across the protocol union,
// core-engine resolution, the per-protocol Zod form schema, and the nested
// `emptyProfile` factory. Heavy logic (config build, share, sub-apply) lives in
// Rust and is reached through the bridge — these are display/edit-time reads
// only. Mirrors `kasumi-core`'s `profile`/`core`/`mixins` accessors.
// ============================================================

import { z } from "zod";
import type { Profile, Protocol, Security, Transport } from "../generated/bindings";
import { EMPTY_PROFILES } from "../generated/defaults";
import {
  AnytlsSchema,
  CustomSchema,
  HttpSchema,
  Hysteria2Schema,
  NaiveSchema,
  ShadowsocksSchema,
  ShadowtlsSchema,
  SocksSchema,
  TrojanSchema,
  TuicSchema,
  VlessSchema,
  VmessSchema,
  WireguardSchema,
} from "../generated/schemas";

/** Stable unique id generator (crypto.randomUUID with a non-crypto fallback). */
export const uid = (): string =>
  globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);

/** A single protocol's concrete shape. */
export type ProfileOf<P extends Protocol> = Extract<Profile, { protocol: P }>;

/* ---------- accessors over the nested union ---------- */

export const profileAddress = (p: Profile): string => ("endpoint" in p ? p.endpoint.address : "");
export const profilePort = (p: Profile): number | null =>
  "endpoint" in p ? p.endpoint.port : null;

export function profileNetwork(p: Profile): string {
  if ("transport" in p && p.transport) return p.transport.kind;
  return p.protocol === "wireguard" ? "udp" : "—";
}

export const profileSecurity = (p: Profile): Security =>
  "tls" in p && p.tls ? (p.tls.security ?? "none") : "none";

/** "host:port" for endpoints, protocol name otherwise (custom). */
export const profileEndpointLabel = (p: Profile): string =>
  "endpoint" in p ? `${p.endpoint.address}:${p.endpoint.port}` : p.protocol;

/** HTTP host header source for the transports that carry one (mirrors `Transport::host`). */
function transportHost(t: Transport): string {
  switch (t.kind) {
    case "tcp":
    case "ws":
    case "h2":
    case "httpupgrade":
    case "xhttp":
      return t.host ?? "";
    default:
      return "";
  }
}

/** Stream path / endpoint for the transports that carry one (mirrors `Transport::path`). */
function transportPath(t: Transport): string {
  switch (t.kind) {
    case "tcp":
    case "ws":
    case "h2":
    case "httpupgrade":
    case "xhttp":
      return t.path ?? "";
    case "grpc":
      return t.serviceName ?? "";
    default:
      return "";
  }
}

/** Lower-cased searchable haystack for filtering (mirrors `sub_apply::profile_search_text`). */
export function profileSearchText(p: Profile): string {
  const parts: string[] = [p.meta.remarks, p.protocol];
  if ("endpoint" in p) {
    parts.push(p.endpoint.address, String(p.endpoint.port));
  }
  if ("transport" in p && p.transport) {
    parts.push(p.transport.kind, transportHost(p.transport), transportPath(p.transport));
  }
  if ("tls" in p && p.tls) {
    parts.push(p.tls.security ?? "", p.tls.sni ?? "");
  }
  return parts.filter(Boolean).join(" ").toLowerCase();
}

/* ---------- form schema (per-protocol, with cross-field refinement) ---------- */

const PROTOCOL_SCHEMA = {
  vless: VlessSchema,
  vmess: VmessSchema,
  trojan: TrojanSchema,
  shadowsocks: ShadowsocksSchema,
  socks: SocksSchema,
  http: HttpSchema,
  wireguard: WireguardSchema,
  hysteria2: Hysteria2Schema,
  tuic: TuicSchema,
  anytls: AnytlsSchema,
  naive: NaiveSchema,
  shadowtls: ShadowtlsSchema,
  custom: CustomSchema,
} as const;

const TRANSPORT_NEEDS_PATH = new Set(["ws", "httpupgrade", "xhttp"]);

// Same cross-field rules as the Rust schema, read off the nested draft. Issue
// paths use the leaf field name so the editor sections can key errors by field.
function refineProfile(value: unknown, ctx: z.RefinementCtx): void {
  const p = value as Profile;
  if ("transport" in p && p.transport && TRANSPORT_NEEDS_PATH.has(p.transport.kind)) {
    const path = "path" in p.transport ? p.transport.path : "";
    if (!path)
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["path"], message: "Path required" });
  }
  if ("tls" in p && p.tls && p.tls.security === "reality") {
    if (!p.tls.sni)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["sni"],
        message: "SNI required for Reality",
      });
    if (!p.tls.publicKey)
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["publicKey"],
        message: "Public key required",
      });
  }
  if (p.protocol === "custom" && !p.raw?.trim())
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["raw"], message: "Config JSON required" });
}

/** Pick the right single-protocol schema for the editor form resolver. */
export const schemaFor = (p: Protocol) =>
  z
    .object({ protocol: z.literal(p) })
    .and(PROTOCOL_SCHEMA[p])
    .superRefine(refineProfile);

/* ---------- nested emptyProfile factory ---------- */

/**
 * A blank profile of the given protocol. Clones the Rust-built template from
 * the generated `EMPTY_PROFILES` (single source — see `kasumi_core::empty_profile`)
 * and stamps a fresh id + the target group. No default value is restated here.
 */
export function emptyProfile(protocol: Protocol, groupId = "g-main"): Profile {
  const base = structuredClone(EMPTY_PROFILES[protocol]);
  base.meta = { ...base.meta, id: uid(), groupId };
  return base;
}
