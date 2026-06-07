// ============================================================
// src/lib/schema/core.ts
// Core-engine resolution — profile override + per-protocol defaults,
// with capability guards for transports/protocols that only one core
// can actually build.
// ============================================================

import type { CoreEngineT } from "./enums";
import type { Profile, Protocol } from "./profile";
import type { AdvancedSettings } from "./settings";

const SINGBOX_ONLY_PROTOCOLS = new Set<Protocol>(["tuic", "anytls", "naive", "shadowtls"]);

/** Protocols whose engine is fixed and not user-selectable. */
export function coreLocked(protocol: Protocol): boolean {
  return SINGBOX_ONLY_PROTOCOLS.has(protocol) || protocol === "custom";
}

/** Engine a protocol uses when nothing overrides it. */
export function defaultCoreFor(protocol: Protocol): CoreEngineT {
  return protocol === "hysteria2" || SINGBOX_ONLY_PROTOCOLS.has(protocol) ? "sing-box" : "xray";
}

function transportForcedCore(p: Profile): CoreEngineT | null {
  if (p.protocol === "shadowsocks" && "network" in p) {
    if (p.security === "tls" || p.network !== "tcp" || p.headerType === "http") return "sing-box";
  }
  if ("network" in p) {
    if (p.network === "h2" || p.network === "quic") return "sing-box";
    if (p.network === "kcp" || p.network === "xhttp") return "xray";
  }
  return null;
}

/** Resolve the actual core for a profile (capabilities > override > table > fallback). */
export function resolveCore(p: Profile, s: AdvancedSettings): CoreEngineT {
  if (p.protocol === "custom") return "xray";
  if (SINGBOX_ONLY_PROTOCOLS.has(p.protocol)) return "sing-box";

  const forcedTransport = transportForcedCore(p);
  if (forcedTransport) return forcedTransport;

  if (p.coreType && p.coreType !== "global") return p.coreType;
  return s.coreByProtocol?.[p.protocol] ?? defaultCoreFor(p.protocol);
}
