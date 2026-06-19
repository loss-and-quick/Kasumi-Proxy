// ============================================================
// features/editor/types.ts
// Editor setter/error types over the nested Profile model. The draft is a real
// `Profile` (generated bindings); each section binds to one nested sub-object
// (meta/endpoint/tls/transport) or the protocol-root credential fields. There is
// no flat view — sections read the narrowed draft directly.
// ============================================================
import type { Endpoint, Meta, Tls, Transport } from "../../generated/bindings";

export type FieldErrors = Record<string, string>;

export type MetaSetter = (patch: Partial<Meta>) => void;
export type EndpointSetter = (patch: Partial<Endpoint>) => void;
export type TlsSetter = (patch: Partial<Tls>) => void;
export type TransportSetter = (next: Transport) => void;
/** Patch protocol-root credential fields (uuid/password/flow/…). The caller reads
 *  the narrowed draft for types; writes are validated by Zod on save. */
export type RootSetter = (patch: Record<string, unknown>) => void;
