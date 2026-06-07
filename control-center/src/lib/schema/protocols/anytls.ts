import { z } from "zod";
import {
  endpointDefault,
  endpointShape,
  metaDefault,
  metaShape,
  tlsDefault,
  tlsShape,
} from "../mixins";

// sing-box only.
export const AnytlsObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...tlsShape,
  protocol: z.literal("anytls"),
  password: z.string().min(1, "Password required"),
  idleSessionCheckInterval: z.string().default(""),
  idleSessionTimeout: z.string().default(""),
  minIdleSession: z.coerce.number().int().default(0),
});
export type Anytls = z.infer<typeof AnytlsObj>;

export function emptyAnytls(groupId: string): Anytls {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...tlsDefault(),
    protocol: "anytls",
    password: "",
    idleSessionCheckInterval: "",
    idleSessionTimeout: "",
    minIdleSession: 0,
  };
}
