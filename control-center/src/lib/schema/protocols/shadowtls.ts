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
export const ShadowtlsObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...tlsShape,
  protocol: z.literal("shadowtls"),
  version: z.coerce.number().int().min(1).max(3).default(3),
  password: z.string().default(""),
});
export type Shadowtls = z.infer<typeof ShadowtlsObj>;

export function emptyShadowtls(groupId: string): Shadowtls {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...tlsDefault(),
    protocol: "shadowtls",
    version: 3,
    password: "",
  };
}
