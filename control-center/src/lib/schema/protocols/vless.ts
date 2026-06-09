import { z } from "zod";
import { Flow, PacketEncoding } from "../enums";
import {
  endpointDefault,
  endpointShape,
  metaDefault,
  metaShape,
  tlsDefault,
  tlsShape,
  transportDefault,
  transportShape,
} from "../mixins";

export const VlessObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...transportShape,
  ...tlsShape,
  protocol: z.literal("vless"),
  uuid: z
    .string()
    .regex(
      /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,
      "UUID required",
    ),
  flow: Flow.default(""),
  encryption: z.string().default("none"),
  packetEncoding: PacketEncoding.default(""),
});
export type Vless = z.infer<typeof VlessObj>;

export function emptyVless(groupId: string): Vless {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...transportDefault(),
    ...tlsDefault(),
    protocol: "vless",
    uuid: "",
    flow: "",
    encryption: "none",
    packetEncoding: "",
  };
}
