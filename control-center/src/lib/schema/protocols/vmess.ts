import { z } from "zod";
import { PacketEncoding, VmessEnc } from "../enums";
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

export const VmessObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...transportShape,
  ...tlsShape,
  protocol: z.literal("vmess"),
  uuid: z
    .string()
    .regex(
      /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/,
      "UUID required",
    ),
  alterId: z.coerce.number().int().min(0).default(0),
  encryption: VmessEnc.default("auto"),
  packetEncoding: PacketEncoding.default(""),
});
export type Vmess = z.infer<typeof VmessObj>;

export function emptyVmess(groupId: string): Vmess {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...transportDefault(),
    ...tlsDefault(),
    protocol: "vmess",
    uuid: "",
    alterId: 0,
    encryption: "auto",
    packetEncoding: "",
  };
}
