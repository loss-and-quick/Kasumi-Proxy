import { z } from "zod";
import { Flow } from "../enums";
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

export const TrojanObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...transportShape,
  ...tlsShape,
  protocol: z.literal("trojan"),
  password: z.string().min(1, "Password required"),
  flow: Flow.default(""),
});
export type Trojan = z.infer<typeof TrojanObj>;

export function emptyTrojan(groupId: string): Trojan {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...transportDefault(),
    ...tlsDefault(),
    protocol: "trojan",
    password: "",
    flow: "",
  };
}
