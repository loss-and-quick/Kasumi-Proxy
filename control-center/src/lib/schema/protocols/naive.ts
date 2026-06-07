import { z } from "zod";
import { CongestionControl } from "../enums";
import {
  endpointDefault,
  endpointShape,
  metaDefault,
  metaShape,
  tlsDefault,
  tlsShape,
} from "../mixins";

// sing-box only.
export const NaiveObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...tlsShape,
  protocol: z.literal("naive"),
  username: z.string().default(""),
  password: z.string().min(1, "Password required"),
  naiveQuic: z.boolean().default(false),
  congestionControl: CongestionControl.default("bbr"),
  insecureConcurrency: z.coerce.number().int().min(0).default(0),
});
export type Naive = z.infer<typeof NaiveObj>;

export function emptyNaive(groupId: string): Naive {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...tlsDefault(),
    protocol: "naive",
    username: "",
    password: "",
    naiveQuic: false,
    congestionControl: "bbr",
    insecureConcurrency: 0,
  };
}
