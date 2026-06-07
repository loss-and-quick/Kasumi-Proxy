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

// QUIC protocol only sing-box can run.
export const TuicObj = z.object({
  ...metaShape,
  ...endpointShape,
  ...tlsShape,
  protocol: z.literal("tuic"),
  uuid: z.string().min(1, "UUID required"),
  password: z.string().min(1, "Password required"),
  congestionControl: CongestionControl.default("bbr"),
  udpRelayMode: z.string().default(""),
  zeroRtt: z.boolean().default(false),
  udpOverStream: z.boolean().default(false),
  heartbeat: z.string().default(""),
});
export type Tuic = z.infer<typeof TuicObj>;

export function emptyTuic(groupId: string): Tuic {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    ...tlsDefault(),
    protocol: "tuic",
    uuid: "",
    password: "",
    congestionControl: "bbr",
    udpRelayMode: "",
    zeroRtt: false,
    udpOverStream: false,
    heartbeat: "",
  };
}
