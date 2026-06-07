import { z } from "zod";
import { endpointDefault, endpointShape, metaDefault, metaShape } from "../mixins";

export const WireguardObj = z.object({
  ...metaShape,
  ...endpointShape,
  protocol: z.literal("wireguard"),
  secretKey: z.string().min(1, "Secret key required"),
  peerPublicKey: z.string().min(1, "Peer public key required"),
  preSharedKey: z.string().default(""),
  reserved: z.string().default(""), // "0,0,0"
  localAddress: z.string().default("172.16.0.2/32"),
  mtu: z.coerce.number().int().default(1420),
  workers: z.coerce.number().int().default(0),
  persistentKeepalive: z.coerce.number().int().default(0),
});
export type Wireguard = z.infer<typeof WireguardObj>;

export function emptyWireguard(groupId: string): Wireguard {
  return {
    ...metaDefault(groupId),
    ...endpointDefault(),
    protocol: "wireguard",
    secretKey: "",
    peerPublicKey: "",
    preSharedKey: "",
    reserved: "",
    localAddress: "172.16.0.2/32",
    mtu: 1420,
    workers: 0,
    persistentKeepalive: 0,
  };
}
