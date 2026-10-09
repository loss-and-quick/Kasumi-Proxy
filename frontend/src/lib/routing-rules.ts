import type { RoutingRule } from "../generated/bindings";

const MAX_PORT = 65535;

function portCoversEveryPort(port: string | null | undefined): boolean {
  if (!port?.trim()) return false;
  const ranges: [number, number][] = [];
  for (const item of port.split(",")) {
    const part = item.trim();
    if (!part) continue;
    const [lo, hi] = part.includes("-") ? part.split("-") : [part, part];
    const from = Number(lo);
    const to = Number(hi);
    if (!Number.isInteger(from) || !Number.isInteger(to)) return false;
    ranges.push([Math.min(from, to), Math.max(from, to)]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  let reached = 0;
  for (const [from, to] of ranges) {
    if (from > reached + 1) break;
    reached = Math.max(reached, to);
  }
  return reached >= MAX_PORT;
}

/** Whether the rule matches every connection, making the rules below it dead. */
export function isCatchAllRule(rule: RoutingRule): boolean {
  if (!rule.enabled) return false;
  if (rule.domain?.length || rule.ip?.length || rule.protocol?.length) return false;
  if (rule.network && rule.network !== "tcp,udp") return false;
  return portCoversEveryPort(rule.port);
}
