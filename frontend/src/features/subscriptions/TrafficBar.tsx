import type { TrafficInfo } from "../../generated/bindings";
import { useFormatters, useT } from "../../i18n";
import { formatBytes } from "../../lib/format";
import { trafficUsage } from "./sub-display";

/** Used against the plan's quota; an unmetered plan shows the usage alone. */
export function TrafficLabel({ traffic }: { traffic: TrafficInfo }) {
  const t = useT();
  const { formatNumber } = useFormatters();
  const { used, total, ratio } = trafficUsage(traffic);
  return (
    <span dir="auto" style={{ fontVariantNumeric: "tabular-nums" }}>
      {ratio == null
        ? t("subs.provider.trafficUnlimited", { used: formatBytes(used, formatNumber) })
        : t("subs.provider.traffic", {
            used: formatBytes(used, formatNumber),
            total: formatBytes(total, formatNumber),
          })}
    </span>
  );
}

/** How much of the quota is used; nothing for an unmetered plan. */
export function TrafficBar({ traffic }: { traffic: TrafficInfo }) {
  const { ratio } = trafficUsage(traffic);
  if (ratio == null) return null;
  const fill = ratio >= 0.95 ? "var(--error)" : ratio >= 0.8 ? "var(--warn)" : "var(--primary)";
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(ratio * 100)}
      style={{ height: 6, borderRadius: 3, background: "var(--sc-high)", overflow: "hidden" }}
    >
      <div
        style={{ width: `${ratio * 100}%`, height: "100%", borderRadius: 3, background: fill }}
      />
    </div>
  );
}
