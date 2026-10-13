import type { TrafficInfo } from "../../generated/bindings";
import { useT } from "../../i18n";
import { formatBytes } from "../../lib/format";
import { trafficUsage } from "./sub-display";

/** Used against the plan's quota; an unmetered plan shows the usage alone. */
export function TrafficBar({ traffic }: { traffic: TrafficInfo }) {
  const t = useT();
  const { used, total, ratio } = trafficUsage(traffic);
  const fill =
    ratio != null && ratio >= 0.95
      ? "var(--error)"
      : ratio != null && ratio >= 0.8
        ? "var(--warn)"
        : "var(--primary)";
  return (
    <div>
      <div
        className="mono"
        style={{ fontSize: 11.5, color: "var(--on-surface-variant)", marginBottom: 6 }}
      >
        {ratio == null
          ? t("subs.provider.trafficUnlimited", { used: formatBytes(used) })
          : t("subs.provider.traffic", { used: formatBytes(used), total: formatBytes(total) })}
      </div>
      {ratio != null && (
        <div
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(ratio * 100)}
          style={{ height: 6, borderRadius: 3, background: "var(--sc-high)", overflow: "hidden" }}
        >
          <div
            style={{
              width: `${ratio * 100}%`,
              height: "100%",
              borderRadius: 3,
              background: fill,
            }}
          />
        </div>
      )}
    </div>
  );
}
