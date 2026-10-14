import type { CSSProperties, ReactNode } from "react";
import { Icon } from "./icons";

export const Spinner = ({ size = 14 }: { size?: number }) => (
  <Icon
    name="autorenew"
    className="spin"
    style={{ fontSize: size, color: "var(--on-surface-variant)" }}
  />
);

export const ProtoTag = ({ protocol }: { protocol: string }) => (
  <span className={`tag ${protocol}`}>{protocol}</span>
);

export const EngineTag = ({ engine }: { engine: string }) => (
  <span className={`tag engine-${engine}`}>{engine}</span>
);

export function pingClass(v: number | null) {
  return v == null
    ? "ping-na"
    : v < 0
      ? "ping-bad"
      : v < 120
        ? "ping-good"
        : v < 220
          ? "ping-mid"
          : "ping-bad";
}

export function pingLabel(v: number | null) {
  // null = never tested ("—"); any negative = the test failed, shown as "err"
  // (unreachable -1 vs probe-core error -2 differ only in the toast/reason).
  if (v == null) return "—";
  if (v < 0) return "err";
  return `${v} ms`;
}

export const Ping = ({ value, animate }: { value: number | null; animate?: boolean }) => (
  <span
    className={`mono ${animate ? "metric-pop " : ""}${pingClass(value)}`}
    style={{ fontSize: 12, fontWeight: 600 }}
  >
    {pingLabel(value)}
  </span>
);

export function speedLabel(bps: number | null | undefined): string {
  // null = never tested ("—"); any negative = failed ("err").
  if (bps == null) return "—";
  if (bps < 0) return "err";
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} KB/s`;
  return `${bps} B/s`;
}

export const Speed = ({
  value,
  animate,
}: {
  value: number | null | undefined;
  animate?: boolean;
}) => (
  <span
    className={`mono ${animate ? "metric-pop " : ""}${value == null ? "ping-na" : value < 0 ? "ping-bad" : "ping-good"}`}
    style={{ fontSize: 12, fontWeight: 600 }}
  >
    {speedLabel(value)}
  </span>
);

export const Card = ({
  children,
  className = "",
  onClick,
  style,
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
  style?: CSSProperties;
}) => {
  const cardClassName = `card ${className}`.trim();

  if (!onClick) {
    return (
      <div className={cardClassName} style={style}>
        {children}
      </div>
    );
  }

  return (
    <button
      type="button"
      className={cardClassName}
      onClick={onClick}
      style={{
        ...style,
        appearance: "none",
        border: "none",
        cursor: "pointer",
        font: "inherit",
        textAlign: "inherit",
        width: "100%",
      }}
    >
      {children}
    </button>
  );
};

export const SectionLabel = ({ children, action }: { children: ReactNode; action?: ReactNode }) => (
  <div className="section-label">
    <span>{children}</span>
    {action}
  </div>
);

export const EmptyHint = ({ icon, text }: { icon: string; text: string }) => (
  <Card
    className="flat"
    style={{
      display: "flex",
      gap: 12,
      alignItems: "center",
      color: "var(--on-surface-variant)",
      marginTop: 4,
    }}
  >
    <Icon name={icon} style={{ fontSize: 22, color: "var(--on-surface-faint)" }} />
    <span style={{ fontSize: 13, lineHeight: 1.4 }}>{text}</span>
  </Card>
);

/**
 * Text that gives up its middle when the line is too narrow, so the ends that
 * tell hosts apart (the first label, the domain suffix and the port) stay in view.
 * The full text is the hover title.
 */
export function MiddleEllipsis({
  text,
  tail = 12,
  className,
}: {
  text: string;
  /** Trailing characters that are never cut. */
  tail?: number;
  className?: string;
}) {
  const chars = Array.from(text);
  const cut = Math.max(0, chars.length - tail);
  return (
    <span className={`mid-ellipsis${className ? ` ${className}` : ""}`} dir="auto" title={text}>
      <span className="mid-head">{chars.slice(0, cut).join("")}</span>
      <span className="mid-tail">{chars.slice(cut).join("")}</span>
    </span>
  );
}
