import type { CSSProperties, ReactNode } from "react";
import { Icon } from "./icons";

export const ProtoTag = ({ protocol }: { protocol: string }) => (
  <span className={`tag ${protocol}`}>{protocol}</span>
);

export const EngineTag = ({ engine }: { engine: string }) => (
  <span className={`tag engine-${engine}`}>{engine}</span>
);

export function pingClass(v: number | null) {
  return v == null || v < 0 ? "ping-na" : v < 120 ? "ping-good" : v < 220 ? "ping-mid" : "ping-bad";
}

export function pingLabel(v: number | null) {
  return v == null || v < 0 ? "—" : `${v} ms`;
}

export const Ping = ({ value }: { value: number | null }) => (
  <span className={`mono ${pingClass(value)}`} style={{ fontSize: 12, fontWeight: 600 }}>
    {pingLabel(value)}
  </span>
);

export function speedLabel(bps: number | null | undefined): string {
  if (bps == null || bps < 0) return "—";
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} MB/s`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} KB/s`;
  return `${bps} B/s`;
}

export const Speed = ({ value }: { value: number | null | undefined }) => (
  <span
    className={`mono ${value == null || value < 0 ? "ping-na" : "ping-good"}`}
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
