import type { ReactNode } from "react";
import { Switch } from "./forms";
import { Icon } from "./icons";

export const AppBar = ({
  title,
  subtitle,
  large,
  left,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  large?: boolean;
  left?: ReactNode;
  actions?: ReactNode;
}) => (
  <div className={`appbar${large ? " lg" : ""}`}>
    {left}
    <div style={{ flex: 1, minWidth: 0 }}>
      <div className="appbar-title truncate">{title}</div>
      {subtitle && <div className="appbar-sub">{subtitle}</div>}
    </div>
    <div style={{ display: "flex", gap: 2 }}>{actions}</div>
  </div>
);

export const ListRow = ({
  icon,
  iconSlot,
  title,
  sub,
  onClick,
  right,
  danger,
  disabled,
}: {
  icon?: string;
  iconSlot?: ReactNode;
  title: ReactNode;
  sub?: ReactNode;
  onClick?: () => void;
  right?: ReactNode;
  danger?: boolean;
  disabled?: boolean;
}) => {
  const content = (
    <>
      <div
        className="lr-icon"
        style={
          danger
            ? { background: "var(--error-container)", color: "oklch(0.92 0.04 25)" }
            : undefined
        }
      >
        {iconSlot ?? (icon ? <Icon name={icon} /> : null)}
      </div>
      <div className="lr-main">
        <div className="lr-title" style={danger ? { color: "var(--error)" } : undefined}>
          {title}
        </div>
        {sub && <div className="lr-sub">{sub}</div>}
      </div>
    </>
  );

  return (
    <div className="list-row">
      {onClick ? (
        <button
          type="button"
          className="btn-reset"
          onClick={onClick}
          disabled={disabled}
          style={{ display: "flex", alignItems: "center", gap: 14, minWidth: 0, flex: 1 }}
        >
          {content}
        </button>
      ) : (
        content
      )}
      {right && <div style={{ flexShrink: 0, display: "flex", alignItems: "center" }}>{right}</div>}
    </div>
  );
};

export const RowToggle = ({
  icon,
  title,
  sub,
  on,
  onChange,
  danger,
}: {
  icon: string;
  title: string;
  sub?: string;
  on: boolean;
  onChange: (v: boolean) => void;
  danger?: boolean;
}) => (
  <div className="list-row" style={{ cursor: "default" }}>
    <div
      className="lr-icon"
      style={
        danger && on
          ? { background: "var(--error-container)", color: "oklch(0.92 0.04 25)" }
          : undefined
      }
    >
      <Icon name={icon} />
    </div>
    <div className="lr-main">
      <div className="lr-title">{title}</div>
      {sub && <div className="lr-sub">{sub}</div>}
    </div>
    <Switch on={on} onChange={onChange} />
  </div>
);

export const SheetAction = ({
  icon,
  label,
  sub,
  onClick,
  danger,
  disabled,
}: {
  icon: string;
  label: string;
  sub?: string;
  onClick?: () => void;
  danger?: boolean;
  disabled?: boolean;
}) => (
  <button
    type="button"
    onClick={onClick}
    disabled={disabled}
    style={{
      display: "flex",
      alignItems: "center",
      gap: 16,
      padding: "13px 4px",
      background: "none",
      border: "none",
      cursor: disabled ? "default" : "pointer",
      textAlign: "left",
      width: "100%",
      color: danger ? "var(--error)" : "var(--on-surface)",
      fontFamily: "var(--font-ui)",
      opacity: disabled ? 0.4 : 1,
    }}
  >
    <Icon
      name={icon}
      style={{ fontSize: 22, color: danger ? "var(--error)" : "var(--on-surface-variant)" }}
    />
    <div>
      <div style={{ fontSize: 15, fontWeight: 500 }}>{label}</div>
      {sub && (
        <div
          className="mono"
          style={{ fontSize: 12, color: "var(--on-surface-faint)", marginTop: 2 }}
        >
          {sub}
        </div>
      )}
    </div>
  </button>
);
