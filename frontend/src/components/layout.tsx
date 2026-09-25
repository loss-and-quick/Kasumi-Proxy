import { type ReactNode, useState } from "react";
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

/** A setting: title and optional hint on the left, a compact control on the right.
 *  `stacked` puts a wide control (segmented, text field) under the title instead. */
export const SettingRow = ({
  title,
  hint,
  stacked,
  children,
}: {
  title: ReactNode;
  hint?: ReactNode;
  stacked?: boolean;
  children: ReactNode;
}) => (
  <div className={`setting-row${stacked ? " stacked" : ""}`}>
    <div className="sr-main">
      <div className="sr-title">{title}</div>
      {hint && <div className="sr-hint">{hint}</div>}
    </div>
    <div className="sr-control">{children}</div>
  </div>
);

/** Options revealed under a toggle row, indented to line up with the row's text. */
export const SettingGroup = ({ children }: { children: ReactNode }) => (
  <div className="setting-group">{children}</div>
);

/** A row that navigates somewhere: icon, title, one-line summary and a chevron. */
export const NavRow = ({
  icon,
  title,
  sub,
  onClick,
  selected,
}: {
  icon: string;
  title: ReactNode;
  sub?: ReactNode;
  onClick: () => void;
  selected?: boolean;
}) => (
  <div className={`nav-row${selected ? " selected" : ""}`}>
    <ListRow
      icon={icon}
      title={title}
      sub={sub}
      onClick={onClick}
      right={<Icon name="chevron_right" style={{ color: "var(--on-surface-faint)" }} />}
    />
  </div>
);

/** Rarely-touched options folded away behind a "show more" toggle. */
export const Disclosure = ({
  label,
  defaultOpen,
  children,
}: {
  label: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}) => {
  const [open, setOpen] = useState(defaultOpen ?? false);
  return (
    <>
      <button
        type="button"
        className={`disclosure${open ? " open" : ""}`}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span style={{ flex: 1 }}>{label}</span>
        <Icon name="expand_more" />
      </button>
      {open && children}
    </>
  );
};
