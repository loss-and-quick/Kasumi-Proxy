import type { CSSProperties, ReactNode } from "react";
import { Icon } from "./icons";

type Variant = "filled" | "tonal" | "outline" | "text" | "error";

export const Btn = ({
  variant = "filled",
  icon,
  children,
  onClick,
  className = "",
  sm,
  block,
  disabled,
  style,
}: {
  variant?: Variant;
  icon?: string;
  children?: ReactNode;
  onClick?: () => void;
  className?: string;
  sm?: boolean;
  block?: boolean;
  disabled?: boolean;
  style?: CSSProperties;
}) => (
  <button
    type="button"
    className={`btn btn-${variant} ${sm ? "btn-sm " : ""}${block ? "btn-block " : ""}${className}`}
    onClick={onClick}
    disabled={disabled}
    style={style}
  >
    {icon && <Icon name={icon} />}
    {children}
  </button>
);

export const Chip = ({
  active,
  icon,
  children,
  onClick,
}: {
  active?: boolean;
  icon?: string;
  children: ReactNode;
  onClick?: () => void;
}) => (
  <button type="button" className={`chip${active ? " active" : ""}`} onClick={onClick}>
    {icon && <Icon name={icon} />}
    {children}
  </button>
);
