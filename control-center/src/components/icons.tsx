import type { CSSProperties } from "react";

const iconModules = import.meta.glob<string>("../assets/icons/*.svg", {
  query: "?no-inline",
  import: "default",
  eager: true,
});

const ICON_MASKS = Object.fromEntries(
  Object.entries(iconModules).map(([filePath, iconUrl]) => [
    filePath
      .split("/")
      .pop()
      ?.replace(/\.svg$/, "") ?? filePath,
    `url("${iconUrl}")`,
  ]),
) as Record<string, string>;

const FALLBACK_MASK = ICON_MASKS.error;

type IconStyle = CSSProperties & { "--icon-mask": string };

export const Icon = ({
  name,
  className = "",
  style,
}: {
  name: string;
  className?: string;
  style?: CSSProperties;
}) => {
  const iconStyle: IconStyle = {
    ...style,
    "--icon-mask": ICON_MASKS[name] ?? FALLBACK_MASK,
  };

  return (
    <span
      className={`material-symbols-rounded ${className}`}
      style={iconStyle}
      aria-hidden="true"
    />
  );
};

export const IconBtn = ({
  name,
  onClick,
  title,
  sm,
  className = "",
  style,
}: {
  name: string;
  onClick?: () => void;
  title?: string;
  sm?: boolean;
  className?: string;
  style?: CSSProperties;
}) => (
  <button
    type="button"
    className={`icon-btn ${sm ? "sm " : ""}${className}`}
    onClick={onClick}
    title={title}
    aria-label={title}
    style={style}
  >
    <Icon name={name} />
  </button>
);
