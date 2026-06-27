import type { CSSProperties, MouseEvent } from "react";

// Inline the SVG source (not a URL): rendering real <svg> in the DOM avoids the
// CSS-mask path, which webkit2gtk drops on elements promoted to a compositing
// layer by a transform animation/transition (spinning icons, the select arrow),
// leaving the bare background as a solid square. The assets use fill="currentColor"
// and a 1em box, so color and size still follow the surrounding text.
const iconModules = import.meta.glob<string>("../assets/icons/*.svg", {
  query: "?raw",
  import: "default",
  eager: true,
});

const ICON_SVGS = Object.fromEntries(
  Object.entries(iconModules).map(([filePath, svg]) => [
    filePath
      .split("/")
      .pop()
      ?.replace(/\.svg$/, "") ?? filePath,
    svg,
  ]),
) as Record<string, string>;

const FALLBACK_SVG = ICON_SVGS.error;

export const Icon = ({
  name,
  className = "",
  style,
}: {
  name: string;
  className?: string;
  style?: CSSProperties;
}) => (
  <span
    className={`material-symbols-rounded ${className}`}
    style={style}
    aria-hidden="true"
    // biome-ignore lint/security/noDangerouslySetInnerHtml: trusted, build-time-bundled local SVGs — no user input, so no XSS surface.
    dangerouslySetInnerHTML={{ __html: ICON_SVGS[name] ?? FALLBACK_SVG }}
  />
);

export const IconBtn = ({
  name,
  onClick,
  onMouseDown,
  title,
  sm,
  className = "",
  style,
}: {
  name: string;
  onClick?: () => void;
  onMouseDown?: (e: MouseEvent<HTMLButtonElement>) => void;
  title?: string;
  sm?: boolean;
  className?: string;
  style?: CSSProperties;
}) => (
  <button
    type="button"
    className={`icon-btn ${sm ? "sm " : ""}${className}`}
    onClick={onClick}
    onMouseDown={onMouseDown}
    title={title}
    aria-label={title}
    style={style}
  >
    <Icon name={name} />
  </button>
);
