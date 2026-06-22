import {
  type CSSProperties,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { createPortal } from "react-dom";
import { Icon } from "./icons";

type Opt<T extends string> = T | { value: T; label: string };
/** A group renders a non-selectable header above its options (replaces <optgroup>). */
type OptGroup<T extends string> = { group: string; options: Opt<T>[] };
type SelectItem<T extends string> = Opt<T> | OptGroup<T>;

export const Switch = ({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) => (
  <button
    type="button"
    className={`switch${on ? " on" : ""}`}
    onClick={() => onChange(!on)}
    role="switch"
    aria-checked={on}
  />
);

export function Segmented<T extends string>({
  options,
  value,
  onChange,
}: {
  options: Opt<T>[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div className="segmented">
      {options.map((o) => {
        const val = typeof o === "string" ? o : o.value;
        const lab = typeof o === "string" ? o : o.label;
        return (
          <button
            type="button"
            key={val}
            className={value === val ? "active" : ""}
            onClick={() => onChange(val)}
          >
            {lab}
          </button>
        );
      })}
    </div>
  );
}

export const Field = ({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
  mono = true,
  hint,
  error,
  area,
}: {
  label?: string;
  value: string | number;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  hint?: string;
  error?: string;
  area?: boolean;
}) => (
  <div className="field">
    {label && <div className="field-label">{label}</div>}
    {area ? (
      <textarea
        className="input"
        style={mono ? undefined : { fontFamily: "var(--font-ui)" }}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    ) : (
      <input
        className="input"
        style={{
          ...(mono ? null : { fontFamily: "var(--font-ui)" }),
          ...(error ? { borderBottomColor: "var(--error)" } : null),
        }}
        type={type}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    )}
    {error ? (
      <div style={{ fontSize: 11.5, color: "var(--error)", marginTop: 5 }}>{error}</div>
    ) : hint ? (
      <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginTop: 5 }}>{hint}</div>
    ) : null}
  </div>
);

const normOpt = <T extends string>(o: Opt<T>): { value: T; label: string } =>
  typeof o === "string" ? { value: o, label: o === "" ? "— none —" : o } : o;

const isGroup = <T extends string>(o: SelectItem<T>): o is OptGroup<T> =>
  typeof o === "object" && "group" in o;

/**
 * Custom dropdown that renders an identical Material menu on every platform,
 * instead of the OS-native <select> popup. The menu lives in a portal and is
 * positioned over the trigger so it escapes scroll/overflow clipping; it flips
 * above the trigger when there is more room there.
 */
export function Select<T extends string>({
  label,
  value,
  onChange,
  options,
  disabled,
  hint,
  placeholder,
  className,
  style,
}: {
  label?: string;
  value: T;
  onChange: (v: T) => void;
  options: SelectItem<T>[];
  disabled?: boolean;
  hint?: string;
  /** Shown on the trigger when no option matches `value`. */
  placeholder?: string;
  /** Extra class / inline style for the trigger button (sizing, flex). */
  className?: string;
  style?: CSSProperties;
}) {
  // Flatten into a render list (group headers + options) and a flat list of the
  // selectable options (for label lookup and keyboard navigation).
  const rows: ({ header: string } | { value: T; label: string })[] = [];
  const selectable: { value: T; label: string }[] = [];
  for (const item of options) {
    if (isGroup(item)) {
      rows.push({ header: item.group });
      for (const inner of item.options) {
        const n = normOpt(inner);
        rows.push(n);
        selectable.push(n);
      }
    } else {
      const n = normOpt(item);
      rows.push(n);
      selectable.push(n);
    }
  }
  const current = selectable.find((o) => o.value === value);

  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{
    left: number;
    top: number;
    width: number;
    maxHeight: number;
    up: boolean;
  } | null>(null);

  const place = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const margin = 8;
    const below = window.innerHeight - r.bottom - margin;
    const above = r.top - margin;
    const up = below < 220 && above > below;
    const maxHeight = Math.max(120, Math.min(320, up ? above : below));
    setPos({ left: r.left, top: up ? r.top : r.bottom, width: r.width, maxHeight, up });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  // Reposition (rather than tear down) while open so the menu tracks the trigger
  // through scroll/resize; capture phase catches inner scroll containers too.
  useEffect(() => {
    if (!open) return;
    const onMove = () => place();
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("resize", onMove);
    return () => {
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("resize", onMove);
    };
  }, [open, place]);

  // Keep the active option in view as it changes.
  useEffect(() => {
    if (!open) return;
    menuRef.current
      ?.querySelector<HTMLElement>(`[data-idx="${active}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const openMenu = () => {
    if (disabled) return;
    const idx = selectable.findIndex((o) => o.value === value);
    setActive(idx < 0 ? 0 : idx);
    setOpen(true);
  };

  const choose = (v: T) => {
    onChange(v);
    setOpen(false);
    triggerRef.current?.focus();
  };

  const onKey = (e: KeyboardEvent) => {
    if (!open) {
      if (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    if (e.key === "Escape") {
      e.preventDefault();
      setOpen(false);
      triggerRef.current?.focus();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(selectable.length - 1, i + 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Home") {
      e.preventDefault();
      setActive(0);
    } else if (e.key === "End") {
      e.preventDefault();
      setActive(selectable.length - 1);
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      const opt = selectable[active];
      if (opt) choose(opt.value);
    }
  };

  const trigger = (
    <button
      type="button"
      ref={triggerRef}
      className={`select-trigger${className ? ` ${className}` : ""}`}
      style={style}
      disabled={disabled}
      aria-haspopup="listbox"
      aria-expanded={open}
      onClick={() => (open ? setOpen(false) : openMenu())}
      onKeyDown={onKey}
    >
      <span className={`select-value${current ? "" : " placeholder"}`}>
        {current ? current.label : (placeholder ?? "")}
      </span>
      <Icon name="expand_more" className={`select-arrow${open ? " up" : ""}`} />
    </button>
  );

  const menu =
    open && pos
      ? createPortal(
          <>
            <button
              type="button"
              className="select-overlay"
              aria-label="Close"
              onPointerDown={() => setOpen(false)}
            />
            <div
              ref={menuRef}
              className={`select-menu${pos.up ? " up" : ""}`}
              role="listbox"
              tabIndex={-1}
              style={{
                left: pos.left,
                width: pos.width,
                maxHeight: pos.maxHeight,
                ...(pos.up ? { bottom: window.innerHeight - pos.top } : { top: pos.top }),
              }}
              onKeyDown={onKey}
            >
              {rows.map((row) =>
                "header" in row ? (
                  <div key={`h-${row.header}`} className="select-group">
                    {row.header}
                  </div>
                ) : (
                  <button
                    type="button"
                    key={row.value}
                    data-idx={selectable.indexOf(row)}
                    role="option"
                    aria-selected={row.value === value}
                    className={`select-option${row.value === value ? " selected" : ""}${
                      selectable.indexOf(row) === active ? " active" : ""
                    }`}
                    onClick={() => choose(row.value)}
                    onPointerEnter={() => setActive(selectable.indexOf(row))}
                  >
                    <span className="select-option-label">{row.label}</span>
                    {row.value === value ? <Icon name="check" className="select-check" /> : null}
                  </button>
                ),
              )}
            </div>
          </>,
          document.body,
        )
      : null;

  if (!label && !hint) {
    return (
      <>
        {trigger}
        {menu}
      </>
    );
  }

  return (
    <div className="field">
      {label && <div className="field-label">{label}</div>}
      {trigger}
      {hint ? (
        <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginTop: 5 }}>{hint}</div>
      ) : null}
      {menu}
    </div>
  );
}
