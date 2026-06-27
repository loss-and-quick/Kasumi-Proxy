import {
  type CSSProperties,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type WheelEvent,
} from "react";
import { createPortal } from "react-dom";
import { useT } from "../i18n";
import { Btn } from "./buttons";
import { Icon } from "./icons";
import { Dialog } from "./overlays";

/**
 * Number inputs mutate their value on wheel scroll while focused, even once the
 * cursor has left them; blur on wheel so the event falls through to page scroll.
 * Shared so every numeric `<input>` (Field and one-off inline ones) behaves alike.
 */
export const blurOnWheel = (e: WheelEvent<HTMLInputElement>) => e.currentTarget.blur();

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
  min,
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
  min?: number;
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
        min={min}
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        onWheel={type === "number" ? blurOnWheel : undefined}
      />
    )}
    {error ? (
      <div style={{ fontSize: 11.5, color: "var(--error)", marginTop: 5 }}>{error}</div>
    ) : hint ? (
      <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginTop: 5 }}>{hint}</div>
    ) : null}
  </div>
);

const pad2 = (n: number) => String(n).padStart(2, "0");

// Clock-dial geometry (SVG viewBox is DIAL_SIZE square, centred at DIAL_C).
const DIAL_SIZE = 256;
const DIAL_C = DIAL_SIZE / 2;
const RING_OUTER = 100; // hours 0–11 and the minute ring
const RING_INNER = 62; // hours 12–23
const toRad = (deg: number) => (deg * Math.PI) / 180;
const dialPos = (deg: number, r: number) => ({
  x: DIAL_C + r * Math.sin(toRad(deg)),
  y: DIAL_C - r * Math.cos(toRad(deg)),
});

/**
 * Material-3 clock-dial used by IntervalField. Drives an hour/minute pair via
 * pointer drag on a circular face; releasing in hour mode auto-advances to
 * minutes, like the Android time picker. Hours fill two rings (0–11 outer,
 * 12–23 inner) so the whole 0–23 range — including 0 — is reachable.
 */
function ClockDial({
  mode,
  setMode,
  h,
  m,
  setH,
  setM,
}: {
  mode: "h" | "m";
  setMode: (mode: "h" | "m") => void;
  h: number;
  m: number;
  setH: (h: number) => void;
  setM: (m: number) => void;
}) {
  const t = useT();
  const svgRef = useRef<SVGSVGElement>(null);
  const dragging = useRef(false);
  // Drives the hand's CSS transition: animate the sweep on tap, but track the
  // pointer 1:1 while dragging (no lag).
  const [dragActive, setDragActive] = useState(false);
  // Auto-advance hours → minutes after a short beat so the picked hour is
  // visible before the dial flips (instant felt jarring).
  const advanceTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(advanceTimer.current), []);

  const apply = (e: React.PointerEvent) => {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const dx = ((e.clientX - rect.left) / rect.width) * DIAL_SIZE - DIAL_C;
    const dy = ((e.clientY - rect.top) / rect.height) * DIAL_SIZE - DIAL_C;
    let deg = (Math.atan2(dx, -dy) * 180) / Math.PI;
    if (deg < 0) deg += 360;
    if (mode === "h") {
      const idx = Math.round(deg / 30) % 12;
      const inner = Math.hypot(dx, dy) < (RING_OUTER + RING_INNER) / 2;
      setH(inner ? idx + 12 : idx);
    } else {
      setM(Math.round(deg / 6) % 60);
    }
  };

  // Highlighted value drives the hand + selector; outer-ring hours and the 0–55
  // minute labels sit on RING_OUTER, inner-ring hours on RING_INNER. The hand
  // is drawn pointing straight up and rotated, so a CSS transition on the
  // rotation animates the sweep between values (like the Android picker).
  const selDeg = mode === "h" ? (h % 12) * 30 : m * 6;
  const selR = mode === "h" && h >= 12 ? RING_INNER : RING_OUTER;
  const onLabel = mode === "h" || m % 5 === 0;

  const labels =
    mode === "h"
      ? [
          ...Array.from({ length: 12 }, (_, i) => ({ v: i, r: RING_OUTER })),
          ...Array.from({ length: 12 }, (_, i) => ({ v: i + 12, r: RING_INNER })),
        ]
      : Array.from({ length: 12 }, (_, i) => ({ v: i * 5, r: RING_OUTER }));

  return (
    <div className="timepicker">
      <div className="timepicker-head">
        <div className="timepicker-seg">
          <button
            type="button"
            className={`timepicker-num${mode === "h" ? " active" : ""}`}
            onClick={() => {
              clearTimeout(advanceTimer.current);
              setMode("h");
            }}
          >
            {pad2(h)}
          </button>
          <span className="timepicker-unit">{t("interval.hours")}</span>
        </div>
        <span className="timepicker-colon">:</span>
        <div className="timepicker-seg">
          <button
            type="button"
            className={`timepicker-num${mode === "m" ? " active" : ""}`}
            onClick={() => {
              clearTimeout(advanceTimer.current);
              setMode("m");
            }}
          >
            {pad2(m)}
          </button>
          <span className="timepicker-unit">{t("interval.minutes")}</span>
        </div>
      </div>

      <svg
        ref={svgRef}
        className="timepicker-dial"
        viewBox={`0 0 ${DIAL_SIZE} ${DIAL_SIZE}`}
        width={DIAL_SIZE}
        height={DIAL_SIZE}
        role="presentation"
        onPointerDown={(e) => {
          svgRef.current?.setPointerCapture(e.pointerId);
          clearTimeout(advanceTimer.current);
          dragging.current = true;
          setDragActive(true);
          apply(e);
        }}
        onPointerMove={(e) => {
          if (dragging.current) apply(e);
        }}
        onPointerUp={() => {
          if (!dragging.current) return;
          dragging.current = false;
          setDragActive(false);
          if (mode === "h") advanceTimer.current = setTimeout(() => setMode("m"), 320);
        }}
      >
        <circle cx={DIAL_C} cy={DIAL_C} r={DIAL_C - 8} className="dial-face" />
        <g
          className={`dial-hand-group${dragActive ? " dragging" : ""}`}
          style={{ transform: `rotate(${selDeg}deg)` }}
        >
          <line x1={DIAL_C} y1={DIAL_C} x2={DIAL_C} y2={DIAL_C - selR} className="dial-hand" />
          <circle cx={DIAL_C} cy={DIAL_C - selR} r={20} className="dial-selector" />
          {!onLabel && <circle cx={DIAL_C} cy={DIAL_C - selR} r={2} className="dial-pivot-end" />}
        </g>
        <circle cx={DIAL_C} cy={DIAL_C} r={5} className="dial-pivot" />
        {/* key={mode} remounts the set on each hour⇄minute switch, replaying the
            fade/scale so the dial transition reads as a crossfade. */}
        <g className="dial-labels" key={mode}>
          {labels.map(({ v, r }) => {
            const idx = mode === "h" ? v % 12 : v / 5;
            const p = dialPos(idx * 30, r);
            const selected = (mode === "h" ? h : m) === v;
            return (
              <text
                key={v}
                x={p.x}
                y={p.y}
                className={`dial-label${selected ? " selected" : ""}${r === RING_INNER ? " inner" : ""}`}
              >
                {pad2(v)}
              </text>
            );
          })}
        </g>
      </svg>
    </div>
  );
}

/**
 * Interval picker for a duration stored as a minute count. Tapping the field
 * opens a Material-3 clock-dial dialog (see ClockDial). Built in-house rather
 * than reusing `<input type="time">`: that native control is a wall-clock widget
 * whose desktop (WebKitGTK) implementation could not reach a 0-hour value. Hours
 * are capped at 23 and minutes at 59 (max interval 23:59).
 */
export const IntervalField = ({
  label,
  minutes,
  onChange,
  error,
}: {
  label?: string;
  minutes: number;
  onChange: (minutes: number) => void;
  error?: string;
}) => {
  const t = useT();
  const safe = Math.max(0, Math.floor(minutes) || 0);
  const h = Math.floor(safe / 60);
  const m = safe % 60;

  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"h" | "m">("h");
  const [draftH, setDraftH] = useState(h);
  const [draftM, setDraftM] = useState(m);

  const openPicker = () => {
    setDraftH(h);
    setDraftM(m);
    setMode("h");
    setOpen(true);
  };
  const commit = () => {
    onChange(draftH * 60 + draftM);
    setOpen(false);
  };

  return (
    <div className="field">
      {label && <div className="field-label">{label}</div>}
      <button
        type="button"
        className="input interval-trigger"
        style={error ? { borderBottomColor: "var(--error)" } : undefined}
        onClick={openPicker}
      >
        <span>{`${pad2(h)}:${pad2(m)}`}</span>
        <Icon name="schedule" />
      </button>
      {error ? (
        <div style={{ fontSize: 11.5, color: "var(--error)", marginTop: 5 }}>{error}</div>
      ) : null}
      {/* Portal to <body>: the picker opens from inside a Sheet, so a centred
          dialog must escape that sheet's absolute-positioned, clipped body and
          out-stack it (sheet-over-sheet would just overlap at the bottom). */}
      {createPortal(
        <Dialog
          open={open}
          title={t("interval.pickTitle")}
          onClose={() => setOpen(false)}
          actions={
            <>
              <Btn variant="text" onClick={() => setOpen(false)}>
                {t("interval.cancel")}
              </Btn>
              <Btn variant="text" onClick={commit}>
                {t("interval.ok")}
              </Btn>
            </>
          }
        >
          <ClockDial
            mode={mode}
            setMode={setMode}
            h={draftH}
            m={draftM}
            setH={setDraftH}
            setM={setDraftM}
          />
        </Dialog>,
        document.body,
      )}
    </div>
  );
};

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
