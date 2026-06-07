type Opt<T extends string> = T | { value: T; label: string };

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

export function Select<T extends string>({
  label,
  value,
  onChange,
  options,
  disabled,
  hint,
}: {
  label?: string;
  value: T;
  onChange: (v: T) => void;
  options: Opt<T>[];
  disabled?: boolean;
  hint?: string;
}) {
  const normalized = options.map((o) => ({
    value: typeof o === "string" ? o : o.value,
    label: typeof o === "string" ? (o === "" ? "— none —" : o) : o.label,
  }));

  return (
    <div className="field">
      {label && <div className="field-label">{label}</div>}
      <select
        className="select-box"
        value={value}
        disabled={disabled}
        onChange={(e) => {
          const selected = normalized.find((o) => o.value === e.currentTarget.value);
          if (selected) onChange(selected.value);
        }}
      >
        {normalized.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {hint ? (
        <div style={{ fontSize: 11.5, color: "var(--on-surface-faint)", marginTop: 5 }}>{hint}</div>
      ) : null}
    </div>
  );
}
