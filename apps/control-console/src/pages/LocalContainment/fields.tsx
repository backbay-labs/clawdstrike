import { clampNumber } from "./utils";

export function TextField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", minWidth: 0 }}
      />
    </label>
  );
}

export function SelectField({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)", background: "rgba(7,8,10,0.72)" }}
      >
        {options.map((item) => (
          <option key={item} value={item}>
            {item}
          </option>
        ))}
      </select>
    </label>
  );
}

export function NumberField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono uppercase tracking-[0.12em] text-[0.65rem] text-[rgba(154,167,181,0.62)]">
        {label}
      </span>
      <input
        aria-label={label}
        type="number"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(clampNumber(event.target.value, min, max, value))}
        className="glass-input font-mono rounded-md px-3 py-2 text-sm outline-none"
        style={{ color: "var(--text)" }}
      />
    </label>
  );
}
