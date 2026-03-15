/**
 * Shared form primitives for visual panel editors (Sigma, YARA, OCSF).
 *
 * All accent-colored focus borders use inline `style` instead of dynamic
 * Tailwind classes, which avoids the JIT class-generation problem where
 * `focus:border-[${variable}]` never gets compiled.
 */
import { useState, useId } from "react";
import { IconChevronRight, IconChevronDown } from "@tabler/icons-react";
import { cn } from "@/lib/utils";


// ---- Collapsible Section ----

export function Section({
  title,
  icon: Icon,
  defaultOpen = true,
  count,
  accentColor,
  children,
}: {
  title: string;
  icon: React.ComponentType<{ size?: number; stroke?: number; className?: string }>;
  defaultOpen?: boolean;
  count?: number;
  accentColor: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <section className="flex flex-col">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-4 py-2.5 hover:bg-[#131721]/50 transition-colors"
      >
        <IconChevronRight
          size={12}
          stroke={1.5}
          className="text-[#6f7f9a]/70 transition-transform"
          style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)", transitionDuration: "150ms" }}
        />
        <Icon size={12} stroke={1.5} className="text-[#6f7f9a]/70" />
        <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
          {title}
        </span>
        {count !== undefined && count > 0 && (
          <span
            className="text-[9px] font-mono px-1.5 py-0.5 rounded-full"
            style={{
              color: accentColor,
              backgroundColor: `${accentColor}15`,
            }}
          >
            {count}
          </span>
        )}
      </button>
      <div
        className="grid transition-[grid-template-rows]"
        style={{
          gridTemplateRows: open ? '1fr' : '0fr',
          transitionDuration: 'var(--duration-normal, 250ms)',
          transitionTimingFunction: 'var(--ease-out-quart, cubic-bezier(0.25, 1, 0.5, 1))',
        }}
      >
        <div className="overflow-hidden">
          <div className="flex flex-col gap-3 px-4 pb-4 pt-1">
            {children}
          </div>
        </div>
      </div>
    </section>
  );
}


// ---- Field Label ----

export function FieldLabel({ label, required, htmlFor }: { label: string; required?: boolean; htmlFor?: string }) {
  return (
    <label htmlFor={htmlFor} className="text-[10px] font-semibold text-[#6f7f9a] uppercase tracking-[0.06em]">
      {label}
      {required && <span className="text-[#c45c5c] ml-0.5">*</span>}
    </label>
  );
}


// ---- Text Input ----

export function TextInput({
  label,
  value,
  onChange,
  placeholder,
  required,
  readOnly,
  mono,
  accentColor,
  id: idProp,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  required?: boolean;
  readOnly?: boolean;
  mono?: boolean;
  accentColor: string;
  id?: string;
}) {
  const [focused, setFocused] = useState(false);
  const autoId = useId();
  const id = idProp ?? autoId;

  return (
    <div className="flex flex-col gap-1">
      <FieldLabel label={label} required={required} htmlFor={id} />
      <input
        id={id}
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        readOnly={readOnly}
        style={focused ? { borderColor: `${accentColor}80` } : undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        className={cn(
          "bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] text-[#ece7dc] px-2 py-1 transition-colors",
          readOnly && "opacity-60 cursor-default",
          mono && "font-mono",
        )}
      />
    </div>
  );
}


// ---- Text Area ----

export function TextArea({
  label,
  value,
  onChange,
  placeholder,
  readOnly,
  rows = 3,
  accentColor,
  id: idProp,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  readOnly?: boolean;
  rows?: number;
  accentColor: string;
  id?: string;
}) {
  const [focused, setFocused] = useState(false);
  const autoId = useId();
  const id = idProp ?? autoId;

  return (
    <div className="flex flex-col gap-1">
      <FieldLabel label={label} htmlFor={id} />
      <textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        readOnly={readOnly}
        rows={rows}
        style={focused ? { borderColor: `${accentColor}80` } : undefined}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        className={cn(
          "bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] px-2 py-1.5 transition-colors resize-none leading-relaxed",
          readOnly && "opacity-60 cursor-default",
        )}
      />
    </div>
  );
}


// ---- Select Input ----

export type SelectOption = string | { value: string | number; label: string };

export function SelectInput({
  label,
  value,
  options,
  onChange,
  readOnly,
  required,
  placeholder,
  accentColor,
  id: idProp,
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  readOnly?: boolean;
  required?: boolean;
  placeholder?: string;
  accentColor: string;
  id?: string;
}) {
  const [focused, setFocused] = useState(false);
  const autoId = useId();
  const id = idProp ?? autoId;

  return (
    <div className="flex flex-col gap-1">
      <FieldLabel label={label} required={required} htmlFor={id} />
      <div className="relative">
        <select
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={readOnly}
          style={focused ? { borderColor: `${accentColor}80` } : undefined}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          className={cn(
            "bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc] px-2 py-1 pr-7 transition-colors appearance-none cursor-pointer w-full",
            readOnly && "opacity-60 cursor-default",
          )}
        >
          {placeholder && <option value="">{placeholder}</option>}
          {options.map((opt) => {
            if (typeof opt === "string") {
              return (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              );
            }
            return (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            );
          })}
        </select>
        <IconChevronDown
          size={10}
          stroke={1.5}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a]/50 pointer-events-none"
        />
      </div>
    </div>
  );
}
