import { useCallback, useState, useEffect } from "react";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TagList } from "@/components/workbench/shared/tag-list";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId, ConfigFieldDef, SecretPattern } from "@/lib/workbench/types";
import { IconAlertTriangle, IconCheck } from "@tabler/icons-react";

interface GuardConfigFieldsProps {
  guardId: GuardId;
  config: Record<string, unknown>;
  onChange: (key: string, value: unknown) => void;
  /** Keys to exclude from rendering (handled by custom UI elsewhere). */
  excludeKeys?: Set<string>;
}

/** Get a nested value from an object by dot-separated key */
function getNestedValue(obj: Record<string, unknown>, key: string): unknown {
  const parts = key.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

function getRegexError(pattern: string): string {
  try {
    new RegExp(pattern);
    return "";
  } catch (e) {
    return e instanceof SyntaxError ? e.message : "Invalid regex";
  }
}

// ---- Secret pattern list editor ----

interface SecretPatternListProps {
  patterns: SecretPattern[];
  onChange: (patterns: SecretPattern[]) => void;
}

const SEVERITY_OPTIONS = ["info", "warning", "error", "critical"] as const;
const SEVERITY_COLORS: Record<string, string> = {
  info: "text-[#6f7f9a]",
  warning: "text-[#d4a84b]",
  error: "text-[#c45c5c]",
  critical: "text-[#c45c5c] font-semibold",
};

function SecretPatternListEditor({ patterns, onChange }: SecretPatternListProps) {
  const [regexErrors, setRegexErrors] = useState<Record<number, string>>({});

  const addRow = useCallback(() => {
    onChange([...patterns, { name: "", pattern: "", severity: "critical" }]);
  }, [patterns, onChange]);

  const updateRow = useCallback(
    (index: number, field: keyof SecretPattern, value: string) => {
      // Always persist the value so typing intermediate states works.
      // Validate regex on each keystroke but only as a visual warning — never block input.
      if (field === "pattern" && value !== "") {
        if (!isValidRegex(value)) {
          setRegexErrors((prev) => ({ ...prev, [index]: `Invalid regex: ${getRegexError(value)}` }));
        } else {
          setRegexErrors((prev) => {
            const next = { ...prev };
            delete next[index];
            return next;
          });
        }
      } else {
        setRegexErrors((prev) => {
          const next = { ...prev };
          delete next[index];
          return next;
        });
      }
      const updated = patterns.map((p, i) =>
        i === index ? { ...p, [field]: value } : p
      );
      onChange(updated);
    },
    [patterns, onChange]
  );

  const removeRow = useCallback(
    (index: number) => {
      setRegexErrors((prev) => {
        const next = { ...prev };
        delete next[index];
        return next;
      });
      onChange(patterns.filter((_, i) => i !== index));
    },
    [patterns, onChange]
  );

  return (
    <div className="flex flex-col gap-2">
      {patterns.map((p, index) => (
        <div key={index} className="flex flex-col gap-0.5">
          <div className="grid grid-cols-[1fr_1.5fr_auto_auto] gap-2 items-center">
            <input
              type="text"
              value={p.name}
              onChange={(e) => updateRow(index, "name", e.target.value)}
              placeholder="e.g., ssh_key_access"
              aria-label="Pattern name"
              className="h-7 rounded-md border border-[#2d3240] bg-[#131721] px-2 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50"
            />
            <div className="relative">
              <input
                type="text"
                value={p.pattern}
                onChange={(e) => {
                  // Allow typing freely — validate on blur/commit, show live indicator
                  const val = e.target.value;
                  // Clear error when user starts editing
                  if (regexErrors[index]) {
                    setRegexErrors((prev) => {
                      const next = { ...prev };
                      delete next[index];
                      return next;
                    });
                  }
                  updateRow(index, "pattern", val);
                }}
                placeholder="e.g., ^/etc/passwd$"
                aria-label="Regex pattern"
                className={`h-7 w-full rounded-md border bg-[#131721] px-2 pr-6 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 ${
                  regexErrors[index] ? "border-[#c45c5c]" : "border-[#2d3240]"
                }`}
              />
              {p.pattern && (
                <span className="absolute right-1.5 top-1/2 -translate-y-1/2">
                  {isValidRegex(p.pattern) ? (
                    <IconCheck size={12} className="text-[#3dbf84]" />
                  ) : (
                    <IconAlertTriangle size={12} className="text-[#c45c5c]" />
                  )}
                </span>
              )}
            </div>
            <Select
              value={p.severity}
              onValueChange={(val) => updateRow(index, "severity", val as string)}
            >
              <SelectTrigger className={`h-7 min-w-[90px] bg-[#131721] border-[#2d3240] text-[10px] font-mono ${SEVERITY_COLORS[p.severity]}`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {SEVERITY_OPTIONS.map((s) => (
                  <SelectItem
                    key={s}
                    value={s}
                    className="text-[10px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <button
              type="button"
              onClick={() => removeRow(index)}
              className="h-7 w-7 flex items-center justify-center rounded-md text-[#6f7f9a] hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors"
            >
              &times;
            </button>
          </div>
          {regexErrors[index] && (
            <span className="text-[9px] font-mono text-[#c45c5c] pl-1">
              {regexErrors[index]}
            </span>
          )}
        </div>
      ))}
      <button
        type="button"
        onClick={addRow}
        className="self-start px-2.5 py-1 text-[10px] font-mono text-[#d4a84b] border border-[#2d3240] rounded-md hover:border-[#d4a84b]/40 hover:bg-[#131721] transition-colors"
      >
        + Add pattern
      </button>
    </div>
  );
}

// ---- Pattern list with regex validation indicators ----

interface PatternListProps {
  items: string[];
  onChange: (items: string[]) => void;
  placeholder?: string;
}

function PatternList({ items, onChange, placeholder }: PatternListProps) {
  const [inputError, setInputError] = useState<string | null>(null);

  // Auto-clear error after 3 seconds
  useEffect(() => {
    if (!inputError) return;
    const timer = setTimeout(() => setInputError(null), 3000);
    return () => clearTimeout(timer);
  }, [inputError]);

  return (
    <div className="flex flex-col gap-2">
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {items.map((item, index) => (
            <span
              key={`${item}-${index}`}
              className="inline-flex items-center gap-1 px-2 py-0.5 bg-[#131721] border border-[#2d3240] text-[#ece7dc] font-mono text-xs rounded-md"
            >
              {isValidRegex(item) ? (
                <IconCheck size={10} className="text-[#3dbf84] shrink-0" />
              ) : (
                <IconAlertTriangle size={10} className="text-[#c45c5c] shrink-0" />
              )}
              {item}
              <button
                type="button"
                onClick={() => onChange(items.filter((_, i) => i !== index))}
                className="text-[#6f7f9a] hover:text-[#c45c5c] transition-colors ml-0.5"
              >
                &times;
              </button>
            </span>
          ))}
        </div>
      )}
      <input
        type="text"
        placeholder={placeholder ?? "Add pattern..."}
        aria-label={placeholder ?? "Add pattern"}
        className={`h-8 w-full rounded-md border bg-[#131721] px-2.5 py-1 text-xs font-mono text-[#ece7dc] placeholder:text-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50 transition-colors ${
          inputError ? "border-[#c45c5c]" : "border-[#2d3240]"
        }`}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            const val = (e.target as HTMLInputElement).value.trim();
            if (!val) return;

            // Issue #15: Check for duplicates
            if (items.includes(val)) {
              setInputError("Duplicate pattern — already in list");
              return;
            }

            setInputError(null);
            onChange([...items, val]);
            (e.target as HTMLInputElement).value = "";
          }
        }}
      />
      {inputError && (
        <span className="text-[9px] font-mono text-[#c45c5c]">
          {inputError}
        </span>
      )}
    </div>
  );
}

// ---- Main component ----

export function GuardConfigFields({ guardId, config, onChange, excludeKeys }: GuardConfigFieldsProps) {
  const meta = GUARD_REGISTRY.find((g) => g.id === guardId);
  if (!meta) return null;

  // Filter out the "enabled" toggle since that is handled in the card header,
  // plus any keys explicitly excluded by the caller.
  const fields = meta.configFields.filter(
    (f) => f.key !== "enabled" && !excludeKeys?.has(f.key),
  );

  return (
    <div className="flex flex-col gap-4 pt-3">
      {fields.map((field) => (
        <FieldRenderer
          key={field.key}
          field={field}
          value={getNestedValue(config, field.key)}
          onChange={(value) => onChange(field.key, value)}
        />
      ))}
    </div>
  );
}

// ---- Individual field renderer ----

interface FieldRendererProps {
  field: ConfigFieldDef;
  value: unknown;
  onChange: (value: unknown) => void;
}

function FieldRenderer({ field, value, onChange }: FieldRendererProps) {
  switch (field.type) {
    case "toggle":
      return (
        <div className="flex items-center justify-between gap-3">
          <div className="flex flex-col gap-0.5">
            <label className="text-xs text-[#ece7dc]">{field.label}</label>
            {field.description && (
              <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
            )}
          </div>
          <Switch
            checked={(value as boolean | undefined) ?? (field.defaultValue as boolean) ?? false}
            onCheckedChange={(checked) => onChange(!!checked)}
            className="data-checked:bg-[#d4a84b]"
          />
        </div>
      );

    case "string_list":
      return (
        <div className="flex flex-col gap-1.5">
          <label className="text-xs text-[#ece7dc]">{field.label}</label>
          {field.description && (
            <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
          )}
          <TagList
            items={(value as string[] | undefined) ?? []}
            onChange={(items) => onChange(items)}
            placeholder={`Add ${field.label.toLowerCase()}...`}
          />
        </div>
      );

    case "pattern_list":
      return (
        <div className="flex flex-col gap-1.5">
          <label className="text-xs text-[#ece7dc]">{field.label}</label>
          {field.description && (
            <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
          )}
          <PatternList
            items={(value as string[] | undefined) ?? []}
            onChange={(items) => onChange(items)}
            placeholder={`Add ${field.label.toLowerCase()}...`}
          />
        </div>
      );

    case "number_slider":
      return (
        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <label className="text-xs text-[#ece7dc]">{field.label}</label>
            <span className="text-xs font-mono text-[#d4a84b]">
              {(value as number | undefined) ?? (field.defaultValue as number) ?? field.min ?? 0}
            </span>
          </div>
          {field.description && (
            <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
          )}
          <Slider
            value={[(value as number | undefined) ?? (field.defaultValue as number) ?? field.min ?? 0]}
            min={field.min ?? 0}
            max={field.max ?? 100}
            step={field.step ?? 1}
            onValueChange={(val) => {
              const v = Array.isArray(val) ? val[0] : val;
              onChange(v);
            }}
            className="[&_[data-slot=slider-range]]:bg-[#d4a84b] [&_[data-slot=slider-thumb]]:border-[#d4a84b]"
          />
          <div className="flex justify-between text-[10px] text-[#6f7f9a] font-mono">
            <span>{field.min ?? 0}</span>
            <span>{field.max ?? 100}</span>
          </div>
        </div>
      );

    case "number_input":
      return (
        <div className="flex flex-col gap-1.5">
          <label className="text-xs text-[#ece7dc]">{field.label}</label>
          {field.description && (
            <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
          )}
          <input
            type="number"
            value={(value as number | undefined) ?? (field.defaultValue as number) ?? ""}
            min={field.min}
            max={field.max}
            step={field.step}
            aria-label="Threshold value"
            onChange={(e) => {
              const num = e.target.value === "" ? undefined : Number(e.target.value);
              onChange(num);
            }}
            className="h-8 w-full rounded-md border border-[#2d3240] bg-[#131721] px-2.5 py-1 text-xs font-mono text-[#ece7dc] outline-none focus:border-[#d4a84b]/50 transition-colors"
          />
        </div>
      );

    case "select":
      return (
        <div className="flex flex-col gap-1.5">
          <label className="text-xs text-[#ece7dc]">{field.label}</label>
          {field.description && (
            <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
          )}
          <Select
            value={(value as string | undefined) ?? (field.defaultValue as string) ?? ""}
            onValueChange={(val) => onChange(val as string)}
          >
            <SelectTrigger className="w-full bg-[#131721] border-[#2d3240] text-[#ece7dc] text-xs font-mono">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-[#131721] border-[#2d3240]">
              {(field.options ?? []).map((opt) => (
                <SelectItem
                  key={opt.value}
                  value={opt.value}
                  className="text-xs font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                >
                  {opt.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      );

    case "secret_pattern_list":
      return (
        <div className="flex flex-col gap-1.5">
          <label className="text-xs text-[#ece7dc]">{field.label}</label>
          {field.description && (
            <span className="text-[10px] text-[#6f7f9a]">{field.description}</span>
          )}
          <SecretPatternListEditor
            patterns={(value as SecretPattern[] | undefined) ?? []}
            onChange={(patterns) => onChange(patterns)}
          />
        </div>
      );

    default:
      return null;
  }
}
