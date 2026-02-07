/**
 * EventFilters - Filter bar for event stream
 */
import { GlowButton } from "@backbay/glia/primitives";
import { GlowInput } from "@backbay/glia/primitives";
import type { EventFilter } from "../EventStreamView";
import type { ActionType, Decision, Severity } from "@/types/events";

interface EventFiltersProps {
  filter: EventFilter;
  onFilterChange: (filter: EventFilter) => void;
  guards: string[];
}

export function EventFilters({ filter, onFilterChange, guards }: EventFiltersProps) {
  const actionTypes: { value: ActionType; label: string }[] = [
    { value: "file_access", label: "File Read" },
    { value: "file_write", label: "File Write" },
    { value: "egress", label: "Network" },
    { value: "shell", label: "Shell" },
    { value: "mcp_tool", label: "MCP Tool" },
    { value: "patch", label: "Patch" },
  ];

  const decisions: { value: Decision; label: string }[] = [
    { value: "allowed", label: "Allowed" },
    { value: "blocked", label: "Blocked" },
  ];

  const severities: { value: Severity; label: string }[] = [
    { value: "info", label: "Info" },
    { value: "warning", label: "Warning" },
    { value: "error", label: "Error" },
    { value: "critical", label: "Critical" },
  ];

  return (
    <div className="flex items-center gap-3 px-4 py-2 border-b border-sdr-border bg-sdr-bg-secondary/50">
      {/* Search */}
      <div className="relative flex-1 max-w-xs">
        <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sdr-text-muted z-10" />
        <GlowInput
          type="text"
          value={filter.search ?? ""}
          onChange={(e) => onFilterChange({ ...filter, search: e.target.value || undefined })}
          placeholder="Search targets, agents..."
          className="w-full pl-9"
        />
      </div>

      {/* Action type */}
      <FilterSelect
        value={filter.actionType}
        onChange={(v) => onFilterChange({ ...filter, actionType: v as ActionType | undefined })}
        options={actionTypes}
        placeholder="Action type"
      />

      {/* Decision */}
      <FilterSelect
        value={filter.decision}
        onChange={(v) => onFilterChange({ ...filter, decision: v as Decision | undefined })}
        options={decisions}
        placeholder="Decision"
      />

      {/* Severity */}
      <FilterSelect
        value={filter.severity}
        onChange={(v) => onFilterChange({ ...filter, severity: v as Severity | undefined })}
        options={severities}
        placeholder="Severity"
      />

      {/* Guard */}
      {guards.length > 0 && (
        <FilterSelect
          value={filter.guard}
          onChange={(v) => onFilterChange({ ...filter, guard: v })}
          options={guards.map((g) => ({ value: g, label: g }))}
          placeholder="Guard"
        />
      )}

      {/* Clear filters */}
      {(filter.actionType || filter.decision || filter.severity || filter.guard || filter.search) && (
        <GlowButton
          onClick={() => onFilterChange({})}
          variant="secondary"
        >
          Clear
        </GlowButton>
      )}
    </div>
  );
}

interface FilterSelectProps {
  value?: string;
  onChange: (value: string | undefined) => void;
  options: { value: string; label: string }[];
  placeholder: string;
}

function FilterSelect({ value, onChange, options, placeholder }: FilterSelectProps) {
  return (
    <select
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value || undefined)}
      className="px-2 py-1.5 text-sm bg-sdr-bg-tertiary text-sdr-text-primary rounded-md border border-sdr-border focus:outline-none focus:border-sdr-accent-blue appearance-none cursor-pointer"
    >
      <option value="">{placeholder}</option>
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <circle cx="11" cy="11" r="8" />
      <path d="M21 21l-4.35-4.35" />
    </svg>
  );
}
