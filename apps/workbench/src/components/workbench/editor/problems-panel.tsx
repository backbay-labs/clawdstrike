import { useState, useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { FileType } from "@/lib/workbench/file-type-registry";
import { FILE_TYPE_REGISTRY } from "@/lib/workbench/file-type-registry";
import {
  IconAlertCircle,
  IconAlertTriangle,
  IconInfoCircle,
  IconCircleCheck,
  IconFilter,
} from "@tabler/icons-react";


// ---- Types ----

export interface ProblemEntry {
  severity: "error" | "warning" | "info";
  message: string;
  file: string;
  fileType: FileType;
  line?: number;
  column?: number;
}

interface ProblemsPanelProps {
  diagnostics: ProblemEntry[];
  className?: string;
}

type SeverityFilter = "all" | "error" | "warning" | "info";

// ---- Constants ----

const SEVERITY_ACCENT: Record<ProblemEntry["severity"], string> = {
  error: "#c45c5c",
  warning: "#d4a84b",
  info: "#6b8ec9",
};

const SEVERITY_ICONS: Record<ProblemEntry["severity"], typeof IconAlertCircle> = {
  error: IconAlertCircle,
  warning: IconAlertTriangle,
  info: IconInfoCircle,
};

const FILTER_OPTIONS: { value: SeverityFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "error", label: "Errors" },
  { value: "warning", label: "Warnings" },
  { value: "info", label: "Info" },
];


// ---- Component ----

export function ProblemsPanel({ diagnostics, className }: ProblemsPanelProps) {
  const [filter, setFilter] = useState<SeverityFilter>("all");

  const counts = useMemo(() => {
    const c = { error: 0, warning: 0, info: 0 };
    for (const d of diagnostics) {
      c[d.severity]++;
    }
    return c;
  }, [diagnostics]);

  const filtered = useMemo(() => {
    if (filter === "all") return diagnostics;
    return diagnostics.filter((d) => d.severity === filter);
  }, [diagnostics, filter]);

  return (
    <div className={cn("flex flex-col bg-[#05060a] border-t border-[#2d3240]", className)}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <div className="flex items-center gap-1.5">
          <IconFilter size={12} stroke={1.5} className="text-[#6f7f9a]" />
          <span className="text-[10px] font-syne font-bold uppercase tracking-wider text-[#ece7dc]">
            Problems
          </span>
        </div>

        {/* Filter toggles */}
        <div className="flex items-center gap-1 ml-2">
          {FILTER_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => setFilter(opt.value)}
              className={cn(
                "px-2 py-0.5 text-[9px] font-mono rounded transition-all duration-150",
                filter === opt.value
                  ? "bg-[#2d3240] text-[#ece7dc]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#2d3240]/50",
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Severity count badges */}
        <div className="flex items-center gap-2 ml-auto">
          {counts.error > 0 && (
            <span className="flex items-center gap-1 text-[9px] font-mono text-[#c45c5c]">
              <IconAlertCircle size={10} stroke={1.5} />
              {counts.error}
            </span>
          )}
          {counts.warning > 0 && (
            <span className="flex items-center gap-1 text-[9px] font-mono text-[#d4a84b]">
              <IconAlertTriangle size={10} stroke={1.5} />
              {counts.warning}
            </span>
          )}
          {counts.info > 0 && (
            <span className="flex items-center gap-1 text-[9px] font-mono text-[#6f7f9a]">
              <IconInfoCircle size={10} stroke={1.5} />
              {counts.info}
            </span>
          )}
          {counts.error === 0 && counts.warning === 0 && counts.info === 0 && (
            <span className="text-[9px] font-mono text-[#6f7f9a]/50">
              No issues
            </span>
          )}
        </div>
      </div>

      {/* Body */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 gap-2">
          <IconCircleCheck size={20} stroke={1.5} className="text-[#3dbf84]/50" />
          <span className="text-[11px] font-mono text-[#6f7f9a]/60">
            All clear — no problems found
          </span>
        </div>
      ) : (
        <ScrollArea className="flex-1 min-h-0">
          <div className="divide-y divide-[#2d3240]/30">
            {filtered.map((entry, idx) => (
              <ProblemRow key={`${entry.file}-${entry.line ?? 0}-${idx}`} entry={entry} />
            ))}
          </div>
        </ScrollArea>
      )}
    </div>
  );
}


// ---- Row ----

function ProblemRow({ entry }: { entry: ProblemEntry }) {
  const accentColor = SEVERITY_ACCENT[entry.severity];
  const Icon = SEVERITY_ICONS[entry.severity];
  const descriptor = FILE_TYPE_REGISTRY[entry.fileType];

  return (
    <div
      className="flex items-center gap-2.5 px-4 py-1.5 hover:bg-[#131721]/40 transition-colors group"
      style={{ borderLeft: `4px solid ${accentColor}` }}
    >
      {/* Severity icon */}
      <Icon
        size={13}
        stroke={1.5}
        className="shrink-0"
        style={{ color: accentColor }}
      />

      {/* File name + format dot */}
      <div className="flex items-center gap-1.5 shrink-0 min-w-[140px]">
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ backgroundColor: descriptor.iconColor }}
          aria-label={descriptor.label}
        />
        <span className="text-[10px] font-mono text-[#ece7dc] truncate max-w-[120px]" title={entry.file}>
          {entry.file}
        </span>
        {entry.line != null && (
          <span className="text-[9px] font-mono text-[#6f7f9a]">
            :{entry.line}
            {entry.column != null && `:${entry.column}`}
          </span>
        )}
      </div>

      {/* Message */}
      <span className="text-[10px] font-mono text-[#6f7f9a] group-hover:text-[#ece7dc]/80 transition-colors truncate flex-1">
        {entry.message}
      </span>
    </div>
  );
}
