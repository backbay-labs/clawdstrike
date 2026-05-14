/**
 * Coverage Gap Card — displays a single CoverageGapCandidate.
 *
 * Shows severity badge, confidence percentage, technique hints as
 * ATT&CK tags, data source hints, rationale, suggested formats, and
 * action buttons for drafting a detection or dismissing.
 */

import { cn } from "@/lib/utils";
import {
  FILE_TYPE_REGISTRY,
  isRegisteredFileType,
} from "@/lib/workbench/file-type-registry";
import type { CoverageGapCandidate } from "@/lib/workbench/detection-workflow/shared-types";
import {
  IconShieldPlus,
  IconX,
  IconAlertTriangle,
} from "@tabler/icons-react";


// ---- Severity Colors ----

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string; label: string }> = {
  high: { bg: "#c45c5c15", text: "#c45c5c", border: "#c45c5c33", label: "HIGH" },
  medium: { bg: "#d4a84b15", text: "#d4a84b", border: "#d4a84b33", label: "MED" },
  low: { bg: "#7c9aef15", text: "#7c9aef", border: "#7c9aef33", label: "LOW" },
};


// ---- Component ----

interface CoverageGapCardProps {
  gap: CoverageGapCandidate;
  onDraft?: (gap: CoverageGapCandidate) => void;
  onDismiss?: (gapId: string) => void;
  compact?: boolean;
}

export function CoverageGapCard({
  gap,
  onDraft,
  onDismiss,
  compact = false,
}: CoverageGapCardProps) {
  const sevStyle = SEVERITY_COLORS[gap.severity] ?? SEVERITY_COLORS.low;

  return (
    <div
      data-testid="coverage-gap-card"
      className={cn(
        "rounded-lg border bg-[#0b0d13] transition-all duration-150",
        "hover:border-[#2d3240]/80",
        compact ? "px-3 py-2.5" : "px-4 py-3",
      )}
      style={{ borderColor: `${sevStyle.text}25` }}
    >
      {/* Top row: severity + confidence + dismiss */}
      <div className="flex items-center gap-2 mb-2">
        {/* Severity badge */}
        <span
          data-testid="severity-badge"
          className="text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border"
          style={{
            color: sevStyle.text,
            backgroundColor: sevStyle.bg,
            borderColor: sevStyle.border,
          }}
        >
          {sevStyle.label}
        </span>

        {/* Confidence */}
        <span className="text-[9px] font-mono text-[#6f7f9a]/60">
          {Math.round(gap.confidence * 100)}% confidence
        </span>

        {/* Alert icon for high severity */}
        {gap.severity === "high" && (
          <IconAlertTriangle size={11} stroke={2} className="text-[#c45c5c]/60" />
        )}

        {/* Spacer + dismiss */}
        <div className="flex-1" />
        {onDismiss && (
          <button
            data-testid="dismiss-button"
            onClick={() => onDismiss(gap.id)}
            className="text-[#6f7f9a]/30 hover:text-[#6f7f9a] transition-colors p-0.5 rounded"
            title="Dismiss gap"
          >
            <IconX size={12} stroke={1.5} />
          </button>
        )}
      </div>

      {/* Technique hints */}
      {gap.techniqueHints.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {gap.techniqueHints.map((tech) => (
            <span
              key={tech}
              data-testid="technique-tag"
              className="text-[8px] font-mono px-1.5 py-0.5 rounded border border-[#d4a84b]/20 bg-[#d4a84b]/5 text-[#d4a84b]/80"
            >
              {tech}
            </span>
          ))}
        </div>
      )}

      {/* Data source hints */}
      {gap.dataSourceHints.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {gap.dataSourceHints.map((ds) => (
            <span
              key={ds}
              className="text-[8px] font-mono px-1.5 py-0.5 rounded border border-[#6f7f9a]/15 bg-[#6f7f9a]/5 text-[#6f7f9a]/60"
            >
              {ds}
            </span>
          ))}
        </div>
      )}

      {/* Rationale */}
      {!compact && (
        <p className="text-[10px] text-[#6f7f9a]/60 leading-relaxed mb-2">
          {gap.rationale}
        </p>
      )}

      {/* Suggested formats */}
      {gap.suggestedFormats.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-2">
          {gap.suggestedFormats
            .filter(isRegisteredFileType)
            .map((format) => {
            const descriptor = FILE_TYPE_REGISTRY[format];
            return (
              <span
                key={format}
                className="text-[7px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded"
                style={{
                  color: descriptor.iconColor,
                  backgroundColor: `${descriptor.iconColor}10`,
                }}
              >
                {descriptor.shortLabel}
              </span>
            );
            })}
        </div>
      )}

      {/* Draft button */}
      {onDraft && (
        <button
          data-testid="draft-button"
          onClick={() => onDraft(gap)}
          className="flex items-center gap-1.5 rounded-md border border-[#7c9aef]/25 bg-[#7c9aef]/8 px-2.5 py-1.5 text-[10px] font-medium text-[#7c9aef] hover:bg-[#7c9aef]/15 transition-colors w-full justify-center mt-1"
        >
          <IconShieldPlus size={12} stroke={1.5} />
          Draft Detection
        </button>
      )}
    </div>
  );
}
