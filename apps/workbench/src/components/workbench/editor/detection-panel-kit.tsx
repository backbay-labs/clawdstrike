"use client";

/**
 * DetectionVisualPanelKit -- shared component library for detection visual panels.
 *
 * Re-exports shared form primitives from `shared-form-fields.tsx` and provides
 * detection-specific components: SeverityBadge, AttackTagBadge, and
 * FieldMappingTable. Plugin adapter panels import from this single module to
 * get a cohesive set of UI primitives.
 */

// ---- Re-exports from shared-form-fields ----

export { Section, FieldLabel, TextInput, TextArea, SelectInput } from "./shared-form-fields";
export type { SelectOption } from "./shared-form-fields";

// ---- Severity Badge ----

const SEVERITY_COLORS: Record<string, string> = {
  informational: "#6b7280",
  low: "#3b82f6",
  medium: "#f59e0b",
  high: "#f97316",
  critical: "#ef4444",
};

const DEFAULT_SEVERITY_COLOR = "#9ca3af";

interface SeverityBadgeProps {
  /** Severity level: "informational" | "low" | "medium" | "high" | "critical" or custom. */
  severity: string;
  className?: string;
}

/**
 * Small colored badge displaying a severity level.
 *
 * Maps known severity levels to semantic colors. Unknown/custom severities
 * render in light gray.
 */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const color = SEVERITY_COLORS[severity.toLowerCase()] ?? DEFAULT_SEVERITY_COLOR;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${className ?? ""}`}
      style={{
        color,
        backgroundColor: `${color}26`,
      }}
    >
      {severity}
    </span>
  );
}

// ---- ATT&CK Tag Badge ----

const ATTACK_ACCENT = "#a78bfa";

/**
 * Known MITRE ATT&CK tactic names for tactic-vs-technique classification.
 */
const ATTACK_TACTICS = new Set([
  "reconnaissance",
  "resource_development",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact",
]);

interface AttackTagBadgeProps {
  /** MITRE ATT&CK tag, e.g. "attack.execution" or "attack.t1059.001". */
  tag: string;
  className?: string;
}

/**
 * Badge for MITRE ATT&CK tags.
 *
 * Technique IDs (e.g. "attack.t1059.001") render as monospace pills with a
 * subtle border. Tactic names (e.g. "attack.execution") render as pills with
 * a tactic-colored background. Uses purple (#a78bfa) as the accent color.
 */
export function AttackTagBadge({ tag, className }: AttackTagBadgeProps) {
  const lower = tag.toLowerCase();
  const isTechnique = lower.startsWith("attack.t");
  const tacticName = lower.startsWith("attack.") ? lower.slice("attack.".length) : null;
  const isTactic = tacticName !== null && ATTACK_TACTICS.has(tacticName);

  // Display text: strip the "attack." prefix for readability.
  const display = tag.startsWith("attack.") ? tag.slice("attack.".length) : tag;

  if (isTechnique) {
    return (
      <span
        className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono border ${className ?? ""}`}
        style={{
          color: ATTACK_ACCENT,
          borderColor: `${ATTACK_ACCENT}40`,
          backgroundColor: `${ATTACK_ACCENT}10`,
        }}
      >
        {display.toUpperCase()}
      </span>
    );
  }

  if (isTactic) {
    return (
      <span
        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${className ?? ""}`}
        style={{
          color: "#fff",
          backgroundColor: `${ATTACK_ACCENT}60`,
        }}
      >
        {display.replace(/_/g, " ")}
      </span>
    );
  }

  // Fallback for unrecognized attack.* tags.
  return (
    <span
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] ${className ?? ""}`}
      style={{
        color: ATTACK_ACCENT,
        backgroundColor: `${ATTACK_ACCENT}15`,
      }}
    >
      {tag}
    </span>
  );
}

// ---- Field Mapping Table ----

/** Confidence level for a single field mapping row. */
export type FieldMappingConfidence = "exact" | "approximate" | "unmapped";

interface FieldMappingTableProps {
  /** Field mapping entries to display. */
  entries: Array<{
    sigmaField: string;
    targetField: string;
    confidence: FieldMappingConfidence;
  }>;
  /** Label for the target column header (e.g. "Splunk CIM", "Sentinel"). */
  targetLabel: string;
  /** Accent color for the table header border. */
  accentColor?: string;
  className?: string;
}

const CONFIDENCE_DOTS: Record<FieldMappingConfidence, { color: string; title: string }> = {
  exact: { color: "#22c55e", title: "Exact mapping" },
  approximate: { color: "#eab308", title: "Approximate mapping" },
  unmapped: { color: "#ef4444", title: "Unmapped field" },
};

/**
 * Compact two-column table displaying Sigma-to-target field mappings with
 * confidence indicators.
 *
 * - exact: green dot
 * - approximate: yellow dot
 * - unmapped: red dot with strikethrough on target field text
 */
export function FieldMappingTable({
  entries,
  targetLabel,
  accentColor = ATTACK_ACCENT,
  className,
}: FieldMappingTableProps) {
  if (entries.length === 0) return null;

  return (
    <table className={`text-xs border-collapse w-full ${className ?? ""}`}>
      <thead>
        <tr style={{ borderBottom: `2px solid ${accentColor}` }}>
          <th className="text-left py-1 px-2 text-[#6f7f9a] text-[10px] font-semibold uppercase tracking-wider">
            Sigma Field
          </th>
          <th className="text-left py-1 px-2 text-[#6f7f9a] text-[10px] font-semibold uppercase tracking-wider">
            {targetLabel}
          </th>
        </tr>
      </thead>
      <tbody>
        {entries.map((entry, idx) => {
          const dot = CONFIDENCE_DOTS[entry.confidence];
          const isOdd = idx % 2 === 1;

          return (
            <tr
              key={entry.sigmaField}
              className={isOdd ? "bg-white/5" : "bg-transparent"}
            >
              <td className="py-1 px-2 font-mono text-[#ece7dc]">
                {entry.sigmaField}
              </td>
              <td className="py-1 px-2 font-mono text-[#ece7dc] flex items-center gap-1.5">
                <span
                  className="inline-block w-1.5 h-1.5 rounded-full flex-shrink-0"
                  style={{ backgroundColor: dot.color }}
                  title={dot.title}
                />
                <span className={entry.confidence === "unmapped" ? "line-through opacity-50" : ""}>
                  {entry.targetField || "\u2014"}
                </span>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
