import { useMemo, useCallback, useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import YAML from "yaml";
import {
  parseSigmaYaml,
  type SigmaRule,
  type SigmaStatus,
  type SigmaLevel,
  type SigmaDetection,
} from "@/lib/workbench/sigma-types";
import {
  IconFileAnalytics,
  IconServer,
  IconSearch,
  IconTag,
  IconShieldQuestion,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Section,
  FieldLabel,
  TextInput,
  TextArea,
  SelectInput,
} from "./shared-form-fields";


// ---- Constants ----

const STATUS_OPTIONS: SigmaStatus[] = [
  "experimental",
  "test",
  "stable",
  "deprecated",
  "unsupported",
];

const LEVEL_OPTIONS: SigmaLevel[] = [
  "informational",
  "low",
  "medium",
  "high",
  "critical",
];

const CATEGORY_OPTIONS = [
  "process_creation",
  "file_event",
  "network_connection",
  "dns_query",
  "registry_set",
  "registry_add",
  "registry_delete",
  "registry_event",
  "image_load",
  "pipe_created",
  "driver_load",
  "file_access",
  "file_change",
  "file_delete",
  "file_rename",
  "create_remote_thread",
  "process_access",
  "process_termination",
  "sysmon_status",
  "wmi_event",
  "clipboard_capture",
  "create_stream_hash",
];

const PRODUCT_OPTIONS = [
  "windows",
  "linux",
  "macos",
  "azure",
  "aws",
  "gcp",
  "m365",
  "okta",
  "github",
  "zeek",
];

const ACCENT = "#7c9aef";


// ---- Props ----

interface SigmaVisualPanelProps {
  yaml: string;
  onYamlChange: (yaml: string) => void;
  readOnly?: boolean;
}




// ---- Detection Logic Circuit Board ----

// Condition tokenizer — splits condition into typed tokens for syntax coloring

interface ConditionToken {
  type: "keyword" | "reference" | "paren" | "other";
  value: string;
}

const CONDITION_KEYWORDS = new Set([
  "and", "or", "not", "1", "of", "all", "them", "any",
]);

function tokenizeCondition(condition: string): ConditionToken[] {
  const tokens: ConditionToken[] = [];
  // Split on whitespace boundaries while preserving parens as separate tokens
  const raw = condition.replace(/([()])/g, " $1 ").split(/\s+/).filter(Boolean);

  for (const word of raw) {
    if (word === "(" || word === ")") {
      tokens.push({ type: "paren", value: word });
    } else if (CONDITION_KEYWORDS.has(word.toLowerCase())) {
      tokens.push({ type: "keyword", value: word });
    } else {
      tokens.push({ type: "reference", value: word });
    }
  }
  return tokens;
}

// Condition parser — extracts operator groups for the logic tree

interface OperatorGroup {
  operator: "and" | "or" | "not";
  operatorLabel: string;
  selections: { name: string; value: Record<string, unknown> }[];
}

function parseConditionGroups(
  condition: string,
  selections: Record<string, unknown>,
): OperatorGroup[] {
  const groups: OperatorGroup[] = [];
  const stripped = condition.replace(/[()]/g, " ").trim();

  // Detect whether the top-level joiner is AND or OR
  // Simple heuristic: split on ` or ` first; if >1 segment, top-level is OR
  const orSegments = stripped.split(/\s+or\s+/i);
  const isTopOr = orSegments.length > 1;

  const segments = isTopOr
    ? orSegments
    : stripped.split(/\s+and\s+/i);
  const topOp = isTopOr ? "or" : "and";

  // Collect positive and negated terms
  const positive: { name: string; value: Record<string, unknown> }[] = [];
  const negated: { name: string; value: Record<string, unknown> }[] = [];

  for (const seg of segments) {
    const trimmed = seg.trim();
    if (!trimmed) continue;

    // Check for "not <selection>"
    const notMatch = trimmed.match(/^not\s+(.+)$/i);
    const isNegated = !!notMatch;
    const expr = isNegated ? notMatch![1].trim() : trimmed;

    // Check for special expressions: "1 of selection*", "all of them", etc.
    const isSpecial = /^\d+\s+of\s+/i.test(expr) || /^all\s+of\s+/i.test(expr) || /^any\s+of\s+/i.test(expr);

    if (isSpecial) {
      const entry = { name: expr, value: {} as Record<string, unknown> };
      if (isNegated) {
        negated.push(entry);
      } else {
        positive.push(entry);
      }
    } else {
      // expr should be a selection name
      const selValue = selections[expr];
      const entry = {
        name: expr,
        value: (selValue != null && typeof selValue === "object" && !Array.isArray(selValue)
          ? selValue
          : {}) as Record<string, unknown>,
      };
      if (isNegated) {
        negated.push(entry);
      } else {
        positive.push(entry);
      }
    }
  }

  if (positive.length > 0) {
    groups.push({
      operator: topOp,
      operatorLabel: topOp.toUpperCase(),
      selections: positive,
    });
  }

  if (negated.length > 0) {
    groups.push({
      operator: "not",
      operatorLabel: `${topOp.toUpperCase()} NOT`,
      selections: negated,
    });
  }

  return groups;
}

// Format a selection value for compact display
function formatFieldValues(value: unknown): string {
  if (value == null) return "null";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    if (value.length <= 3) {
      return value.map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ");
    }
    const shown = value.slice(0, 3).map((v) => (typeof v === "object" ? JSON.stringify(v) : String(v))).join(", ");
    return `${shown} +${value.length - 3} more`;
  }
  return JSON.stringify(value);
}

// ConditionBar — syntax-colored condition display

function ConditionBar({
  condition,
  hoveredSelection,
  onHoverSelection,
}: {
  condition: string;
  hoveredSelection: string | null;
  onHoverSelection: (name: string | null) => void;
}) {
  const tokens = useMemo(() => tokenizeCondition(condition), [condition]);

  if (!condition) {
    return (
      <div
        className="bg-[#05060a] border border-[#2d3240] border-l-2 rounded px-4 py-3 font-mono text-[12px] text-[#6f7f9a]/50 italic"
        style={{ borderLeftColor: ACCENT }}
      >
        (empty)
      </div>
    );
  }

  return (
    <div
      className="bg-[#05060a] border border-[#2d3240] border-l-2 rounded px-4 py-3 font-mono text-[12px] leading-relaxed flex flex-wrap gap-x-1.5 gap-y-0.5"
      style={{ borderLeftColor: ACCENT }}
    >
      {tokens.map((token, i) => {
        let color = "#ece7dc";
        let cursor = "default";

        if (token.type === "keyword") {
          const lower = token.value.toLowerCase();
          if (lower === "not") {
            color = "#c45c5c";
          } else {
            color = "#d4a84b";
          }
        } else if (token.type === "reference") {
          color = ACCENT;
          cursor = "pointer";
        } else if (token.type === "paren") {
          color = "#6f7f9a";
        }

        return (
          <span
            key={i}
            style={{
              color,
              cursor,
              borderBottom: token.type === "reference" && hoveredSelection === token.value
                ? `1px solid ${ACCENT}60`
                : "1px solid transparent",
              transition: "border-color 150ms ease",
            }}
            onMouseEnter={token.type === "reference" ? () => onHoverSelection(token.value) : undefined}
            onMouseLeave={token.type === "reference" ? () => onHoverSelection(null) : undefined}
          >
            {token.value}
          </span>
        );
      })}
    </div>
  );
}

// SelectionNode — a single selection in the logic tree

function SelectionNode({
  name,
  value,
  isNegated,
  isHighlighted,
  onMouseEnter,
  onMouseLeave,
}: {
  name: string;
  value: Record<string, unknown>;
  isNegated: boolean;
  isHighlighted: boolean;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}) {
  const borderColor = isNegated ? "#c45c5c" : ACCENT;
  const entries = Object.entries(value);
  const isEmpty = entries.length === 0;

  return (
    <div
      className="bg-[#0b0d13]/60 border rounded-md pl-3 pr-3 py-2 transition-shadow"
      style={{
        borderColor: `${borderColor}30`,
        borderLeftWidth: 3,
        borderLeftColor: borderColor,
        opacity: isNegated ? 0.7 : 1,
        boxShadow: isHighlighted ? `0 0 0 1px ${ACCENT}40` : "none",
        transition: "box-shadow 150ms ease",
      }}
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
    >
      <div className="flex items-center gap-2">
        <span
          className="text-[11px] font-mono font-bold"
          style={{ color: isNegated ? "#c45c5c" : ACCENT }}
        >
          {name}
        </span>
        {isNegated && (
          <span className="text-[8px] font-mono uppercase tracking-wider text-[#c45c5c]/60">
            excluded
          </span>
        )}
      </div>
      {!isEmpty && (
        <div className="flex flex-col gap-0.5 mt-1.5">
          {entries.map(([field, val]) => (
            <div key={field} className="flex items-baseline gap-1.5">
              <span className="text-[10px] font-mono text-[#6f7f9a] shrink-0">{field}:</span>
              <span className="text-[10px] font-mono text-[#ece7dc]/60 break-all">
                {formatFieldValues(val)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// LogicTree — renders operator groups with junction markers and connector lines

function LogicTree({
  groups,
  hoveredSelection,
  onHoverSelection,
}: {
  groups: OperatorGroup[];
  hoveredSelection: string | null;
  onHoverSelection: (name: string | null) => void;
}) {
  if (groups.length === 0) {
    return (
      <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
        No selection groups parsed.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 mt-2">
      {groups.map((group, gi) => {
        const isNot = group.operator === "not";
        const isOr = group.operator === "or";
        const junctionColor = isNot ? "#c45c5c" : "#d4a84b";
        const junctionLabel = isNot ? "!" : isOr ? "|" : "&";

        return (
          <div key={gi} className="flex flex-col">
            {/* Operator junction header */}
            <div className="flex items-center gap-2 mb-2">
              {/* Junction circle */}
              <div
                className="w-[22px] h-[22px] rounded-full flex items-center justify-center text-[8px] font-mono font-black shrink-0"
                style={{
                  color: junctionColor,
                  backgroundColor: `${junctionColor}1a`,
                  border: `1px solid ${junctionColor}33`,
                }}
              >
                {junctionLabel}
              </div>
              {/* Horizontal rule */}
              <div className="flex items-center gap-2 flex-1">
                <span
                  className="text-[9px] font-mono font-bold tracking-wider"
                  style={{ color: junctionColor }}
                >
                  {group.operatorLabel}
                </span>
                <div className="flex-1 h-px" style={{ backgroundColor: "#2d3240" }} />
              </div>
            </div>

            {/* Selection nodes with vertical connector */}
            <div className="flex">
              {/* Vertical connector line */}
              <div className="flex flex-col items-center" style={{ width: 22 }}>
                <div
                  className="flex-1"
                  style={{ width: 1, backgroundColor: "#2d3240" }}
                />
              </div>

              {/* Nodes */}
              <div className="flex flex-col gap-2 flex-1 pl-3">
                {group.selections.map((sel, si) => {
                  const isLast = si === group.selections.length - 1;
                  return (
                    <div key={si} className="relative">
                      {/* Horizontal branch connector */}
                      <div
                        className="absolute"
                        style={{
                          left: -12,
                          top: 14,
                          width: 12,
                          height: 1,
                          backgroundColor: "#2d3240",
                        }}
                      />
                      {/* Branch node indicator */}
                      <div
                        className="absolute"
                        style={{
                          left: -15,
                          top: 11,
                          width: 5,
                          height: 5,
                          borderRadius: "50%",
                          backgroundColor: isLast ? "#2d3240" : "transparent",
                          border: `1px solid ${isNot ? "#c45c5c40" : "#2d3240"}`,
                        }}
                      />
                      <SelectionNode
                        name={sel.name}
                        value={sel.value}
                        isNegated={isNot}
                        isHighlighted={hoveredSelection === sel.name}
                        onMouseEnter={() => onHoverSelection(sel.name)}
                        onMouseLeave={() => onHoverSelection(null)}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// DetectionSection — circuit board layout combining ConditionBar and LogicTree

function DetectionSection({ detection }: { detection: SigmaDetection }) {
  const [hoveredSelection, setHoveredSelection] = useState<string | null>(null);

  // Memoize the selections object separately so that the rest spread does not
  // create a new reference on every render.  We key on the stringified detection
  // to ensure the memo updates when any field (condition or selection maps) changes.
  const detectionKey = useMemo(() => JSON.stringify(detection), [detection]);

  const groups = useMemo(() => {
    const { condition, ...selections } = detection;
    return parseConditionGroups(condition || "", selections as Record<string, unknown>);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detectionKey]);

  return (
    <div className="flex flex-col gap-3">
      {/* Condition bar with syntax coloring */}
      <div className="flex flex-col gap-1">
        <FieldLabel label="Condition" />
        <ConditionBar
          condition={detection.condition || ""}
          hoveredSelection={hoveredSelection}
          onHoverSelection={setHoveredSelection}
        />
      </div>

      {/* Logic tree */}
      <LogicTree
        groups={groups}
        hoveredSelection={hoveredSelection}
        onHoverSelection={setHoveredSelection}
      />
    </div>
  );
}


// ---- Tag Badges ----

function TagBadge({ tag }: { tag: string }) {
  const isAttack = tag.startsWith("attack.");
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono",
        isAttack
          ? "border"
          : "bg-[#2d3240]/50 text-[#ece7dc]/70 border border-[#2d3240]",
      )}
      style={
        isAttack
          ? {
              color: ACCENT,
              backgroundColor: `${ACCENT}10`,
              borderColor: `${ACCENT}30`,
            }
          : undefined
      }
    >
      {tag}
    </span>
  );
}


// ---- Level badge color helper ----

function levelColor(level: SigmaLevel): string {
  switch (level) {
    case "critical":
      return "#c45c5c";
    case "high":
      return "#e0915c";
    case "medium":
      return "#d4a84b";
    case "low":
      return "#3dbf84";
    case "informational":
      return "#8b9dc3";
    default:
      return "#6f7f9a";
  }
}

function statusColor(status: SigmaStatus): string {
  switch (status) {
    case "stable":
      return "#3dbf84";
    case "test":
      return "#d4a84b";
    case "experimental":
      return "#7c9aef";
    case "deprecated":
      return "#e0915c";
    case "unsupported":
      return "#c45c5c";
    default:
      return "#6f7f9a";
  }
}


// ---- Main Panel ----

export function SigmaVisualPanel({ yaml: yamlText, onYamlChange, readOnly }: SigmaVisualPanelProps) {
  const { rule, errors } = useMemo(() => parseSigmaYaml(yamlText), [yamlText]);

  // Round-trip update: parse current YAML as a document, update a field, stringify back.
  const updateField = useCallback(
    (path: string[], value: unknown) => {
      try {
        const doc = YAML.parseDocument(yamlText);

        if (value === "" || value === undefined || value === null) {
          // Remove the field if value is empty
          if (path.length === 1) {
            doc.delete(path[0]);
          } else if (path.length === 2) {
            const parent = doc.get(path[0]) as YAML.YAMLMap | undefined;
            if (parent && parent instanceof YAML.YAMLMap) {
              parent.delete(path[1]);
            }
          }
        } else {
          doc.setIn(path, value);
        }

        onYamlChange(doc.toString());
      } catch {
        // If YAML doc manipulation fails, fall back to full rewrite
        // This can happen when the YAML is fundamentally broken
      }
    },
    [yamlText, onYamlChange],
  );

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col pb-6">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>SIG</span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">Sigma Detection Rule</span>
        </div>

        {/* Parse errors banner */}
        {errors.length > 0 && (
          <div className="mx-4 mt-3 p-2 bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
            <div className="flex flex-col gap-1">
              {errors.map((err, i) => (
                <span key={i} className="text-[10px] font-mono text-[#c45c5c]">
                  {err}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Status + Level summary bar */}
        {rule && (
          <div className="flex items-center gap-2 px-4 pt-3 pb-0">
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: statusColor(rule.status),
                borderColor: `${statusColor(rule.status)}30`,
                backgroundColor: `${statusColor(rule.status)}08`,
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: statusColor(rule.status) }}
              />
              {rule.status}
            </span>
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: levelColor(rule.level),
                borderColor: `${levelColor(rule.level)}30`,
                backgroundColor: `${levelColor(rule.level)}08`,
              }}
            >
              {rule.level}
            </span>
          </div>
        )}

        {/* Section 1: Rule Header */}
        <Section title="Rule Header" icon={IconFileAnalytics} accentColor={ACCENT}>
          <TextInput
            label="Title"
            value={rule?.title ?? ""}
            onChange={(v) => updateField(["title"], v)}
            required
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <TextInput
            label="ID"
            value={rule?.id ?? ""}
            onChange={() => {}}
            readOnly
            mono
            accentColor={ACCENT}
          />
          <div className="grid grid-cols-2 gap-3">
            <SelectInput
              label="Status"
              value={rule?.status ?? "experimental"}
              options={STATUS_OPTIONS}
              onChange={(v) => updateField(["status"], v)}
              readOnly={readOnly}
              required
              accentColor={ACCENT}
            />
            <SelectInput
              label="Level"
              value={rule?.level ?? "medium"}
              options={LEVEL_OPTIONS}
              onChange={(v) => updateField(["level"], v)}
              readOnly={readOnly}
              required
              accentColor={ACCENT}
            />
          </div>
          <TextArea
            label="Description"
            value={rule?.description ?? ""}
            onChange={(v) => updateField(["description"], v || undefined)}
            placeholder="Describe what this rule detects and why it matters."
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <div className="grid grid-cols-2 gap-3">
            <TextInput
              label="Author"
              value={rule?.author ?? ""}
              onChange={(v) => updateField(["author"], v || undefined)}
              placeholder="Your name or team"
              readOnly={readOnly}
              accentColor={ACCENT}
            />
            <TextInput
              label="Date"
              value={rule?.date ?? ""}
              onChange={(v) => updateField(["date"], v || undefined)}
              placeholder="YYYY/MM/DD"
              readOnly={readOnly}
              mono
              accentColor={ACCENT}
            />
          </div>
        </Section>

        {/* Section 2: Logsource */}
        <Section title="Log Source" icon={IconServer} accentColor={ACCENT}>
          <div className="grid grid-cols-2 gap-3">
            <SelectInput
              label="Category"
              value={rule?.logsource?.category ?? ""}
              options={CATEGORY_OPTIONS}
              onChange={(v) => updateField(["logsource", "category"], v || undefined)}
              readOnly={readOnly}
              placeholder="Select category..."
              accentColor={ACCENT}
            />
            <SelectInput
              label="Product"
              value={rule?.logsource?.product ?? ""}
              options={PRODUCT_OPTIONS}
              onChange={(v) => updateField(["logsource", "product"], v || undefined)}
              readOnly={readOnly}
              placeholder="Select product..."
              accentColor={ACCENT}
            />
          </div>
          <TextInput
            label="Service"
            value={rule?.logsource?.service ?? ""}
            onChange={(v) => updateField(["logsource", "service"], v || undefined)}
            placeholder="e.g. sysmon, security, powershell"
            readOnly={readOnly}
            accentColor={ACCENT}
          />
        </Section>

        {/* Section 3: Detection */}
        <Section title="Detection" icon={IconSearch} accentColor={ACCENT}>
          {rule?.detection ? (
            <DetectionSection detection={rule.detection} />
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
              No detection logic found. Add a detection block in the YAML editor.
            </div>
          )}
        </Section>

        {/* Section 4: Tags */}
        <Section title="Tags" icon={IconTag} defaultOpen={!!(rule?.tags && rule.tags.length > 0)} accentColor={ACCENT}>
          {rule?.tags && rule.tags.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {rule.tags.map((tag, i) => (
                <TagBadge key={i} tag={tag} />
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-1">
              No tags yet. Add ATT&CK tags like attack.t1059 to map this rule to techniques.
            </div>
          )}
        </Section>

        {/* Section 5: False Positives */}
        <Section
          title="False Positives"
          icon={IconShieldQuestion}
          defaultOpen={!!(rule?.falsepositives && rule.falsepositives.length > 0)}
          accentColor={ACCENT}
        >
          {rule?.falsepositives && rule.falsepositives.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {rule.falsepositives.map((fp, i) => (
                <div
                  key={i}
                  className="bg-[#0b0d13]/50 border border-[#2d3240] rounded px-3 py-2 text-[11px] font-mono text-[#ece7dc]/70 leading-relaxed"
                >
                  {fp}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-1">
              No false positives documented. Consider adding known benign triggers.
            </div>
          )}
        </Section>

      </div>
    </ScrollArea>
  );
}
