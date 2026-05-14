"use client";

import { useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  IconFileAnalytics,
  IconTimeline,
  IconFilter,
  IconAlignBoxLeftTop,
  IconPlus,
  IconTrash,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Section,
  FieldLabel,
  TextInput,
  TextArea,
  SelectInput,
  SeverityBadge,
  AttackTagBadge,
} from "./detection-panel-kit";
import type { DetectionVisualPanelProps } from "@/lib/workbench/detection-workflow/shared-types";
import { registerVisualPanel } from "@/lib/workbench/detection-workflow/visual-panels";


/** Default accent color for YARA-L panels (Google blue). */
const DEFAULT_ACCENT = "#4285f4";

const SEVERITY_OPTIONS = [
  "INFORMATIONAL",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

const OPERATOR_OPTIONS = [
  { value: "=", label: "=" },
  { value: "!=", label: "!=" },
  { value: ">", label: ">" },
  { value: "<", label: "<" },
  { value: ">=", label: ">=" },
  { value: "<=", label: "<=" },
];


interface YaralPredicate {
  fieldPath: string;
  operator: string;
  value: string;
  isRegex: boolean;
  nocase: boolean;
  lineNumber: number;
}

interface YaralEventVariable {
  name: string;
  predicates: YaralPredicate[];
}

interface ParsedYaralRule {
  ruleName: string;
  meta: Array<{ key: string; value: string }>;
  eventVariables: YaralEventVariable[];
  condition: string;
  matchSection: string | null;
  outcomeSection: string | null;
}


/**
 * Regex-based best-effort parser for YARA-L rule source text.
 * Extracts rule name, meta key-value pairs, event variables with their
 * predicates, condition expression, and optional match/outcome sections.
 */
function parseYaralSource(source: string): ParsedYaralRule | null {
  // Extract rule name
  const ruleNameMatch = source.match(/rule\s+(\w+)\s*\{/);
  if (!ruleNameMatch) return null;
  const ruleName = ruleNameMatch[1];

  const lines = source.split(/\r?\n/);

  let currentSection: "none" | "meta" | "events" | "condition" | "match" | "outcome" = "none";
  const metaLines: Array<{ text: string; lineNumber: number }> = [];
  const eventLines: Array<{ text: string; lineNumber: number }> = [];
  const conditionLines: string[] = [];
  const matchLines: string[] = [];
  const outcomeLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed === "" || trimmed === "}") continue;
    if (/^rule\s+\w+\s*\{/.test(trimmed)) continue;

    // Detect section headers
    if (trimmed === "meta:") { currentSection = "meta"; continue; }
    if (trimmed === "events:") { currentSection = "events"; continue; }
    if (trimmed === "condition:") { currentSection = "condition"; continue; }
    if (trimmed === "match:") { currentSection = "match"; continue; }
    if (trimmed === "outcome:") { currentSection = "outcome"; continue; }

    switch (currentSection) {
      case "meta": metaLines.push({ text: trimmed, lineNumber: i + 1 }); break;
      case "events": eventLines.push({ text: trimmed, lineNumber: i + 1 }); break;
      case "condition": conditionLines.push(trimmed); break;
      case "match": matchLines.push(trimmed); break;
      case "outcome": outcomeLines.push(trimmed); break;
    }
  }

  // Parse meta: key = "value" or key = value
  const meta: Array<{ key: string; value: string }> = [];
  for (const { text } of metaLines) {
    const metaMatch = text.match(/^(\w+)\s*=\s*"?([^"]*)"?$/);
    if (metaMatch) {
      meta.push({ key: metaMatch[1], value: metaMatch[2] });
    }
  }

  // Parse events: group predicates by variable name
  const variableMap = new Map<string, YaralPredicate[]>();

  for (const { text, lineNumber } of eventLines) {
    // Match: $var.field.path <operator> <value>
    const eventMatch = text.match(
      /^(\$\w+)\.(\S+)\s*(!=|>=|<=|>|<|=)\s*(.+)$/,
    );
    if (eventMatch) {
      const varName = eventMatch[1];
      const fieldPath = eventMatch[2];
      const operator = eventMatch[3];
      let valueStr = eventMatch[4].trim();

      let isRegex = false;
      let nocase = false;

      // Check for nocase modifier
      if (valueStr.endsWith(" nocase")) {
        nocase = true;
        valueStr = valueStr.slice(0, -7).trim();
      }

      // Check if regex: /pattern/
      if (valueStr.startsWith("/") && valueStr.endsWith("/")) {
        isRegex = true;
        valueStr = valueStr.slice(1, -1);
      } else if (valueStr.startsWith("/")) {
        const regexEnd = valueStr.lastIndexOf("/");
        if (regexEnd > 0) {
          isRegex = true;
          valueStr = valueStr.slice(1, regexEnd);
        }
      }

      // Strip quotes from string values
      if (valueStr.startsWith('"') && valueStr.endsWith('"')) {
        valueStr = valueStr.slice(1, -1);
      }

      const existing = variableMap.get(varName) ?? [];
      existing.push({ fieldPath, operator, value: valueStr, isRegex, nocase, lineNumber });
      variableMap.set(varName, existing);
    }
  }

  const eventVariables: YaralEventVariable[] = [];
  for (const [name, predicates] of variableMap) {
    eventVariables.push({ name, predicates });
  }

  const condition = conditionLines.join(" ").trim();
  const matchSection = matchLines.length > 0 ? matchLines.join("\n") : null;
  const outcomeSection = outcomeLines.length > 0 ? outcomeLines.join("\n") : null;

  return { ruleName, meta, eventVariables, condition, matchSection, outcomeSection };
}


/**
 * Regenerate valid YARA-L source text from a ParsedYaralRule.
 * Enables round-tripping: parse -> edit -> regenerate -> onSourceChange.
 */
function regenerateYaralSource(parsed: ParsedYaralRule): string {
  const lines: string[] = [];

  lines.push(`rule ${parsed.ruleName} {`);

  // Meta section
  if (parsed.meta.length > 0) {
    lines.push("  meta:");
    for (const { key, value } of parsed.meta) {
      lines.push(`    ${key} = "${value}"`);
    }
    lines.push("");
  }

  // Events section
  if (parsed.eventVariables.length > 0) {
    lines.push("  events:");
    for (const ev of parsed.eventVariables) {
      for (const pred of ev.predicates) {
        let valueStr: string;
        if (pred.isRegex) {
          valueStr = `/${pred.value}/`;
        } else {
          valueStr = `"${pred.value}"`;
        }
        if (pred.nocase) {
          valueStr += " nocase";
        }
        lines.push(`    ${ev.name}.${pred.fieldPath} ${pred.operator} ${valueStr}`);
      }
    }
    lines.push("");
  }

  // Match section (optional)
  if (parsed.matchSection) {
    lines.push("  match:");
    for (const line of parsed.matchSection.split("\n")) {
      lines.push(`    ${line}`);
    }
    lines.push("");
  }

  // Outcome section (optional)
  if (parsed.outcomeSection) {
    lines.push("  outcome:");
    for (const line of parsed.outcomeSection.split("\n")) {
      lines.push(`    ${line}`);
    }
    lines.push("");
  }

  // Condition section
  lines.push("  condition:");
  lines.push(`    ${parsed.condition}`);

  lines.push("}");
  lines.push("");

  return lines.join("\n");
}


/** MetaSection -- renders meta fields as editable inputs. */
function MetaSection({
  meta,
  accentColor,
  readOnly,
  onUpdateMeta,
}: {
  meta: Array<{ key: string; value: string }>;
  accentColor: string;
  readOnly?: boolean;
  onUpdateMeta: (index: number, value: string) => void;
}) {
  const getMetaValue = (key: string): string => {
    const entry = meta.find((m) => m.key === key);
    return entry?.value ?? "";
  };

  const getMetaIndex = (key: string): number => {
    return meta.findIndex((m) => m.key === key);
  };

  const severity = getMetaValue("severity");
  const mitreAttack = getMetaValue("mitre_attack");
  const techniques = mitreAttack
    ? mitreAttack.split(",").map((t) => t.trim()).filter(Boolean)
    : [];

  return (
    <Section title="Rule Meta" icon={IconFileAnalytics} accentColor={accentColor}>
      <TextInput
        label="Author"
        value={getMetaValue("author")}
        onChange={(v) => {
          const idx = getMetaIndex("author");
          if (idx >= 0) onUpdateMeta(idx, v);
        }}
        placeholder="Rule author"
        readOnly={readOnly}
        accentColor={accentColor}
      />
      <TextArea
        label="Description"
        value={getMetaValue("description")}
        onChange={(v) => {
          const idx = getMetaIndex("description");
          if (idx >= 0) onUpdateMeta(idx, v);
        }}
        placeholder="Describe what this rule detects..."
        readOnly={readOnly}
        accentColor={accentColor}
      />
      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <SelectInput
              label="Severity"
              value={severity}
              options={SEVERITY_OPTIONS}
              onChange={(v) => {
                const idx = getMetaIndex("severity");
                if (idx >= 0) onUpdateMeta(idx, v);
              }}
              readOnly={readOnly}
              accentColor={accentColor}
            />
          </div>
          {severity && (
            <div className="mt-1">
              <SeverityBadge severity={severity.toLowerCase()} />
            </div>
          )}
        </div>
        <TextInput
          label="Created"
          value={getMetaValue("created")}
          onChange={(v) => {
            const idx = getMetaIndex("created");
            if (idx >= 0) onUpdateMeta(idx, v);
          }}
          placeholder="YYYY-MM-DD"
          readOnly={readOnly}
          mono
          accentColor={accentColor}
        />
      </div>
      {techniques.length > 0 && (
        <div className="flex flex-col gap-1">
          <FieldLabel label="MITRE ATT&CK" />
          <div className="flex flex-wrap gap-1.5">
            {techniques.map((t, i) => (
              <AttackTagBadge key={i} tag={`attack.${t}`} />
            ))}
          </div>
        </div>
      )}
    </Section>
  );
}


/** EventVariableCard -- renders one event variable with its UDM field predicates. */
function EventVariableCard({
  variable,
  accentColor,
  readOnly,
  onUpdatePredicate,
  onAddPredicate,
  onRemovePredicate,
}: {
  variable: YaralEventVariable;
  accentColor: string;
  readOnly?: boolean;
  onUpdatePredicate: (
    predicateIndex: number,
    field: "fieldPath" | "operator" | "value",
    newValue: string,
  ) => void;
  onAddPredicate: () => void;
  onRemovePredicate: (predicateIndex: number) => void;
}) {
  return (
    <div
      className="rounded-md border p-3"
      style={{
        borderColor: `${accentColor}30`,
        borderLeftWidth: 3,
        borderLeftColor: accentColor,
      }}
    >
      {/* Variable header */}
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span
            className="text-[13px] font-mono font-bold"
            style={{ color: accentColor }}
          >
            {variable.name}
          </span>
          <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
            event variable
          </span>
        </div>
        <span
          className="text-[9px] font-mono px-1.5 py-0.5 rounded-full"
          style={{
            color: accentColor,
            backgroundColor: `${accentColor}15`,
          }}
        >
          {variable.predicates.length} predicate{variable.predicates.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Predicates list */}
      <div className="flex flex-col gap-1">
        {variable.predicates.map((pred, pi) => (
          <div
            key={pi}
            className={cn(
              "flex items-center gap-1.5 px-2 py-1.5 rounded text-[10px] font-mono",
              pi % 2 === 1 ? "bg-white/5" : "bg-transparent",
            )}
          >
            {/* Field path */}
            <input
              type="text"
              value={pred.fieldPath}
              onChange={(e) => onUpdatePredicate(pi, "fieldPath", e.target.value)}
              readOnly={readOnly}
              className={cn(
                "bg-transparent border-none text-[#ece7dc] text-[10px] font-mono flex-1 min-w-0 outline-none",
                readOnly && "cursor-default",
              )}
              title={`${variable.name}.${pred.fieldPath}`}
            />

            {/* Operator */}
            <select
              value={pred.operator}
              onChange={(e) => onUpdatePredicate(pi, "operator", e.target.value)}
              disabled={readOnly}
              className="bg-[#0b0d13] border border-[#2d3240] rounded text-[10px] font-mono text-[#d4a84b] px-1 py-0.5 appearance-none cursor-pointer"
            >
              {OPERATOR_OPTIONS.map((op) => (
                <option key={op.value} value={op.value}>{op.label}</option>
              ))}
            </select>

            {/* Value */}
            <input
              type="text"
              value={pred.isRegex ? `/${pred.value}/` : pred.value}
              onChange={(e) => {
                let val = e.target.value;
                // Handle regex syntax in input
                if (val.startsWith("/") && val.endsWith("/") && val.length > 1) {
                  val = val.slice(1, -1);
                }
                onUpdatePredicate(pi, "value", val);
              }}
              readOnly={readOnly}
              className={cn(
                "bg-transparent border-none text-[10px] font-mono flex-1 min-w-0 outline-none",
                pred.isRegex ? "text-[#e0915c]" : "text-[#3dbf84]",
                readOnly && "cursor-default",
              )}
            />

            {/* Nocase indicator */}
            {pred.nocase && (
              <span className="text-[8px] font-mono text-[#6f7f9a] uppercase tracking-wider shrink-0">
                nocase
              </span>
            )}

            {/* Regex indicator */}
            {pred.isRegex && (
              <span className="text-[8px] font-mono text-[#e0915c]/60 uppercase tracking-wider shrink-0">
                regex
              </span>
            )}

            {/* Remove button */}
            {!readOnly && (
              <button
                type="button"
                onClick={() => onRemovePredicate(pi)}
                className="text-[#6f7f9a]/50 hover:text-[#c45c5c] transition-colors shrink-0"
                title="Remove predicate"
              >
                <IconTrash size={10} stroke={1.5} />
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Add predicate button */}
      {!readOnly && (
        <button
          type="button"
          onClick={onAddPredicate}
          className="flex items-center gap-1 mt-2 px-2 py-1 text-[9px] font-mono rounded transition-colors hover:bg-white/5"
          style={{ color: `${accentColor}80` }}
        >
          <IconPlus size={10} stroke={1.5} />
          Add predicate
        </button>
      )}
    </div>
  );
}


/** ConditionEditor -- renders the condition expression. */
function ConditionEditor({
  condition,
  accentColor,
  readOnly,
  onUpdateCondition,
}: {
  condition: string;
  accentColor: string;
  readOnly?: boolean;
  onUpdateCondition: (value: string) => void;
}) {
  return (
    <Section title="Condition" icon={IconFilter} accentColor={accentColor}>
      <TextInput
        label="Condition Expression"
        value={condition}
        onChange={onUpdateCondition}
        placeholder="$e or $e1 and $e2"
        readOnly={readOnly}
        mono
        accentColor={accentColor}
      />
      <div className="text-[9px] font-mono text-[#6f7f9a]/60 leading-relaxed">
        Single variable: <span className="text-[#ece7dc]/40">$e</span> | Multi-event: <span className="text-[#ece7dc]/40">$e1 and $e2</span> | With count: <span className="text-[#ece7dc]/40">#e &gt; 5</span>
      </div>
    </Section>
  );
}


/** MatchOutcomeSection -- optional raw editing for match/outcome blocks. */
function MatchOutcomeSection({
  matchSection,
  outcomeSection,
  accentColor,
  readOnly,
  onUpdateMatch,
  onUpdateOutcome,
}: {
  matchSection: string | null;
  outcomeSection: string | null;
  accentColor: string;
  readOnly?: boolean;
  onUpdateMatch: (value: string) => void;
  onUpdateOutcome: (value: string) => void;
}) {
  if (!matchSection && !outcomeSection) return null;

  return (
    <Section
      title="Match / Outcome"
      icon={IconAlignBoxLeftTop}
      defaultOpen={false}
      accentColor={accentColor}
    >
      {matchSection !== null && (
        <TextArea
          label="Match"
          value={matchSection}
          onChange={onUpdateMatch}
          placeholder="e.g. $e.principal.hostname over 5m"
          readOnly={readOnly}
          rows={2}
          accentColor={accentColor}
        />
      )}
      {outcomeSection !== null && (
        <TextArea
          label="Outcome"
          value={outcomeSection}
          onChange={onUpdateOutcome}
          placeholder="e.g. $risk_score = max(95)"
          readOnly={readOnly}
          rows={2}
          accentColor={accentColor}
        />
      )}
    </Section>
  );
}


export function YaralVisualPanel({
  source,
  onSourceChange,
  readOnly,
  accentColor,
}: DetectionVisualPanelProps) {
  const ACCENT = accentColor ?? DEFAULT_ACCENT;

  const parsed = useMemo(() => parseYaralSource(source), [source]);


  const updateRuleName = useCallback(
    (newName: string) => {
      if (!parsed) return;
      const updated = { ...parsed, ruleName: newName.replace(/[^a-zA-Z0-9_]/g, "_") };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const updateMeta = useCallback(
    (index: number, value: string) => {
      if (!parsed) return;
      const newMeta = [...parsed.meta];
      newMeta[index] = { ...newMeta[index], value };
      const updated = { ...parsed, meta: newMeta };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const updatePredicate = useCallback(
    (
      varIndex: number,
      predicateIndex: number,
      field: "fieldPath" | "operator" | "value",
      newValue: string,
    ) => {
      if (!parsed) return;
      const newVars = parsed.eventVariables.map((ev, vi) => {
        if (vi !== varIndex) return ev;
        const newPreds = ev.predicates.map((pred, pi) => {
          if (pi !== predicateIndex) return pred;
          return { ...pred, [field]: newValue };
        });
        return { ...ev, predicates: newPreds };
      });
      const updated = { ...parsed, eventVariables: newVars };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const addPredicate = useCallback(
    (varIndex: number) => {
      if (!parsed) return;
      const newVars = parsed.eventVariables.map((ev, vi) => {
        if (vi !== varIndex) return ev;
        const newPred: YaralPredicate = {
          fieldPath: "metadata.event_type",
          operator: "=",
          value: "",
          isRegex: false,
          nocase: false,
          lineNumber: 0,
        };
        return { ...ev, predicates: [...ev.predicates, newPred] };
      });
      const updated = { ...parsed, eventVariables: newVars };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const removePredicate = useCallback(
    (varIndex: number, predicateIndex: number) => {
      if (!parsed) return;
      const newVars = parsed.eventVariables.map((ev, vi) => {
        if (vi !== varIndex) return ev;
        const newPreds = ev.predicates.filter((_, pi) => pi !== predicateIndex);
        return { ...ev, predicates: newPreds };
      });
      const updated = { ...parsed, eventVariables: newVars };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const updateCondition = useCallback(
    (value: string) => {
      if (!parsed) return;
      const updated = { ...parsed, condition: value };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const updateMatch = useCallback(
    (value: string) => {
      if (!parsed) return;
      const updated = { ...parsed, matchSection: value || null };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );

  const updateOutcome = useCallback(
    (value: string) => {
      if (!parsed) return;
      const updated = { ...parsed, outcomeSection: value || null };
      onSourceChange(regenerateYaralSource(updated));
    },
    [parsed, onSourceChange],
  );


  if (!parsed) {
    return (
      <ScrollArea className="h-full">
        <div className="flex flex-col pb-6">
          <div className="flex items-center gap-2 px-4 pt-3 pb-1">
            <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>YARA-L</span>
            <span className="text-[10px] font-mono text-[#6f7f9a]">Chronicle Detection Rule</span>
          </div>
          <div
            className="mx-4 mt-3 p-3 rounded border"
            style={{ borderColor: `${ACCENT}40`, backgroundColor: `${ACCENT}08` }}
          >
            <span className="text-[11px] font-mono" style={{ color: ACCENT }}>
              Unable to parse YARA-L rule. Check that the source contains a valid{" "}
              <code className="bg-white/5 px-1 rounded">rule name {"{"} ... {"}"}</code> structure.
            </span>
          </div>
        </div>
      </ScrollArea>
    );
  }

  const totalPredicates = parsed.eventVariables.reduce(
    (sum, ev) => sum + ev.predicates.length,
    0,
  );

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col pb-6">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>YARA-L</span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">Chronicle Detection Rule</span>
        </div>

        {/* Summary bar */}
        <div className="flex items-center gap-2 px-4 pt-2 pb-0 flex-wrap">
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
            style={{
              color: ACCENT,
              borderColor: `${ACCENT}30`,
              backgroundColor: `${ACCENT}08`,
            }}
          >
            {parsed.eventVariables.length} event var{parsed.eventVariables.length !== 1 ? "s" : ""}
          </span>
          <span
            className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
            style={{
              color: "#6f7f9a",
              borderColor: "#2d324040",
              backgroundColor: "#2d324010",
            }}
          >
            {totalPredicates} predicate{totalPredicates !== 1 ? "s" : ""}
          </span>
          {parsed.matchSection && (
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: "#d4a84b",
                borderColor: "#d4a84b30",
                backgroundColor: "#d4a84b08",
              }}
            >
              match
            </span>
          )}
          {parsed.outcomeSection && (
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono border rounded"
              style={{
                color: "#3dbf84",
                borderColor: "#3dbf8430",
                backgroundColor: "#3dbf8408",
              }}
            >
              outcome
            </span>
          )}
        </div>

        {/* Rule name */}
        <div className="px-4 pt-3">
          <TextInput
            label="Rule Name"
            value={parsed.ruleName}
            onChange={updateRuleName}
            placeholder="rule_name"
            readOnly={readOnly}
            mono
            accentColor={ACCENT}
          />
        </div>

        {/* Divider */}
        <div className="mx-4 my-3 h-px bg-[#2d3240]" />

        {/* Meta section */}
        <MetaSection
          meta={parsed.meta}
          accentColor={ACCENT}
          readOnly={readOnly}
          onUpdateMeta={updateMeta}
        />

        {/* Divider */}
        <div className="mx-4 my-1 h-px bg-[#2d3240]" />

        {/* Events section */}
        <Section
          title="Events"
          icon={IconTimeline}
          count={parsed.eventVariables.length}
          accentColor={ACCENT}
        >
          {parsed.eventVariables.length > 0 ? (
            <div className="flex flex-col gap-3">
              {parsed.eventVariables.map((ev, vi) => (
                <EventVariableCard
                  key={ev.name}
                  variable={ev}
                  accentColor={ACCENT}
                  readOnly={readOnly}
                  onUpdatePredicate={(pi, field, val) => updatePredicate(vi, pi, field, val)}
                  onAddPredicate={() => addPredicate(vi)}
                  onRemovePredicate={(pi) => removePredicate(vi, pi)}
                />
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
              No event variables found. Add predicates like <code className="text-[#ece7dc]/40">$e.metadata.event_type = "PROCESS_LAUNCH"</code> in the events section.
            </div>
          )}
        </Section>

        {/* Divider */}
        <div className="mx-4 my-1 h-px bg-[#2d3240]" />

        {/* Condition section */}
        <ConditionEditor
          condition={parsed.condition}
          accentColor={ACCENT}
          readOnly={readOnly}
          onUpdateCondition={updateCondition}
        />

        {/* Match / Outcome section (optional) */}
        <MatchOutcomeSection
          matchSection={parsed.matchSection}
          outcomeSection={parsed.outcomeSection}
          accentColor={ACCENT}
          readOnly={readOnly}
          onUpdateMatch={updateMatch}
          onUpdateOutcome={updateOutcome}
        />
      </div>
    </ScrollArea>
  );
}


registerVisualPanel("yaral_rule", YaralVisualPanel);
