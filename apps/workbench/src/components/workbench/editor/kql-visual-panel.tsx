"use client";

import { useMemo, useCallback, useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import {
  Section,
  FieldLabel,
  TextInput,
  SelectInput,
} from "./detection-panel-kit";
import type { SelectOption } from "./detection-panel-kit";
import {
  parseKqlQuery,
  type KqlParsedQuery,
  type KqlWhereClause,
} from "@/lib/workbench/detection-workflow/kql-adapter";
import type { DetectionVisualPanelProps } from "@/lib/workbench/detection-workflow/shared-types";
import { registerVisualPanel } from "@/lib/workbench/detection-workflow/visual-panels";
import {
  IconDatabase,
  IconFilter,
  IconColumns3,
  IconCode,
  IconPlus,
  IconX,
  IconChevronRight,
} from "@tabler/icons-react";


/** Default accent color for KQL panels (Microsoft blue). */
const DEFAULT_ACCENT = "#0078d4";

/** Sentinel table options for the source table selector dropdown. */
const SENTINEL_TABLES: SelectOption[] = [
  { value: "SecurityEvent", label: "Security Event Log" },
  { value: "CommonSecurityLog", label: "Common Security Log" },
  { value: "SigninLogs", label: "Sign-in Logs" },
  { value: "AuditLogs", label: "Audit Logs" },
  { value: "DeviceProcessEvents", label: "Defender - Process Events" },
  { value: "DeviceFileEvents", label: "Defender - File Events" },
  { value: "DeviceNetworkEvents", label: "Defender - Network Events" },
  { value: "DeviceLogonEvents", label: "Defender - Logon Events" },
  { value: "OfficeActivity", label: "Office 365 Activity" },
  { value: "Syslog", label: "Syslog" },
  { value: "AzureActivity", label: "Azure Activity" },
];

/** Known Sentinel table names for fast lookup. */
const SENTINEL_TABLE_NAMES = new Set(
  SENTINEL_TABLES.map((t) => (typeof t === "string" ? t : t.value)),
);

/** KQL operator options for where-clause operator dropdowns. */
const KQL_OPERATORS: SelectOption[] = [
  { value: "==", label: "==" },
  { value: "!=", label: "!=" },
  { value: "contains", label: "contains" },
  { value: "!contains", label: "!contains" },
  { value: "startswith", label: "startswith" },
  { value: "!startswith", label: "!startswith" },
  { value: "endswith", label: "endswith" },
  { value: "!endswith", label: "!endswith" },
  { value: "has", label: "has" },
  { value: "!has", label: "!has" },
  { value: "matches regex", label: "matches regex" },
  { value: "in", label: "in" },
  { value: "!in", label: "!in" },
];


/**
 * Reconstruct a valid KQL query string from its parsed components.
 *
 * Output ordering:
 *   1. Comment lines (// ...)
 *   2. Table name
 *   3. Where clauses: `| where {field} {operator} "{value}"`
 *   4. Project clause: `| project col1, col2, ...`
 *   5. Extend expressions: `| extend {expr}`
 */
function reconstructKql(
  tableName: string,
  whereClauses: KqlWhereClause[],
  projectColumns: string[],
  extendExpressions: string[],
  comments: string[],
): string {
  const lines: string[] = [];

  // 1. Comments
  for (const comment of comments) {
    lines.push(comment);
  }

  // 2. Table name
  if (tableName) {
    lines.push(tableName);
  }

  // 3. Where clauses
  for (const clause of whereClauses) {
    if (!clause.field && !clause.value) continue;
    const op = clause.operator || "==";
    // For "in" / "!in" operators, wrap value in parentheses rather than quotes
    if (op === "in" || op === "!in") {
      const val = clause.value.startsWith("(") ? clause.value : `(${clause.value})`;
      lines.push(`| where ${clause.field} ${op} ${val}`);
    } else {
      lines.push(`| where ${clause.field} ${op} "${clause.value}"`);
    }
  }

  // 4. Project
  if (projectColumns.length > 0) {
    lines.push(`| project ${projectColumns.join(", ")}`);
  }

  // 5. Extend
  for (const expr of extendExpressions) {
    lines.push(`| extend ${expr}`);
  }

  return lines.join("\n") + "\n";
}


function WhereClauseCard({
  clause,
  index,
  readOnly,
  accentColor,
  onFieldChange,
  onOperatorChange,
  onValueChange,
  onRemove,
}: {
  clause: KqlWhereClause;
  index: number;
  readOnly?: boolean;
  accentColor: string;
  onFieldChange: (index: number, value: string) => void;
  onOperatorChange: (index: number, value: string) => void;
  onValueChange: (index: number, value: string) => void;
  onRemove: (index: number) => void;
}) {
  return (
    <div
      className="bg-white/5 rounded-md px-3 py-2.5 flex flex-col gap-2"
      style={{ borderLeft: `3px solid ${accentColor}26` }}
    >
      <div className="flex items-center justify-between">
        <span className="text-[9px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider">
          Filter {index + 1}
        </span>
        {!readOnly && (
          <button
            type="button"
            onClick={() => onRemove(index)}
            className="text-[#6f7f9a]/50 hover:text-[#c45c5c] transition-colors p-0.5"
            title="Remove filter"
          >
            <IconX size={12} stroke={1.5} />
          </button>
        )}
      </div>
      <div className="grid grid-cols-[1fr_auto_1fr] gap-2 items-end">
        <TextInput
          label="Field"
          value={clause.field}
          onChange={(v) => onFieldChange(index, v)}
          placeholder="FieldName"
          readOnly={readOnly}
          mono
          accentColor={accentColor}
        />
        <div className="min-w-[110px]">
          <SelectInput
            label="Operator"
            value={clause.operator}
            options={KQL_OPERATORS}
            onChange={(v) => onOperatorChange(index, v)}
            readOnly={readOnly}
            accentColor={accentColor}
          />
        </div>
        <TextInput
          label="Value"
          value={clause.value}
          onChange={(v) => onValueChange(index, v)}
          placeholder="value"
          readOnly={readOnly}
          mono
          accentColor={accentColor}
        />
      </div>
    </div>
  );
}


function RawKqlPreview({ kql, accentColor }: { kql: string; accentColor: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="flex flex-col">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a] hover:text-[#ece7dc]/60 transition-colors py-1"
      >
        <IconChevronRight
          size={10}
          stroke={1.5}
          className="transition-transform"
          style={{
            transform: open ? "rotate(90deg)" : "rotate(0deg)",
            transitionDuration: "150ms",
          }}
        />
        <IconCode size={11} stroke={1.5} />
        Raw KQL
      </button>
      {open && (
        <pre
          className="bg-[#05060a] border border-[#2d3240] rounded px-3 py-2 text-[10px] font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap mt-1"
          style={{
            color: "#6f7f9a",
            borderLeftWidth: 2,
            borderLeftColor: `${accentColor}40`,
          }}
        >
          {kql}
        </pre>
      )}
    </div>
  );
}


export function KqlVisualPanel(props: DetectionVisualPanelProps) {
  const { source, onSourceChange, readOnly, accentColor } = props;
  const ACCENT = accentColor ?? DEFAULT_ACCENT;

  // Parse the current KQL source into structured components
  const parsed: KqlParsedQuery = useMemo(() => parseKqlQuery(source), [source]);


  const handleTableChange = useCallback(
    (newTable: string) => {
      const kql = reconstructKql(
        newTable,
        parsed.whereClauses,
        parsed.projectColumns,
        parsed.extendExpressions,
        parsed.comments,
      );
      onSourceChange(kql);
    },
    [parsed, onSourceChange],
  );


  const handleFieldChange = useCallback(
    (index: number, value: string) => {
      const updated = [...parsed.whereClauses];
      updated[index] = { ...updated[index], field: value };
      const kql = reconstructKql(
        parsed.tableName,
        updated,
        parsed.projectColumns,
        parsed.extendExpressions,
        parsed.comments,
      );
      onSourceChange(kql);
    },
    [parsed, onSourceChange],
  );

  const handleOperatorChange = useCallback(
    (index: number, value: string) => {
      const updated = [...parsed.whereClauses];
      updated[index] = { ...updated[index], operator: value };
      const kql = reconstructKql(
        parsed.tableName,
        updated,
        parsed.projectColumns,
        parsed.extendExpressions,
        parsed.comments,
      );
      onSourceChange(kql);
    },
    [parsed, onSourceChange],
  );

  const handleValueChange = useCallback(
    (index: number, value: string) => {
      const updated = [...parsed.whereClauses];
      updated[index] = { ...updated[index], value };
      const kql = reconstructKql(
        parsed.tableName,
        updated,
        parsed.projectColumns,
        parsed.extendExpressions,
        parsed.comments,
      );
      onSourceChange(kql);
    },
    [parsed, onSourceChange],
  );

  const handleRemoveClause = useCallback(
    (index: number) => {
      const updated = parsed.whereClauses.filter((_, i) => i !== index);
      const kql = reconstructKql(
        parsed.tableName,
        updated,
        parsed.projectColumns,
        parsed.extendExpressions,
        parsed.comments,
      );
      onSourceChange(kql);
    },
    [parsed, onSourceChange],
  );

  const handleAddClause = useCallback(() => {
    const newClause: KqlWhereClause = {
      field: "",
      operator: "contains",
      value: "",
      raw: "",
    };
    const updated = [...parsed.whereClauses, newClause];
    const kql = reconstructKql(
      parsed.tableName,
      updated,
      parsed.projectColumns,
      parsed.extendExpressions,
      parsed.comments,
    );
    onSourceChange(kql);
  }, [parsed, onSourceChange]);


  const handleProjectionChange = useCallback(
    (value: string) => {
      const cols = value
        .split(",")
        .map((c) => c.trim())
        .filter(Boolean);
      const kql = reconstructKql(
        parsed.tableName,
        parsed.whereClauses,
        cols,
        parsed.extendExpressions,
        parsed.comments,
      );
      onSourceChange(kql);
    },
    [parsed, onSourceChange],
  );

  // Build table selector options: include custom table if not in predefined list
  const tableOptions = useMemo(() => {
    if (parsed.tableName && !SENTINEL_TABLE_NAMES.has(parsed.tableName)) {
      return [
        { value: parsed.tableName, label: `${parsed.tableName} (custom)` },
        ...SENTINEL_TABLES,
      ];
    }
    return SENTINEL_TABLES;
  }, [parsed.tableName]);

  // Reconstruct for raw preview
  const reconstructed = useMemo(
    () =>
      reconstructKql(
        parsed.tableName,
        parsed.whereClauses,
        parsed.projectColumns,
        parsed.extendExpressions,
        parsed.comments,
      ),
    [parsed],
  );

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col pb-6">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span
            className="text-base font-black tracking-tight"
            style={{ color: ACCENT }}
          >
            KQL
          </span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            Microsoft Sentinel Query
          </span>
        </div>

        {/* Section 1: Source Table */}
        <Section title="Source Table" icon={IconDatabase} accentColor={ACCENT}>
          {readOnly ? (
            <div className="flex flex-col gap-1">
              <FieldLabel label="Table" />
              <div
                className="bg-[#0b0d13] border border-[#2d3240] rounded px-2 py-1 text-[11px] font-mono text-[#ece7dc]"
                style={{ borderColor: `${ACCENT}40` }}
              >
                {parsed.tableName || "(none)"}
              </div>
            </div>
          ) : (
            <SelectInput
              label="Table"
              value={parsed.tableName}
              options={tableOptions}
              onChange={handleTableChange}
              readOnly={readOnly}
              placeholder="Select a Sentinel table..."
              accentColor={ACCENT}
            />
          )}
        </Section>

        {/* Section 2: Filter Chain */}
        <Section
          title="Filter Chain"
          icon={IconFilter}
          count={parsed.whereClauses.length}
          accentColor={ACCENT}
        >
          {parsed.whereClauses.length > 0 ? (
            <div className="flex flex-col gap-2">
              {parsed.whereClauses.map((clause, i) => (
                <WhereClauseCard
                  key={i}
                  clause={clause}
                  index={i}
                  readOnly={readOnly}
                  accentColor={ACCENT}
                  onFieldChange={handleFieldChange}
                  onOperatorChange={handleOperatorChange}
                  onValueChange={handleValueChange}
                  onRemove={handleRemoveClause}
                />
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
              No where-clause filters. Add a filter to narrow results.
            </div>
          )}

          {!readOnly && (
            <button
              type="button"
              onClick={handleAddClause}
              className={cn(
                "flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider",
                "px-2.5 py-1.5 rounded border border-dashed transition-colors mt-1",
              )}
              style={{
                color: ACCENT,
                borderColor: `${ACCENT}40`,
                backgroundColor: `${ACCENT}08`,
              }}
            >
              <IconPlus size={11} stroke={2} />
              Add Filter
            </button>
          )}
        </Section>

        {/* Section 3: Projection */}
        <Section
          title="Projection"
          icon={IconColumns3}
          defaultOpen={parsed.projectColumns.length > 0}
          accentColor={ACCENT}
        >
          {parsed.projectColumns.length > 0 ? (
            <TextInput
              label="Columns"
              value={parsed.projectColumns.join(", ")}
              onChange={handleProjectionChange}
              placeholder="TimeGenerated, Computer, ..."
              readOnly={readOnly}
              mono
              accentColor={ACCENT}
            />
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-1">
              No projection specified -- all columns returned.
            </div>
          )}
        </Section>

        {/* Section 4: Extend Expressions (conditional) */}
        {parsed.extendExpressions.length > 0 && (
          <Section
            title="Extend Expressions"
            icon={IconCode}
            defaultOpen={false}
            count={parsed.extendExpressions.length}
            accentColor={ACCENT}
          >
            <div className="flex flex-col gap-1.5">
              {parsed.extendExpressions.map((expr, i) => (
                <div
                  key={i}
                  className="bg-[#05060a] border border-[#2d3240] rounded px-3 py-2 text-[10px] font-mono text-[#ece7dc]/70 leading-relaxed"
                  style={{ borderLeftWidth: 2, borderLeftColor: `${ACCENT}30` }}
                >
                  <span className="text-[#6f7f9a] mr-1.5">extend</span>
                  {expr}
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Section 5: Raw KQL Preview (collapsed by default) */}
        <div className="px-4 pt-2">
          <RawKqlPreview kql={reconstructed} accentColor={ACCENT} />
        </div>
      </div>
    </ScrollArea>
  );
}

registerVisualPanel("kql_rule", KqlVisualPanel);
export { KqlVisualPanel as default };
