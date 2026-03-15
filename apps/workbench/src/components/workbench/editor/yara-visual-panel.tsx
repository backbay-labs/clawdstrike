/**
 * Visual panel for YARA rule editing.
 *
 * Provides a form-based view of YARA rule structure:
 *  - Meta section: editable fields (name, author, description, date, reference)
 *  - Strings section: read-only display with type/modifier badges
 *  - Condition section: read-only code display
 *  - Imports section: module badges
 *
 * YARA is NOT YAML — all parsing is regex-based with targeted string
 * replacement for round-trip editing of meta fields.
 */
import { useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  IconFileAnalytics,
  IconVariable,
  IconFilter,
  IconPackageImport,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Section,
  FieldLabel,
  TextInput,
  TextArea,
} from "./shared-form-fields";


// ---- Constants ----

const ACCENT = "#e0915c";


// ---- Types ----

interface YaraVisualPanelProps {
  source: string;
  onSourceChange: (source: string) => void;
  readOnly?: boolean;
}

interface ParsedYaraRule {
  ruleName: string;
  tags: string[];
  isPrivate: boolean;
  isGlobal: boolean;
  meta: { key: string; value: string }[];
  strings: ParsedYaraString[];
  condition: string;
  imports: string[];
}

interface ParsedYaraString {
  variable: string;
  value: string;
  type: "text" | "hex" | "regex";
  modifiers: string[];
}


// ---- Parsing helpers (regex-based, NOT YAML) ----

function parseYaraRule(source: string): ParsedYaraRule {
  const result: ParsedYaraRule = {
    ruleName: "",
    tags: [],
    isPrivate: false,
    isGlobal: false,
    meta: [],
    strings: [],
    condition: "",
    imports: [],
  };

  // Extract imports: import "module"
  const importRe = /import\s+"(\w+)"/g;
  let importMatch: RegExpExecArray | null;
  while ((importMatch = importRe.exec(source)) !== null) {
    result.imports.push(importMatch[1]);
  }

  // Extract rule declaration: [private] [global] rule <name> [: tag1 tag2] {
  const ruleRe = /((?:private|global)\s+)*rule\s+(\w+)(?:\s*:\s*([^{]*))?/;
  const ruleMatch = source.match(ruleRe);
  if (ruleMatch) {
    const modifiers = ruleMatch[1] || "";
    result.isPrivate = /private/i.test(modifiers);
    result.isGlobal = /global/i.test(modifiers);
    result.ruleName = ruleMatch[2];
    if (ruleMatch[3]) {
      result.tags = ruleMatch[3]
        .trim()
        .split(/\s+/)
        .filter((t) => t.length > 0);
    }
  }

  // Find the rule body (content between the first { after rule declaration and last })
  const bodyStart = source.indexOf("{", source.search(/rule\s+\w+/));
  const bodyEnd = source.lastIndexOf("}");
  if (bodyStart === -1 || bodyEnd === -1 || bodyEnd <= bodyStart) {
    return result;
  }
  const body = source.slice(bodyStart + 1, bodyEnd);

  // Split body into sections
  const metaIdx = body.search(/^\s*meta\s*:/m);
  const stringsIdx = body.search(/^\s*strings\s*:/m);
  const conditionIdx = body.search(/^\s*condition\s*:/m);

  // Extract meta section
  if (metaIdx !== -1) {
    const metaEnd =
      stringsIdx !== -1 && stringsIdx > metaIdx
        ? stringsIdx
        : conditionIdx !== -1 && conditionIdx > metaIdx
        ? conditionIdx
        : body.length;
    const metaBlock = body.slice(metaIdx, metaEnd);
    // Remove the "meta:" header line
    const metaContent = metaBlock.replace(/^\s*meta\s*:\s*/m, "");
    // Parse key = value pairs
    const metaLineRe = /^\s*(\w+)\s*=\s*"([^"]*)"\s*$/gm;
    let metaLineMatch: RegExpExecArray | null;
    while ((metaLineMatch = metaLineRe.exec(metaContent)) !== null) {
      result.meta.push({ key: metaLineMatch[1], value: metaLineMatch[2] });
    }
    // Also parse non-string values (numbers, booleans)
    const metaValRe = /^\s*(\w+)\s*=\s*([^"\s][^\n]*?)\s*$/gm;
    while ((metaLineMatch = metaValRe.exec(metaContent)) !== null) {
      // Skip if already captured as a string value
      if (!result.meta.some((m) => m.key === metaLineMatch![1])) {
        result.meta.push({ key: metaLineMatch[1], value: metaLineMatch[2] });
      }
    }
  }

  // Extract strings section
  if (stringsIdx !== -1) {
    const stringsEnd =
      conditionIdx !== -1 && conditionIdx > stringsIdx
        ? conditionIdx
        : body.length;
    const stringsBlock = body.slice(stringsIdx, stringsEnd);
    const stringsContent = stringsBlock.replace(/^\s*strings\s*:\s*/m, "");

    // Match string declarations: $var = "text" modifiers
    // Also handles hex strings: $var = { AB CD ?? }
    // Also handles regex: $var = /pattern/modifiers
    const stringLineRe =
      /^\s*(\$\w*)\s*=\s*((?:"(?:[^"\\]|\\.)*")|(?:\{[^}]*\})|(?:\/(?:[^/\\]|\\.)*\/[ismg]*))(.*?)$/gm;
    let strLineMatch: RegExpExecArray | null;
    while ((strLineMatch = stringLineRe.exec(stringsContent)) !== null) {
      const variable = strLineMatch[1];
      const rawValue = strLineMatch[2].trim();
      const rawModifiers = strLineMatch[3].trim();

      let type: ParsedYaraString["type"] = "text";
      if (rawValue.startsWith("{")) {
        type = "hex";
      } else if (rawValue.startsWith("/")) {
        type = "regex";
      }

      const modifiers = rawModifiers
        .split(/\s+/)
        .filter((m) => m.length > 0);

      result.strings.push({ variable, value: rawValue, type, modifiers });
    }
  }

  // Extract condition section
  if (conditionIdx !== -1) {
    const conditionBlock = body.slice(conditionIdx);
    const conditionContent = conditionBlock.replace(/^\s*condition\s*:\s*/m, "");
    result.condition = conditionContent.trim();
  }

  return result;
}

function updateMetaField(
  source: string,
  key: string,
  newValue: string,
): string {
  // Try to find and replace existing meta field
  const existingRe = new RegExp(
    `^(\\s*${key}\\s*=\\s*)"([^"]*)"`,
    "m",
  );
  if (existingRe.test(source)) {
    return source.replace(existingRe, `$1"${newValue}"`);
  }

  // Try non-string value
  const existingValRe = new RegExp(
    `^(\\s*${key}\\s*=\\s*)([^"\\s][^\\n]*)`,
    "m",
  );
  if (existingValRe.test(source)) {
    return source.replace(existingValRe, `$1"${newValue}"`);
  }

  // Field doesn't exist — insert it into the meta section
  const metaRe = /^(\s*meta\s*:)/m;
  if (metaRe.test(source)) {
    return source.replace(metaRe, `$1\n        ${key} = "${newValue}"`);
  }

  return source;
}

function updateRuleName(source: string, newName: string): string {
  if (!newName || !/^[a-zA-Z_]\w*$/.test(newName)) return source;
  return source.replace(
    /((?:private|global)\s+)*rule\s+\w+/,
    (match) => {
      const prefix = match.match(/((?:private|global)\s+)*/)?.[0] || "";
      return `${prefix}rule ${newName}`;
    },
  );
}




// ---- String Type Badge ----

function StringTypeBadge({ type }: { type: ParsedYaraString["type"] }) {
  const colors: Record<ParsedYaraString["type"], { bg: string; text: string }> = {
    text: { bg: "#3dbf8415", text: "#3dbf84" },
    hex: { bg: `${ACCENT}15`, text: ACCENT },
    regex: { bg: "#7c9aef15", text: "#7c9aef" },
  };

  const c = colors[type];

  return (
    <span
      className="text-[9px] font-mono px-1.5 py-0.5 rounded uppercase"
      style={{ backgroundColor: c.bg, color: c.text }}
    >
      {type}
    </span>
  );
}

function ModifierBadge({ modifier }: { modifier: string }) {
  return (
    <span
      className="text-[9px] font-mono px-1.5 py-0.5 rounded border"
      style={{
        color: ACCENT,
        backgroundColor: `${ACCENT}10`,
        borderColor: `${ACCENT}30`,
      }}
    >
      {modifier}
    </span>
  );
}


// ---- String Row ----

function StringRow({ str }: { str: ParsedYaraString }) {
  return (
    <div className="bg-[#0b0d13]/50 border border-[#2d3240] rounded-lg p-3">
      <div className="flex items-center gap-2 mb-2">
        <span
          className="text-[11px] font-semibold font-mono"
          style={{ color: ACCENT }}
        >
          {str.variable}
        </span>
        <StringTypeBadge type={str.type} />
        {str.modifiers.map((mod) => (
          <ModifierBadge key={mod} modifier={mod} />
        ))}
      </div>
      <div
        className={cn(
          "text-[11px] font-mono leading-relaxed break-all",
          str.type === "hex"
            ? "text-[#e0915c]/80"
            : str.type === "regex"
            ? "text-[#7c9aef]/80"
            : "text-[#3dbf84]/80",
        )}
      >
        {str.value}
      </div>
    </div>
  );
}


// ---- Main Panel ----

export function YaraVisualPanel({
  source,
  onSourceChange,
  readOnly,
}: YaraVisualPanelProps) {
  const rule = useMemo(() => parseYaraRule(source), [source]);

  const getMetaValue = useCallback(
    (key: string): string => {
      const entry = rule.meta.find((m) => m.key === key);
      return entry?.value ?? "";
    },
    [rule.meta],
  );

  const handleMetaChange = useCallback(
    (key: string, value: string) => {
      onSourceChange(updateMetaField(source, key, value));
    },
    [source, onSourceChange],
  );

  const handleRuleNameChange = useCallback(
    (name: string) => {
      onSourceChange(updateRuleName(source, name));
    },
    [source, onSourceChange],
  );

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col">
        {/* Format sigil */}
        <div className="flex items-center gap-2 px-4 pt-3 pb-1">
          <span className="text-base font-black tracking-tight" style={{ color: ACCENT }}>YAR</span>
          <span className="text-[10px] font-mono text-[#6f7f9a]">YARA Pattern Rule</span>
        </div>

        {/* Rule modifier badges */}
        {(rule.isPrivate || rule.isGlobal || rule.tags.length > 0) && (
          <div className="flex items-center gap-2 px-4 pt-3 pb-0 flex-wrap">
            {rule.isPrivate && (
              <span
                className="inline-flex items-center px-2 py-0.5 text-[9px] font-mono border rounded"
                style={{
                  color: "#c45c5c",
                  borderColor: "#c45c5c30",
                  backgroundColor: "#c45c5c08",
                }}
              >
                private
              </span>
            )}
            {rule.isGlobal && (
              <span
                className="inline-flex items-center px-2 py-0.5 text-[9px] font-mono border rounded"
                style={{
                  color: "#7c9aef",
                  borderColor: "#7c9aef30",
                  backgroundColor: "#7c9aef08",
                }}
              >
                global
              </span>
            )}
            {rule.tags.map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center px-2 py-0.5 text-[9px] font-mono border rounded"
                style={{
                  color: ACCENT,
                  borderColor: `${ACCENT}30`,
                  backgroundColor: `${ACCENT}10`,
                }}
              >
                {tag}
              </span>
            ))}
          </div>
        )}

        {/* Section 1: Meta */}
        <Section title="Meta" icon={IconFileAnalytics} accentColor={ACCENT}>
          <TextInput
            label="Rule Name"
            value={rule.ruleName}
            onChange={handleRuleNameChange}
            required
            readOnly={readOnly}
            mono
            accentColor={ACCENT}
          />
          <TextInput
            label="Author"
            value={getMetaValue("author")}
            onChange={(v) => handleMetaChange("author", v)}
            placeholder="Your name or team"
            readOnly={readOnly}
            accentColor={ACCENT}
          />
          <TextArea
            label="Description"
            value={getMetaValue("description")}
            onChange={(v) => handleMetaChange("description", v)}
            placeholder="What does this rule detect?"
            readOnly={readOnly}
            rows={2}
            accentColor={ACCENT}
          />
          <div className="grid grid-cols-2 gap-3">
            <TextInput
              label="Date"
              value={getMetaValue("date")}
              onChange={(v) => handleMetaChange("date", v)}
              placeholder="YYYY-MM-DD"
              readOnly={readOnly}
              mono
              accentColor={ACCENT}
            />
            <TextInput
              label="Reference"
              value={getMetaValue("reference")}
              onChange={(v) => handleMetaChange("reference", v)}
              placeholder="https://..."
              readOnly={readOnly}
              accentColor={ACCENT}
            />
          </div>

          {/* Show any extra meta fields not covered above */}
          {rule.meta
            .filter(
              (m) =>
                !["author", "description", "date", "reference"].includes(m.key),
            )
            .map((m) => (
              <div key={m.key} className="flex flex-col gap-1">
                <FieldLabel label={m.key} />
                <div className="bg-[#0b0d13] border border-[#2d3240] rounded text-[11px] font-mono text-[#ece7dc]/70 px-2 py-1">
                  {m.value}
                </div>
              </div>
            ))}
        </Section>

        {/* Section 2: Strings (read-only) */}
        <Section
          title="Strings"
          icon={IconVariable}
          count={rule.strings.length}
          defaultOpen={rule.strings.length > 0}
          accentColor={ACCENT}
        >
          {rule.strings.length > 0 ? (
            <div className="flex flex-col gap-2">
              {rule.strings.map((str, i) => (
                <StringRow key={`${str.variable}-${i}`} str={str} />
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
              No string patterns found. Add strings in the YARA source editor.
            </div>
          )}
        </Section>

        {/* Section 3: Condition (read-only) */}
        <Section title="Condition" icon={IconFilter} accentColor={ACCENT}>
          {rule.condition ? (
            <div
              className="bg-[#0b0d13] border border-[#2d3240] rounded-lg px-3 py-2.5 font-mono text-[11px] leading-relaxed whitespace-pre-wrap"
              style={{ color: ACCENT }}
            >
              {rule.condition}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-2">
              Every YARA rule needs a condition. Add one in the source editor.
            </div>
          )}
        </Section>

        {/* Section 4: Imports */}
        <Section
          title="Imports"
          icon={IconPackageImport}
          defaultOpen={rule.imports.length > 0}
          count={rule.imports.length}
          accentColor={ACCENT}
        >
          {rule.imports.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {rule.imports.map((mod) => (
                <span
                  key={mod}
                  className="inline-flex items-center px-2 py-0.5 text-[10px] font-mono border rounded"
                  style={{
                    color: ACCENT,
                    borderColor: `${ACCENT}30`,
                    backgroundColor: `${ACCENT}10`,
                  }}
                >
                  {mod}
                </span>
              ))}
            </div>
          ) : (
            <div className="text-[11px] font-mono text-[#6f7f9a]/50 italic py-1">
              No module imports
            </div>
          )}
        </Section>

        {/* Bottom padding */}
        <div className="h-6" />
      </div>
    </ScrollArea>
  );
}
