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

function escapeYaraMetaString(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
}

function unescapeYaraMetaString(value: string): string {
  return value
    .replace(/\\r/g, "\r")
    .replace(/\\n/g, "\n")
    .replace(/\\t/g, "\t")
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, "\\");
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
    const metaLineRe = /^\s*(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$/gm;
    let metaLineMatch: RegExpExecArray | null;
    while ((metaLineMatch = metaLineRe.exec(metaContent)) !== null) {
      result.meta.push({ key: metaLineMatch[1], value: unescapeYaraMetaString(metaLineMatch[2]) });
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
  const escapedValue = escapeYaraMetaString(newValue);
  // Try to find and replace existing meta field
  const existingRe = new RegExp(
    `^(\\s*${key}\\s*=\\s*)"(?:[^"\\\\]|\\\\.)*"`,
    "m",
  );
  if (existingRe.test(source)) {
    const safeValue = escapedValue.replace(/\$/g, "$$$$");
    return source.replace(existingRe, `$1"${safeValue}"`);
  }

  // Try non-string value
  const existingValRe = new RegExp(
    `^(\\s*${key}\\s*=\\s*)([^"\\s][^\\n]*)`,
    "m",
  );
  if (existingValRe.test(source)) {
    return source.replace(existingValRe, `$1"${escapedValue.replace(/\$/g, "$$$$")}"`);
  }

  // Field doesn't exist — insert it into the meta section
  const metaRe = /^(\s*meta\s*:)/m;
  if (metaRe.test(source)) {
    return source.replace(metaRe, `$1\n        ${key} = "${escapedValue.replace(/\$/g, "$$$$")}"`);
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




// ---- Type Color Mapping ----

function stringTypeColor(type: string): string {
  switch (type) {
    case "text":
      return "#3dbf84";
    case "hex":
      return "#e0915c";
    case "regex":
      return "#7c9aef";
    default:
      return "#6f7f9a";
  }
}


// ---- String Type Badge ----

function StringTypeBadge({ type }: { type: ParsedYaraString["type"] }) {
  const color = stringTypeColor(type);
  return (
    <span
      className="text-[9px] font-mono px-1.5 py-0.5 rounded uppercase"
      style={{ backgroundColor: `${color}15`, color }}
    >
      {type}
    </span>
  );
}

function ModifierBadge({ modifier }: { modifier: string }) {
  return (
    <span
      className="text-[9px] font-mono px-1.5 py-0.5 rounded"
      style={{
        color: "#6f7f9a",
        backgroundColor: "#6f7f9a15",
      }}
    >
      {modifier}
    </span>
  );
}


// ---- Regex Tokenizer ----

interface Token {
  type: string;
  value: string;
}

function tokenizeRegex(value: string): Token[] {
  const tokens: Token[] = [];
  let pattern = value;
  let flags = "";

  // Strip /pattern/flags format
  if (pattern.startsWith("/")) {
    const lastSlash = pattern.lastIndexOf("/");
    if (lastSlash > 0) {
      flags = pattern.slice(lastSlash + 1);
      pattern = pattern.slice(1, lastSlash);
    }
  }

  tokens.push({ type: "delimiter", value: "/" });

  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];

    // Escape sequences
    if (ch === "\\" && i + 1 < pattern.length) {
      const next = pattern[i + 1];
      // Named character classes: \d, \w, \s, \b, etc.
      if (/[dwsDbWSB]/.test(next)) {
        tokens.push({ type: "charClass", value: `\\${next}` });
      } else {
        tokens.push({ type: "escape", value: `\\${next}` });
      }
      i += 2;
      continue;
    }

    // Character classes [...]
    if (ch === "[") {
      let classEnd = i + 1;
      // Handle leading ] or ^]
      if (classEnd < pattern.length && pattern[classEnd] === "^") classEnd++;
      if (classEnd < pattern.length && pattern[classEnd] === "]") classEnd++;
      while (classEnd < pattern.length && pattern[classEnd] !== "]") {
        if (pattern[classEnd] === "\\" && classEnd + 1 < pattern.length) classEnd++;
        classEnd++;
      }
      if (classEnd < pattern.length) classEnd++; // include closing ]
      tokens.push({ type: "charClass", value: pattern.slice(i, classEnd) });
      i = classEnd;
      continue;
    }

    // Dot wildcard
    if (ch === ".") {
      tokens.push({ type: "charClass", value: "." });
      i++;
      continue;
    }

    // Quantifiers
    if (ch === "+" || ch === "*" || ch === "?") {
      tokens.push({ type: "quantifier", value: ch });
      i++;
      continue;
    }

    // Quantifier {n,m}
    if (ch === "{") {
      const braceMatch = pattern.slice(i).match(/^\{\d+(?:,\d*)?\}/);
      if (braceMatch) {
        tokens.push({ type: "quantifier", value: braceMatch[0] });
        i += braceMatch[0].length;
        continue;
      }
    }

    // Groups ( ) and alternation |
    if (ch === "(" || ch === ")" || ch === "|") {
      tokens.push({ type: "group", value: ch });
      i++;
      continue;
    }

    // Anchors
    if (ch === "^" || ch === "$") {
      tokens.push({ type: "charClass", value: ch });
      i++;
      continue;
    }

    // Literal characters — accumulate consecutive
    let literal = "";
    while (
      i < pattern.length &&
      !"\\.[](){}+*?|^$".includes(pattern[i])
    ) {
      literal += pattern[i];
      i++;
    }
    if (literal) {
      tokens.push({ type: "literal", value: literal });
    }
  }

  tokens.push({ type: "delimiter", value: "/" });

  if (flags) {
    tokens.push({ type: "flags", value: flags });
  }

  return tokens;
}

const REGEX_TOKEN_COLORS: Record<string, string> = {
  delimiter: "#6f7f9a",
  literal: "#7c9aef",
  charClass: "#e0915c",
  quantifier: "#d4a84b",
  escape: "#c45c5c",
  group: "#6f7f9a",
  flags: "#9c6fe0",
};


// ---- Hex Display ----

function HexPatternDisplay({ value }: { value: string }) {
  // Strip { } delimiters and split into byte tokens
  const inner = value.replace(/^\{/, "").replace(/\}$/, "").trim();
  const bytes = inner.split(/\s+/).filter((b) => b.length > 0);

  // Group into rows of 12
  const rows: string[][] = [];
  for (let i = 0; i < bytes.length; i += 12) {
    rows.push(bytes.slice(i, i + 12));
  }

  return (
    <div className="font-mono text-[11px] leading-[1.8] pt-1">
      {rows.map((row, ri) => (
        <div key={ri} className="flex flex-wrap">
          {row.map((byte, bi) => {
            const isWildcard = byte === "??" || byte === "?";
            // Extra spacing after every 4th byte (quad grouping)
            const isQuadEnd = (bi + 1) % 4 === 0 && bi < row.length - 1;
            return (
              <span
                key={bi}
                className={cn(
                  "w-[24px] text-center tabular-nums",
                  isQuadEnd && "mr-3",
                )}
                style={{
                  color: "#e0915c",
                  opacity: isWildcard ? 0.3 : 0.85,
                }}
              >
                {byte}
              </span>
            );
          })}
        </div>
      ))}
    </div>
  );
}


// ---- Text Pattern Display ----

function TextPatternDisplay({ value, modifiers }: { value: string; modifiers: string[] }) {
  // value is like "some pattern" — strip quotes
  const inner = value.slice(1, -1);
  return (
    <div className="font-mono text-[11px] leading-relaxed pt-1 flex items-baseline gap-2 flex-wrap">
      <span>
        <span style={{ color: "#3dbf84", opacity: 0.4 }}>&quot;</span>
        <span style={{ color: "#3dbf84" }}>{inner}</span>
        <span style={{ color: "#3dbf84", opacity: 0.4 }}>&quot;</span>
      </span>
      {modifiers.length > 0 && (
        <span className="text-[10px]" style={{ color: "#6f7f9a" }}>
          {modifiers.join(" ")}
        </span>
      )}
    </div>
  );
}


// ---- Regex Pattern Display ----

function RegexPatternDisplay({ value }: { value: string }) {
  const tokens = tokenizeRegex(value);
  return (
    <div className="font-mono text-[11px] leading-relaxed pt-1 break-all">
      {tokens.map((tok, i) => (
        <span
          key={i}
          style={{
            color: REGEX_TOKEN_COLORS[tok.type] || "#6f7f9a",
            opacity: tok.type === "delimiter" ? 0.4 : 1,
          }}
        >
          {tok.value}
        </span>
      ))}
    </div>
  );
}


// ---- String Display (dispatcher) ----

function StringDisplay({ str }: { str: ParsedYaraString }) {
  const color = stringTypeColor(str.type);
  return (
    <div
      className="border-l-2 pl-3 py-2 hover:bg-[#0b0d13]/40 transition-colors rounded-r"
      style={{ borderLeftColor: color }}
    >
      {/* Header row: variable name, type badge, modifier badges */}
      <div className="flex items-center gap-2 flex-wrap">
        <span
          className="text-[11px] font-semibold font-mono"
          style={{ color: ACCENT }}
        >
          {str.variable}
        </span>
        <StringTypeBadge type={str.type} />
        {str.type !== "text" &&
          str.modifiers.map((mod) => (
            <ModifierBadge key={mod} modifier={mod} />
          ))}
      </div>

      {/* Type-specific value rendering */}
      {str.type === "text" && (
        <TextPatternDisplay value={str.value} modifiers={str.modifiers} />
      )}
      {str.type === "hex" && <HexPatternDisplay value={str.value} />}
      {str.type === "regex" && <RegexPatternDisplay value={str.value} />}
    </div>
  );
}


// ---- Condition Display ----

function tokenizeYaraCondition(condition: string): Token[] {
  const tokens: Token[] = [];
  const keywords = new Set([
    "and", "or", "not", "of", "at", "in", "for", "all", "any", "none",
  ]);
  const builtins = new Set([
    "them", "filesize", "entrypoint", "true", "false",
  ]);

  let i = 0;
  while (i < condition.length) {
    const ch = condition[i];

    // Whitespace — preserve
    if (/\s/.test(ch)) {
      let ws = "";
      while (i < condition.length && /\s/.test(condition[i])) {
        ws += condition[i];
        i++;
      }
      tokens.push({ type: "space", value: ws });
      continue;
    }

    // Parentheses
    if (ch === "(" || ch === ")") {
      tokens.push({ type: "paren", value: ch });
      i++;
      continue;
    }

    // Variable references ($name, $name*, #name, @name)
    if (ch === "$" || ch === "#" || ch === "@") {
      let varName = ch;
      i++;
      while (i < condition.length && /[\w*]/.test(condition[i])) {
        varName += condition[i];
        i++;
      }
      tokens.push({ type: "variable", value: varName });
      continue;
    }

    // Numbers (decimal and hex 0x...)
    if (/\d/.test(ch)) {
      let num = "";
      if (ch === "0" && i + 1 < condition.length && condition[i + 1] === "x") {
        num = "0x";
        i += 2;
        while (i < condition.length && /[\da-fA-F]/.test(condition[i])) {
          num += condition[i];
          i++;
        }
      } else {
        while (i < condition.length && /[\d.]/.test(condition[i])) {
          num += condition[i];
          i++;
        }
        // Handle KB/MB suffixes
        if (i < condition.length && /[KMG]/.test(condition[i])) {
          num += condition[i];
          i++;
          if (i < condition.length && condition[i] === "B") {
            num += condition[i];
            i++;
          }
        }
      }
      tokens.push({ type: "number", value: num });
      continue;
    }

    // Words (identifiers, keywords, builtins)
    if (/[a-zA-Z_]/.test(ch)) {
      let word = "";
      while (i < condition.length && /[\w.]/.test(condition[i])) {
        word += condition[i];
        i++;
      }
      if (keywords.has(word)) {
        tokens.push({ type: "keyword", value: word });
      } else if (builtins.has(word)) {
        tokens.push({ type: "builtin", value: word });
      } else {
        // Could be a module function like pe.is_dll
        tokens.push({ type: "builtin", value: word });
      }
      continue;
    }

    // Operators and other symbols
    tokens.push({ type: "operator", value: ch });
    i++;
  }

  return tokens;
}

const CONDITION_TOKEN_COLORS: Record<string, string> = {
  keyword: "#d4a84b",
  variable: "#e0915c",
  number: "#3dbf84",
  builtin: "#7c9aef",
  paren: "#6f7f9a",
  operator: "#6f7f9a",
  space: "inherit",
};

function ConditionDisplay({ condition }: { condition: string }) {
  const tokens = tokenizeYaraCondition(condition);
  return (
    <div
      className="border-l-2 pl-4 py-3 font-mono text-[12px] leading-[1.8] whitespace-pre-wrap"
      style={{ borderLeftColor: ACCENT }}
    >
      {tokens.map((tok, i) => (
        <span
          key={i}
          style={{ color: CONDITION_TOKEN_COLORS[tok.type] || "#ece7dc" }}
        >
          {tok.value}
        </span>
      ))}
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
      <div className="flex flex-col pb-6">
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
                <StringDisplay key={`${str.variable}-${i}`} str={str} />
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
            <ConditionDisplay condition={rule.condition} />
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

      </div>
    </ScrollArea>
  );
}
