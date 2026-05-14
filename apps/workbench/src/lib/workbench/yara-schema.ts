import type { Completion, CompletionContext, CompletionResult, CompletionSource } from "@codemirror/autocomplete";

// YARA autocomplete completion source for CodeMirror 6
// Provides keyword, modifier, condition operator, module, and meta field completions.

/** A completion option with label, insert text, and description. */
interface YaraOption {
  label: string;
  /** Text to insert. Defaults to label. */
  apply?: string;
  /** Type hint for the completion widget. */
  type?: string;
  /** Description shown alongside the completion. */
  detail?: string;
}

// ---- YARA keywords ----

const KEYWORD_OPTIONS: YaraOption[] = [
  { label: "rule", apply: "rule ", type: "keyword", detail: "define a rule" },
  { label: "meta", apply: "meta:", type: "keyword", detail: "metadata section" },
  { label: "strings", apply: "strings:", type: "keyword", detail: "strings section" },
  { label: "condition", apply: "condition:", type: "keyword", detail: "condition section" },
  { label: "import", apply: "import ", type: "keyword", detail: "import module" },
  { label: "include", apply: "include ", type: "keyword", detail: "include file" },
  { label: "private", apply: "private ", type: "keyword", detail: "private rule modifier" },
  { label: "global", apply: "global ", type: "keyword", detail: "global rule modifier" },
];

// ---- String modifiers ----

const STRING_MODIFIER_OPTIONS: YaraOption[] = [
  { label: "ascii", type: "keyword", detail: "ASCII encoding" },
  { label: "wide", type: "keyword", detail: "UTF-16 encoding" },
  { label: "nocase", type: "keyword", detail: "case-insensitive match" },
  { label: "fullword", type: "keyword", detail: "full word boundary match" },
  { label: "xor", type: "keyword", detail: "XOR-encoded match" },
  { label: "base64", type: "keyword", detail: "base64-encoded match" },
];

// ---- Condition operators ----

const CONDITION_OPERATOR_OPTIONS: YaraOption[] = [
  { label: "all", type: "keyword", detail: "all strings must match" },
  { label: "any", type: "keyword", detail: "any string matches" },
  { label: "none", type: "keyword", detail: "no strings match" },
  { label: "of", type: "keyword", detail: "quantifier operator" },
  { label: "them", type: "keyword", detail: "reference all strings" },
  { label: "at", type: "keyword", detail: "match at offset" },
  { label: "in", type: "keyword", detail: "match within range" },
  { label: "for", type: "keyword", detail: "loop quantifier" },
  { label: "filesize", type: "keyword", detail: "file size variable" },
  { label: "entrypoint", type: "keyword", detail: "PE/ELF entry point" },
];

// ---- Common modules ----

const MODULE_OPTIONS: YaraOption[] = [
  { label: "pe", apply: '"pe"', type: "module", detail: "PE file analysis" },
  { label: "elf", apply: '"elf"', type: "module", detail: "ELF file analysis" },
  { label: "math", apply: '"math"', type: "module", detail: "mathematical functions" },
  { label: "hash", apply: '"hash"', type: "module", detail: "hash functions" },
  { label: "cuckoo", apply: '"cuckoo"', type: "module", detail: "Cuckoo sandbox results" },
  { label: "magic", apply: '"magic"', type: "module", detail: "file type magic" },
  { label: "dotnet", apply: '"dotnet"', type: "module", detail: ".NET assembly analysis" },
];

// ---- Meta fields ----

const META_FIELD_OPTIONS: YaraOption[] = [
  { label: "author", apply: "author = ", type: "property", detail: "rule author" },
  { label: "description", apply: "description = ", type: "property", detail: "rule description" },
  { label: "reference", apply: "reference = ", type: "property", detail: "reference URL" },
  { label: "date", apply: "date = ", type: "property", detail: "creation date" },
  { label: "hash", apply: "hash = ", type: "property", detail: "sample hash" },
  { label: "tlp", apply: "tlp = ", type: "property", detail: "Traffic Light Protocol" },
];

// ---- Section detection ----

type YaraSection = "top" | "meta" | "strings" | "condition" | "import";

/**
 * Determine the YARA section the cursor is currently inside by walking
 * backwards through lines looking for section headers or `rule` keywords.
 */
function detectSection(ctx: CompletionContext): YaraSection {
  const { state, pos } = ctx;
  const curLine = state.doc.lineAt(pos);

  for (let i = curLine.number; i >= 1; i--) {
    const lineText = state.doc.line(i).text.trim();

    if (/^condition\s*:/.test(lineText)) return "condition";
    if (/^strings\s*:/.test(lineText)) return "strings";
    if (/^meta\s*:/.test(lineText)) return "meta";
    if (/^import\b/.test(lineText)) return "import";
    // If we reach a `rule` declaration, we are at the top of a rule body
    if (/^(private\s+|global\s+)*rule\s+/.test(lineText)) return "top";
  }

  return "top";
}

/** Convert a YaraOption to a CodeMirror Completion object. */
function toCompletion(opt: YaraOption, sectionLabel?: string): Completion {
  const c: Completion = {
    label: opt.label,
    type: opt.type ?? "text",
    detail: opt.detail,
    boost: 0,
  };
  if (opt.apply) {
    c.apply = opt.apply;
  }
  if (sectionLabel) {
    c.section = sectionLabel;
  }
  return c;
}

/**
 * CodeMirror completion source for YARA rule files.
 *
 * Uses simple section detection to offer context-appropriate completions:
 * - Top level / between rules: keywords (rule, import, include, private, global)
 * - After `import`: module names
 * - Inside `meta:` section: meta fields (author, description, etc.)
 * - Inside `strings:` section: string modifiers (ascii, wide, nocase, etc.)
 * - Inside `condition:` section: condition operators (all, any, of, them, etc.)
 */
export const yaraCompletionSource: CompletionSource = (
  ctx: CompletionContext,
): CompletionResult | null => {
  // Don't trigger on delete or if explicitly cancelled
  if (!ctx.explicit && !ctx.matchBefore(/\w+/)) return null;

  const line = ctx.state.doc.lineAt(ctx.pos);
  const textBefore = line.text.slice(0, ctx.pos - line.from);

  // Determine the start of the word being typed
  const wordMatch = textBefore.match(/(\w+)$/);
  const prefix = wordMatch ? wordMatch[1] : "";
  const from = ctx.pos - prefix.length;

  // Check for `import` on the current line -> module completions
  if (/^\s*import\s+/.test(textBefore)) {
    return {
      from,
      options: MODULE_OPTIONS.map((o) => toCompletion(o, "Modules")),
      filter: true,
    };
  }

  const section = detectSection(ctx);

  switch (section) {
    case "meta":
      return {
        from,
        options: META_FIELD_OPTIONS.map((o) => toCompletion(o, "Meta Fields")),
        filter: true,
      };

    case "strings":
      return {
        from,
        options: STRING_MODIFIER_OPTIONS.map((o) => toCompletion(o, "String Modifiers")),
        filter: true,
      };

    case "condition":
      return {
        from,
        options: CONDITION_OPERATOR_OPTIONS.map((o) => toCompletion(o, "Condition")),
        filter: true,
      };

    case "import":
      return {
        from,
        options: MODULE_OPTIONS.map((o) => toCompletion(o, "Modules")),
        filter: true,
      };

    case "top":
    default:
      return {
        from,
        options: KEYWORD_OPTIONS.map((o) => toCompletion(o, "YARA")),
        filter: true,
      };
  }
};
