import type { Parser } from "@lezer/common";
import { highlightCode } from "@lezer/highlight";
import type { HighlightStyle } from "@codemirror/language";
import type { ParsedDiffLine } from "./diff-preview";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HighlightedToken {
  text: string;
  className: string;
}

export interface DiffHunkGroup {
  filePath: string | null;
  lines: ParsedDiffLine[];
}

// ---------------------------------------------------------------------------
// Language resolution
// ---------------------------------------------------------------------------

type LanguageLoader = () => Promise<Parser>;

const LANGUAGE_MAP: Record<string, LanguageLoader> = {
  rs: () => import("@codemirror/lang-rust").then((m) => m.rustLanguage.parser),
  ts: () =>
    import("@codemirror/lang-javascript").then((m) => m.tsxLanguage.parser),
  tsx: () =>
    import("@codemirror/lang-javascript").then((m) => m.tsxLanguage.parser),
  mts: () =>
    import("@codemirror/lang-javascript").then((m) => m.tsxLanguage.parser),
  cts: () =>
    import("@codemirror/lang-javascript").then((m) => m.tsxLanguage.parser),
  js: () =>
    import("@codemirror/lang-javascript").then((m) => m.jsxLanguage.parser),
  jsx: () =>
    import("@codemirror/lang-javascript").then((m) => m.jsxLanguage.parser),
  mjs: () =>
    import("@codemirror/lang-javascript").then((m) => m.jsxLanguage.parser),
  cjs: () =>
    import("@codemirror/lang-javascript").then((m) => m.jsxLanguage.parser),
  json: () =>
    import("@codemirror/lang-json").then((m) => m.jsonLanguage.parser),
  yaml: () =>
    import("@codemirror/lang-yaml").then((m) => m.yamlLanguage.parser),
  yml: () =>
    import("@codemirror/lang-yaml").then((m) => m.yamlLanguage.parser),
  py: () =>
    import("@codemirror/lang-python").then((m) => m.pythonLanguage.parser),
};

const parserCache = new Map<string, Parser>();

/**
 * Resolve a Lezer parser for the given file path based on its extension.
 * Results are cached so subsequent calls for the same extension are synchronous.
 * Returns `null` for unsupported or extensionless paths.
 */
export async function resolveParser(
  filePath: string,
): Promise<Parser | null> {
  const ext = filePath.split(".").pop()?.toLowerCase();
  if (!ext || ext === filePath.toLowerCase()) return null;

  const cached = parserCache.get(ext);
  if (cached) return cached;

  const loader = LANGUAGE_MAP[ext];
  if (!loader) return null;

  const parser = await loader();
  parserCache.set(ext, parser);
  return parser;
}

// ---------------------------------------------------------------------------
// Diff metadata helpers
// ---------------------------------------------------------------------------

/**
 * Extract the file path from a group of parsed diff lines.
 * Tries `diff --git a/... b/...` first, then falls back to `+++ b/...`.
 */
export function extractDiffFilePath(
  lines: ParsedDiffLine[],
): string | null {
  for (const line of lines) {
    if (line.kind !== "meta") continue;

    const gitMatch = line.content.match(
      /^diff --git a\/(.+?) b\/(.+)$/,
    );
    if (gitMatch) return gitMatch[2];
  }

  // Fallback: scan for "+++ b/path"
  for (const line of lines) {
    if (line.kind !== "meta") continue;
    if (
      line.content.startsWith("+++ ") &&
      !line.content.startsWith("+++ /dev/null")
    ) {
      return line.content.slice(4).replace(/^[ab]\//, "");
    }
  }

  return null;
}

/**
 * Split parsed diff lines into per-file groups, delimited by `diff --git` lines.
 * Each group carries the resolved file path (or null if the header is absent).
 */
export function groupDiffByFile(
  lines: ParsedDiffLine[],
): DiffHunkGroup[] {
  const groups: DiffHunkGroup[] = [];
  let current: DiffHunkGroup = { filePath: null, lines: [] };

  for (const line of lines) {
    if (line.content.startsWith("diff --git ")) {
      if (current.lines.length > 0) groups.push(current);
      const match = line.content.match(
        /^diff --git a\/(.+?) b\/(.+)$/,
      );
      current = { filePath: match?.[2] ?? null, lines: [line] };
    } else {
      current.lines.push(line);
    }
  }

  if (current.lines.length > 0) groups.push(current);
  return groups;
}

// ---------------------------------------------------------------------------
// Line-level syntax tokenization
// ---------------------------------------------------------------------------

/**
 * Tokenize a single diff line using Lezer's `highlightCode`.
 *
 * The leading character (diff prefix: `+`, `-`, or ` `) is split into its own
 * token with an empty `className` so the caller can style it via diff-line kind.
 * Subsequent tokens carry the syntax class name from the provided HighlightStyle.
 */
export function highlightLine(
  lineContent: string,
  parser: Parser,
  style: HighlightStyle,
): HighlightedToken[] {
  const prefix = lineContent.length > 0 ? lineContent[0] : "";
  const codeContent = lineContent.length > 0 ? lineContent.slice(1) : "";

  const tokens: HighlightedToken[] = [{ text: prefix, className: "" }];

  highlightCode(
    codeContent,
    parser.parse(codeContent),
    style,
    (text: string, classes: string) => {
      tokens.push({ text, className: classes });
    },
    () => {
      // Single-line tokenization -- line-break callback is a no-op
    },
  );

  return tokens;
}
