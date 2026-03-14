/**
 * CodeMirror 6 StreamLanguage tokenizer for YARA syntax highlighting.
 *
 * Handles keywords, string variables, string/hex/regex literals,
 * comments (line and block), numbers, rule names, and operators.
 */
import { StreamLanguage, type StreamParser } from "@codemirror/language";

interface YaraState {
  /** Currently inside a block comment */
  inBlockComment: boolean;
  /** Currently inside a hex string { ... } */
  inHexString: boolean;
  /** Currently inside a double-quoted string */
  inString: boolean;
  /** The previous token was the `rule` keyword (next identifier is a rule name) */
  afterRule: boolean;
}

const KEYWORDS = new Set([
  "rule",
  "meta",
  "strings",
  "condition",
  "import",
  "include",
  "private",
  "global",
  "true",
  "false",
  "and",
  "or",
  "not",
  "any",
  "all",
  "of",
  "them",
  "for",
  "in",
  "at",
  "filesize",
  "entrypoint",
  "none",
]);

const yaraParser: StreamParser<YaraState> = {
  startState(): YaraState {
    return {
      inBlockComment: false,
      inHexString: false,
      inString: false,
      afterRule: false,
    };
  },

  token(stream, state): string | null {
    // ---- Block comment continuation ----
    if (state.inBlockComment) {
      const endIdx = stream.string.indexOf("*/", stream.pos);
      if (endIdx === -1) {
        stream.skipToEnd();
      } else {
        stream.pos = endIdx + 2;
        state.inBlockComment = false;
      }
      return "comment";
    }

    // ---- Hex string continuation ----
    if (state.inHexString) {
      while (!stream.eol()) {
        const ch = stream.next();
        if (ch === "}") {
          state.inHexString = false;
          return "string";
        }
      }
      return "string";
    }

    // ---- String literal continuation ----
    if (state.inString) {
      while (!stream.eol()) {
        const ch = stream.next();
        if (ch === "\\") {
          // Skip escaped character
          stream.next();
        } else if (ch === '"') {
          state.inString = false;
          return "string";
        }
      }
      return "string";
    }

    // ---- Skip whitespace ----
    if (stream.eatSpace()) {
      return null;
    }

    // ---- Line comment ----
    if (stream.match("//")) {
      stream.skipToEnd();
      return "comment";
    }

    // ---- Block comment start ----
    if (stream.match("/*")) {
      state.inBlockComment = true;
      const endIdx = stream.string.indexOf("*/", stream.pos);
      if (endIdx === -1) {
        stream.skipToEnd();
      } else {
        stream.pos = endIdx + 2;
        state.inBlockComment = false;
      }
      return "comment";
    }

    // ---- String literal start ----
    if (stream.peek() === '"') {
      stream.next(); // consume opening quote
      while (!stream.eol()) {
        const ch = stream.next();
        if (ch === "\\") {
          stream.next(); // skip escaped char
        } else if (ch === '"') {
          return "string";
        }
      }
      state.inString = true;
      return "string";
    }

    // ---- Regex pattern: /pattern/modifiers ----
    // Only match when / is not preceded by another operator context that would
    // make it ambiguous (simplified: we match /.../ with optional trailing [ismg]*)
    if (stream.peek() === "/") {
      // Attempt to match a regex literal
      const rest = stream.string.slice(stream.pos);
      const rxMatch = rest.match(/^\/(?:[^/\\]|\\.)+\/[ismg]*/);
      if (rxMatch) {
        stream.pos += rxMatch[0].length;
        return "regexp";
      }
    }

    // ---- String variable references: $, #, @, ! followed by identifier ----
    if (
      stream.peek() === "$" ||
      stream.peek() === "#" ||
      stream.peek() === "@" ||
      stream.peek() === "!"
    ) {
      const prefix = stream.next();
      // Eat optional identifier characters
      if (stream.match(/^[a-zA-Z_][a-zA-Z0-9_]*/)) {
        return "variableName";
      }
      // Bare sigil (e.g. `$` alone in conditions)
      if (prefix === "$") return "variableName";
      return null;
    }

    // ---- Hex string start { ----
    // Hex strings in YARA use { XX XX ?? } syntax.
    // We need to distinguish hex strings from rule body braces.
    // Heuristic: a `{` that follows content on the same line that looks like
    // hex bytes is a hex string, OR we defer to a simpler approach: track
    // that after `=` on the strings line a `{` starts a hex literal.
    // For simplicity, we check if the content after `{` looks hex-ish.
    if (stream.peek() === "{") {
      const rest = stream.string.slice(stream.pos + 1).trimStart();
      // If what follows looks like hex digits, wildcards, or whitespace,
      // treat as hex string. Rule-body braces will have keywords/identifiers.
      if (/^[0-9a-fA-F?(\[\]\-|\s)]+/.test(rest) && rest.length > 0 && !/^$/.test(rest)) {
        // Check more carefully: must have at least one hex pair or wildcard
        if (/[0-9a-fA-F]{2}|\?\?/.test(rest)) {
          stream.next(); // consume {
          state.inHexString = true;
          // Try to find closing brace on same line
          while (!stream.eol()) {
            const ch = stream.next();
            if (ch === "}") {
              state.inHexString = false;
              return "string";
            }
          }
          return "string";
        }
      }
    }

    // ---- Numbers: hex (0x...) and decimal ----
    if (stream.match(/^0x[0-9a-fA-F]+/)) {
      return "number";
    }
    if (stream.match(/^[0-9]+(\.[0-9]+)?/)) {
      return "number";
    }

    // ---- Operators and punctuation ----
    const opCh = stream.peek();
    if (opCh && "=<>(){}:".includes(opCh)) {
      stream.next();
      // Consume == or !=
      if ((opCh === "=" || opCh === "!" || opCh === "<" || opCh === ">") && stream.peek() === "=") {
        stream.next();
      }
      return "operator";
    }

    // ---- Identifiers and keywords ----
    if (stream.match(/^[a-zA-Z_][a-zA-Z0-9_]*/)) {
      const word = stream.current();

      // Section keywords with colon (e.g. `meta:`, `strings:`, `condition:`)
      // The colon was already consumed as a separate token in some cases,
      // but if the word itself is a section keyword, mark it.
      if (word === "meta" || word === "strings" || word === "condition") {
        // Peek for colon
        if (stream.peek() === ":") {
          stream.next(); // consume the colon as part of the keyword token
          state.afterRule = false;
          return "keyword";
        }
      }

      // If previous token was `rule`, this is a rule name
      if (state.afterRule) {
        state.afterRule = false;
        return "typeName";
      }

      // Check if keyword
      if (KEYWORDS.has(word)) {
        if (word === "rule") {
          state.afterRule = true;
        }
        return "keyword";
      }

      // Regular identifier
      return null;
    }

    // ---- Fallback: consume one character ----
    stream.next();
    return null;
  },
};

export const yaraLanguage = StreamLanguage.define(yaraParser);
