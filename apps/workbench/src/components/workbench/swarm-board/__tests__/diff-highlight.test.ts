import { describe, expect, it } from "vitest";

import {
  resolveParser,
  highlightLine,
  extractDiffFilePath,
  groupDiffByFile,
  type HighlightedToken,
  type DiffHunkGroup,
} from "../diff-highlight";
import { SYNTAX_COLORS } from "../codemirror-theme";
import { diffHighlightStyle } from "../codemirror-theme";
import type { ParsedDiffLine } from "../diff-preview";

describe("resolveParser", () => {
  it("resolves a Rust parser for .rs files", async () => {
    const parser = await resolveParser("src/auth.rs");
    expect(parser).not.toBeNull();
  });

  it("resolves a parser for .tsx files", async () => {
    const parser = await resolveParser("src/app.tsx");
    expect(parser).not.toBeNull();
  });

  it("resolves a parser for .yaml files", async () => {
    const parser = await resolveParser("config.yaml");
    expect(parser).not.toBeNull();
  });

  it("resolves a parser for .json files", async () => {
    const parser = await resolveParser("data.json");
    expect(parser).not.toBeNull();
  });

  it("resolves a parser for .py files", async () => {
    const parser = await resolveParser("script.py");
    expect(parser).not.toBeNull();
  });

  it("returns null for unsupported extensions like .md", async () => {
    const parser = await resolveParser("README.md");
    expect(parser).toBeNull();
  });

  it("returns null for files with no extension", async () => {
    const parser = await resolveParser("Makefile");
    expect(parser).toBeNull();
  });
});

describe("extractDiffFilePath", () => {
  it("extracts path from 'diff --git a/... b/...' meta line", () => {
    const lines: ParsedDiffLine[] = [
      { content: "diff --git a/src/auth.rs b/src/auth.rs", kind: "meta" },
      { content: "index 1111111..2222222 100644", kind: "meta" },
      { content: "--- a/src/auth.rs", kind: "meta" },
      { content: "+++ b/src/auth.rs", kind: "meta" },
      { content: "@@ -1,2 +1,3 @@", kind: "hunk" },
      { content: "+const x = 1;", kind: "add" },
    ];
    expect(extractDiffFilePath(lines)).toBe("src/auth.rs");
  });

  it("extracts path from '+++ b/...' when no 'diff --git' line present", () => {
    const lines: ParsedDiffLine[] = [
      { content: "--- a/src/auth.rs", kind: "meta" },
      { content: "+++ b/src/auth.rs", kind: "meta" },
      { content: "@@ -1,2 +1,3 @@", kind: "hunk" },
      { content: "+const x = 1;", kind: "add" },
    ];
    expect(extractDiffFilePath(lines)).toBe("src/auth.rs");
  });

  it("returns null when no meta lines have file paths", () => {
    const lines: ParsedDiffLine[] = [
      { content: "@@ -1,2 +1,3 @@", kind: "hunk" },
      { content: "+const x = 1;", kind: "add" },
      { content: "-const y = 2;", kind: "remove" },
    ];
    expect(extractDiffFilePath(lines)).toBeNull();
  });
});

describe("groupDiffByFile", () => {
  it("splits a multi-file diff into separate groups with correct filePaths", () => {
    const lines: ParsedDiffLine[] = [
      { content: "diff --git a/src/auth.rs b/src/auth.rs", kind: "meta" },
      { content: "@@ -1,2 +1,3 @@", kind: "hunk" },
      { content: "+use serde;", kind: "add" },
      { content: "diff --git a/Cargo.toml b/Cargo.toml", kind: "meta" },
      { content: "@@ -4,0 +5,1 @@", kind: "hunk" },
      { content: '+serde = "1"', kind: "add" },
    ];
    const groups = groupDiffByFile(lines);
    expect(groups).toHaveLength(2);
    expect(groups[0].filePath).toBe("src/auth.rs");
    expect(groups[0].lines).toHaveLength(3);
    expect(groups[1].filePath).toBe("Cargo.toml");
    expect(groups[1].lines).toHaveLength(3);
  });

  it("returns single group for single-file diff", () => {
    const lines: ParsedDiffLine[] = [
      { content: "diff --git a/src/main.rs b/src/main.rs", kind: "meta" },
      { content: "@@ -1 +1 @@", kind: "hunk" },
      { content: "-old", kind: "remove" },
      { content: "+new", kind: "add" },
    ];
    const groups = groupDiffByFile(lines);
    expect(groups).toHaveLength(1);
    expect(groups[0].filePath).toBe("src/main.rs");
    expect(groups[0].lines).toHaveLength(4);
  });
});

describe("highlightLine", () => {
  it("produces tokens array with prefix and code tokens for a JSON line", async () => {
    const { jsonLanguage } = await import("@codemirror/lang-json");
    const parser = jsonLanguage.parser;

    const tokens = highlightLine('+{ "key": "value" }', parser, diffHighlightStyle);
    expect(tokens.length).toBeGreaterThanOrEqual(2);
    // First token is the diff prefix
    expect(tokens[0].text).toBe("+");
    expect(tokens[0].className).toBe("");
  });

  it("prefix token text is '+' for add lines", async () => {
    const { jsonLanguage } = await import("@codemirror/lang-json");
    const tokens = highlightLine('+"hello"', jsonLanguage.parser, diffHighlightStyle);
    expect(tokens[0].text).toBe("+");
  });

  it("prefix token text is '-' for remove lines", async () => {
    const { jsonLanguage } = await import("@codemirror/lang-json");
    const tokens = highlightLine('-"hello"', jsonLanguage.parser, diffHighlightStyle);
    expect(tokens[0].text).toBe("-");
  });

  it("prefix token text is ' ' for context lines", async () => {
    const { jsonLanguage } = await import("@codemirror/lang-json");
    const tokens = highlightLine(' "hello"', jsonLanguage.parser, diffHighlightStyle);
    expect(tokens[0].text).toBe(" ");
  });
});

describe("SYNTAX_COLORS", () => {
  it("contains entries for keyword, string, number, comment", () => {
    expect(SYNTAX_COLORS).toHaveProperty("keyword");
    expect(SYNTAX_COLORS).toHaveProperty("string");
    expect(SYNTAX_COLORS).toHaveProperty("number");
    expect(SYNTAX_COLORS).toHaveProperty("comment");
  });
});
