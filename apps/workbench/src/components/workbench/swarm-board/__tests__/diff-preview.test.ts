import { describe, expect, it } from "vitest";

import {
  classifyDiffLine,
  normalizeUnifiedDiffContent,
  parseUnifiedDiffLines,
  summarizeUnifiedDiff,
} from "../diff-preview";

describe("diff-preview helpers", () => {
  it("normalizes CRLF diff content", () => {
    expect(normalizeUnifiedDiffContent("a\r\nb\r\n")).toBe("a\nb");
  });

  it("classifies unified diff lines by role", () => {
    expect(classifyDiffLine("diff --git a/a.ts b/a.ts")).toBe("meta");
    expect(classifyDiffLine("@@ -1,2 +1,3 @@")).toBe("hunk");
    expect(classifyDiffLine("+const added = true;")).toBe("add");
    expect(classifyDiffLine("-const removed = true;")).toBe("remove");
    expect(classifyDiffLine(" const untouched = true;")).toBe("context");
  });

  it("summarizes added, removed, and changed files from a unified diff", () => {
    const summary = summarizeUnifiedDiff(`diff --git a/src/auth.rs b/src/auth.rs
index 1111111..2222222 100644
--- a/src/auth.rs
+++ b/src/auth.rs
@@ -1,2 +1,3 @@
 export const auth = true;
-export const stale = false;
+export const stale = true;
+export const hardened = true;
diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -4,0 +5,1 @@
+serde = "1"`);

    expect(summary).toEqual({
      added: 3,
      removed: 1,
      files: ["src/auth.rs", "Cargo.toml"],
    });
  });

  it("parses line records for preview rendering", () => {
    const lines = parseUnifiedDiffLines(`@@ -1 +1 @@
-old
+new`);

    expect(lines).toEqual([
      { content: "@@ -1 +1 @@", kind: "hunk" },
      { content: "-old", kind: "remove" },
      { content: "+new", kind: "add" },
    ]);
  });
});
