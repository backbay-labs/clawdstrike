export type DiffLineKind = "meta" | "hunk" | "add" | "remove" | "context";

export interface ParsedDiffLine {
  content: string;
  kind: DiffLineKind;
}

export interface UnifiedDiffSummary {
  added: number;
  removed: number;
  files: string[];
}

export function normalizeUnifiedDiffContent(content: string): string {
  return content.replace(/\r\n?/g, "\n").trimEnd();
}

export function classifyDiffLine(line: string): DiffLineKind {
  if (
    line.startsWith("diff --git ") ||
    line.startsWith("index ") ||
    line.startsWith("--- ") ||
    line.startsWith("+++ ") ||
    line.startsWith("new file mode ") ||
    line.startsWith("deleted file mode ") ||
    line.startsWith("similarity index ") ||
    line.startsWith("rename from ") ||
    line.startsWith("rename to ")
  ) {
    return "meta";
  }

  if (line.startsWith("@@")) {
    return "hunk";
  }

  if (line.startsWith("+")) {
    return "add";
  }

  if (line.startsWith("-")) {
    return "remove";
  }

  return "context";
}

function normalizeDiffFilePath(filePath: string): string {
  if (filePath === "/dev/null") {
    return filePath;
  }

  return filePath.replace(/^[ab]\//, "");
}

function pushDiffFile(files: Set<string>, filePath: string): void {
  const normalized = normalizeDiffFilePath(filePath.trim());
  if (normalized.length === 0 || normalized === "/dev/null") {
    return;
  }
  files.add(normalized);
}

export function parseUnifiedDiffLines(content: string): ParsedDiffLine[] {
  return normalizeUnifiedDiffContent(content)
    .split("\n")
    .map((line) => ({
      content: line,
      kind: classifyDiffLine(line),
    }));
}

export function summarizeUnifiedDiff(content: string): UnifiedDiffSummary {
  const normalized = normalizeUnifiedDiffContent(content);
  if (normalized.length === 0) {
    return { added: 0, removed: 0, files: [] };
  }

  let added = 0;
  let removed = 0;
  const files = new Set<string>();

  for (const line of normalized.split("\n")) {
    if (line.startsWith("diff --git ")) {
      const match = line.match(/^diff --git a\/(.+?) b\/(.+)$/);
      if (match) {
        pushDiffFile(files, match[2]);
      }
      continue;
    }

    if (line.startsWith("+++ ")) {
      pushDiffFile(files, line.slice(4));
      continue;
    }

    const kind = classifyDiffLine(line);
    if (kind === "add") {
      added += 1;
    } else if (kind === "remove") {
      removed += 1;
    }
  }

  return {
    added,
    removed,
    files: Array.from(files),
  };
}
