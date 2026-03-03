export interface DiffLine {
  type: "added" | "removed" | "unchanged";
  content: string;
  lineNumber: number;
}

export interface DiffResult {
  left: DiffLine[];
  right: DiffLine[];
}

/**
 * Compute a line-by-line diff between two text blocks using a simple LCS approach.
 */
export function diffLines(oldText: string, newText: string): DiffResult {
  const oldLines = oldText.split("\n");
  const newLines = newText.split("\n");

  const lcs = computeLCS(oldLines, newLines);

  const left: DiffLine[] = [];
  const right: DiffLine[] = [];

  let oi = 0;
  let ni = 0;
  let li = 0;

  while (oi < oldLines.length || ni < newLines.length) {
    if (
      li < lcs.length &&
      oi < oldLines.length &&
      ni < newLines.length &&
      oldLines[oi] === lcs[li] &&
      newLines[ni] === lcs[li]
    ) {
      left.push({ type: "unchanged", content: oldLines[oi], lineNumber: oi + 1 });
      right.push({ type: "unchanged", content: newLines[ni], lineNumber: ni + 1 });
      oi++;
      ni++;
      li++;
    } else if (li < lcs.length && oi < oldLines.length && oldLines[oi] !== lcs[li]) {
      left.push({ type: "removed", content: oldLines[oi], lineNumber: oi + 1 });
      oi++;
    } else if (li < lcs.length && ni < newLines.length && newLines[ni] !== lcs[li]) {
      right.push({ type: "added", content: newLines[ni], lineNumber: ni + 1 });
      ni++;
    } else if (li >= lcs.length && oi < oldLines.length) {
      left.push({ type: "removed", content: oldLines[oi], lineNumber: oi + 1 });
      oi++;
    } else if (li >= lcs.length && ni < newLines.length) {
      right.push({ type: "added", content: newLines[ni], lineNumber: ni + 1 });
      ni++;
    } else {
      break;
    }
  }

  return { left, right };
}

function computeLCS(a: string[], b: string[]): string[] {
  const m = a.length;
  const n = b.length;

  // For large files, use a simplified approach to avoid excessive memory
  if (m * n > 1_000_000) {
    return simpleLCS(a, b);
  }

  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const result: string[] = [];
  let i = m;
  let j = n;
  while (i > 0 && j > 0) {
    if (a[i - 1] === b[j - 1]) {
      result.unshift(a[i - 1]);
      i--;
      j--;
    } else if (dp[i - 1][j] >= dp[i][j - 1]) {
      i--;
    } else {
      j--;
    }
  }

  return result;
}

/** Fallback for large files: greedy sequential match. */
function simpleLCS(a: string[], b: string[]): string[] {
  const result: string[] = [];
  let j = 0;
  for (let i = 0; i < a.length && j < b.length; i++) {
    if (a[i] === b[j]) {
      result.push(a[i]);
      j++;
    } else {
      const nextJ = b.indexOf(a[i], j);
      if (nextJ >= 0 && nextJ - j < 10) {
        result.push(a[i]);
        j = nextJ + 1;
      }
    }
  }
  return result;
}
