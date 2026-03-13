import { useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";

interface YamlDiffViewProps {
  yamlA: string;
  yamlB: string;
}

interface DiffLine {
  lineNum: number | null;
  text: string;
  type: "same" | "added" | "removed" | "empty";
}

/**
 * Simple line-by-line diff using longest common subsequence.
 * Returns aligned left/right line pairs for side-by-side display.
 */
function computeDiff(
  linesA: string[],
  linesB: string[]
): { left: DiffLine[]; right: DiffLine[] } {
  const m = linesA.length;
  const n = linesB.length;

  // Build LCS table
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array(n + 1).fill(0)
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (linesA[i - 1] === linesB[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack to build diff
  const left: DiffLine[] = [];
  const right: DiffLine[] = [];

  let i = m;
  let j = n;

  const result: Array<{ type: "same" | "removed" | "added"; aIdx?: number; bIdx?: number }> = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && linesA[i - 1] === linesB[j - 1]) {
      result.push({ type: "same", aIdx: i - 1, bIdx: j - 1 });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      result.push({ type: "added", bIdx: j - 1 });
      j--;
    } else {
      result.push({ type: "removed", aIdx: i - 1 });
      i--;
    }
  }

  result.reverse();

  for (const entry of result) {
    if (entry.type === "same") {
      left.push({
        lineNum: entry.aIdx! + 1,
        text: linesA[entry.aIdx!],
        type: "same",
      });
      right.push({
        lineNum: entry.bIdx! + 1,
        text: linesB[entry.bIdx!],
        type: "same",
      });
    } else if (entry.type === "removed") {
      left.push({
        lineNum: entry.aIdx! + 1,
        text: linesA[entry.aIdx!],
        type: "removed",
      });
      right.push({ lineNum: null, text: "", type: "empty" });
    } else {
      left.push({ lineNum: null, text: "", type: "empty" });
      right.push({
        lineNum: entry.bIdx! + 1,
        text: linesB[entry.bIdx!],
        type: "added",
      });
    }
  }

  return { left, right };
}

function DiffColumn({
  lines,
  label,
}: {
  lines: DiffLine[];
  label: string;
}) {
  return (
    <div className="flex-1 min-w-0 flex flex-col">
      <div className="shrink-0 px-3 py-2 border-b border-[#2d3240] bg-[#131721]">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
          {label}
        </span>
      </div>
      <ScrollArea className="flex-1">
        <div className="font-mono text-xs leading-5">
          {lines.map((line, idx) => {
            let bg = "transparent";
            if (line.type === "removed") bg = "#c45c5c15";
            else if (line.type === "added") bg = "#3dbf8415";

            return (
              <div
                key={idx}
                className="flex min-h-[20px]"
                style={{ backgroundColor: bg }}
              >
                <span className="shrink-0 w-10 text-right pr-2 select-none text-[#6f7f9a]/50">
                  {line.lineNum ?? ""}
                </span>
                <span className="flex-1 pr-2 whitespace-pre text-[#ece7dc]">
                  {line.text}
                </span>
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}

export function YamlDiffView({ yamlA, yamlB }: YamlDiffViewProps) {
  const { left, right } = useMemo(() => {
    const linesA = yamlA.split("\n");
    const linesB = yamlB.split("\n");
    return computeDiff(linesA, linesB);
  }, [yamlA, yamlB]);

  if (!yamlA && !yamlB) {
    return (
      <div className="flex items-center justify-center h-full text-[#6f7f9a] text-sm">
        Select two policies above to compare their YAML
      </div>
    );
  }

  return (
    <div className="flex h-full border border-[#2d3240] rounded-lg overflow-hidden">
      <DiffColumn lines={left} label="Policy A" />
      <div className="w-px bg-[#2d3240] shrink-0" />
      <DiffColumn lines={right} label="Policy B" />
    </div>
  );
}
