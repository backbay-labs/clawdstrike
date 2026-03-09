import { useState, useMemo, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  IconGitCompare,
  IconArrowBackUp,
  IconPlus,
  IconMinus,
  IconArrowsExchange,
} from "@tabler/icons-react";
import { diffVersions, compactChangeSummary, type VersionDiff, type VersionChange } from "@/lib/workbench/version-diff";
import type { PolicyVersion } from "@/lib/workbench/version-store";
import type { WorkbenchPolicy } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";

// ---- Types ----

interface VersionDiffDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  versions: PolicyVersion[];
  currentPolicy: WorkbenchPolicy;
  currentYaml: string;
  initialFromId?: string;
  initialToId?: string;
  onRollback: (version: PolicyVersion) => void;
}

type DiffViewMode = "semantic" | "yaml";

// ---- YAML line diff (inline from yaml-diff-view patterns) ----

interface DiffLine {
  text: string;
  type: "same" | "added" | "removed";
}

function computeUnifiedDiff(linesA: string[], linesB: string[]): DiffLine[] {
  const m = linesA.length;
  const n = linesB.length;

  // LCS
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (linesA[i - 1] === linesB[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  let i = m;
  let j = n;
  const temp: DiffLine[] = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && linesA[i - 1] === linesB[j - 1]) {
      temp.push({ text: linesA[i - 1], type: "same" });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      temp.push({ text: linesB[j - 1], type: "added" });
      j--;
    } else {
      temp.push({ text: linesA[i - 1], type: "removed" });
      i--;
    }
  }

  temp.reverse();
  return temp;
}

// ---- Component ----

export function VersionDiffDialog({
  open,
  onOpenChange,
  versions,
  currentPolicy,
  currentYaml,
  initialFromId,
  initialToId,
  onRollback,
}: VersionDiffDialogProps) {
  const [fromId, setFromId] = useState(initialFromId ?? "");
  const [toId, setToId] = useState(initialToId ?? "");
  const [viewMode, setViewMode] = useState<DiffViewMode>("semantic");

  // Update from/to when initialFromId/initialToId change
  useEffect(() => {
    if (initialFromId) setFromId(initialFromId);
    if (initialToId) setToId(initialToId);
  }, [initialFromId, initialToId]);

  // Build selection options: all versions + "current"
  const options = useMemo(() => {
    const items = versions.map((v) => ({
      id: v.id,
      label: `v${v.version}${v.tags.length > 0 ? ` [${v.tags.join(", ")}]` : ""}`,
      version: v,
    }));
    items.unshift({
      id: "__current__",
      label: "Current (unsaved)",
      version: null as unknown as PolicyVersion,
    });
    return items;
  }, [versions]);

  // Resolve policies from selection
  const fromVersion = useMemo(
    () => versions.find((v) => v.id === fromId) ?? null,
    [versions, fromId],
  );
  const toVersion = useMemo(
    () => versions.find((v) => v.id === toId) ?? null,
    [versions, toId],
  );

  const fromPolicy = fromId === "__current__" ? currentPolicy : fromVersion?.policy ?? null;
  const toPolicy = toId === "__current__" ? currentPolicy : toVersion?.policy ?? null;
  const fromYaml = fromId === "__current__" ? currentYaml : fromVersion?.yaml ?? "";
  const toYaml = toId === "__current__" ? currentYaml : toVersion?.yaml ?? "";

  // Compute diff
  const diff = useMemo<VersionDiff | null>(() => {
    if (!fromPolicy || !toPolicy) return null;
    return diffVersions(
      fromPolicy,
      toPolicy,
      fromVersion?.version ?? 0,
      toVersion?.version ?? 0,
    );
  }, [fromPolicy, toPolicy, fromVersion, toVersion]);

  // YAML diff lines
  const yamlDiffLines = useMemo(() => {
    if (!fromYaml && !toYaml) return [];
    return computeUnifiedDiff(fromYaml.split("\n"), toYaml.split("\n"));
  }, [fromYaml, toYaml]);

  const canRollback = toVersion !== null && toId !== "__current__";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="!max-w-3xl !w-[90vw] bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] max-h-[80vh] flex flex-col"
        showCloseButton
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm text-[#ece7dc]">
            <IconGitCompare size={16} stroke={1.5} className="text-[#d4a84b]" />
            Compare Versions
          </DialogTitle>
          <DialogDescription className="text-[#6f7f9a] text-xs">
            Select two versions to compare their differences
          </DialogDescription>
        </DialogHeader>

        {/* Version selectors */}
        <div className="flex items-center gap-3 py-2">
          <div className="flex-1">
            <label className="text-[9px] font-mono uppercase text-[#6f7f9a] mb-1 block">
              From (older)
            </label>
            <Select
              value={fromId || undefined}
              onValueChange={(val) => setFromId(val as string)}
            >
              <SelectTrigger className="w-full h-7 text-[10px] font-mono bg-[#131721] border-[#2d3240] text-[#ece7dc]">
                <SelectValue placeholder="Select version..." />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {options.map((opt) => (
                  <SelectItem
                    key={opt.id}
                    value={opt.id}
                    className="text-[10px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <IconArrowsExchange size={14} stroke={1.5} className="text-[#6f7f9a] mt-4 shrink-0" />

          <div className="flex-1">
            <label className="text-[9px] font-mono uppercase text-[#6f7f9a] mb-1 block">
              To (newer)
            </label>
            <Select
              value={toId || undefined}
              onValueChange={(val) => setToId(val as string)}
            >
              <SelectTrigger className="w-full h-7 text-[10px] font-mono bg-[#131721] border-[#2d3240] text-[#ece7dc]">
                <SelectValue placeholder="Select version..." />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {options.map((opt) => (
                  <SelectItem
                    key={opt.id}
                    value={opt.id}
                    className="text-[10px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    {opt.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* View mode toggle */}
        <div className="flex items-center gap-2 border-b border-[#2d3240] pb-2">
          <button
            type="button"
            onClick={() => setViewMode("semantic")}
            className={cn(
              "px-2.5 py-1 text-[9px] font-mono rounded transition-colors",
              viewMode === "semantic"
                ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent",
            )}
          >
            Semantic
          </button>
          <button
            type="button"
            onClick={() => setViewMode("yaml")}
            className={cn(
              "px-2.5 py-1 text-[9px] font-mono rounded transition-colors",
              viewMode === "yaml"
                ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent",
            )}
          >
            YAML
          </button>

          {diff && (
            <span className="ml-auto text-[9px] font-mono text-[#6f7f9a]/60">
              {compactChangeSummary(diff.changes)}
            </span>
          )}
        </div>

        {/* Diff content */}
        <ScrollArea className="flex-1 min-h-0 max-h-[50vh]">
          {!diff && (
            <div className="flex items-center justify-center py-16 text-[#6f7f9a] text-xs">
              Select two versions above to compare
            </div>
          )}

          {diff && viewMode === "semantic" && (
            <SemanticDiffContent diff={diff} />
          )}

          {diff && viewMode === "yaml" && (
            <YamlDiffContent lines={yamlDiffLines} />
          )}
        </ScrollArea>

        {/* Actions */}
        {canRollback && (
          <div className="flex justify-end pt-2 border-t border-[#2d3240]">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                if (toVersion) {
                  onRollback(toVersion);
                  onOpenChange(false);
                }
              }}
              className="text-[10px] font-mono text-[#d4a84b] hover:bg-[#d4a84b]/10"
            >
              <IconArrowBackUp size={12} stroke={1.5} />
              Rollback to v{toVersion?.version}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ---- Semantic diff content ----

function SemanticDiffContent({ diff }: { diff: VersionDiff }) {
  if (diff.changes.length === 0) {
    return (
      <div className="flex items-center justify-center py-16 text-[#6f7f9a] text-xs">
        No differences found
      </div>
    );
  }

  const grouped = {
    meta: diff.changes.filter((c) => c.category === "meta" || c.category === "extends"),
    guard: diff.changes.filter((c) => c.category === "guard"),
    setting: diff.changes.filter((c) => c.category === "setting"),
    posture: diff.changes.filter((c) => c.category === "posture"),
    origin: diff.changes.filter((c) => c.category === "origin"),
  };

  return (
    <div className="p-3 space-y-4">
      {grouped.meta.length > 0 && (
        <DiffSection title="Metadata" changes={grouped.meta} />
      )}
      {grouped.guard.length > 0 && (
        <DiffSection title="Guards" changes={grouped.guard} />
      )}
      {grouped.setting.length > 0 && (
        <DiffSection title="Settings" changes={grouped.setting} />
      )}
      {grouped.posture.length > 0 && (
        <DiffSection title="Posture" changes={grouped.posture} />
      )}
      {grouped.origin.length > 0 && (
        <DiffSection title="Origins" changes={grouped.origin} />
      )}
    </div>
  );
}

function DiffSection({ title, changes }: { title: string; changes: VersionChange[] }) {
  return (
    <section>
      <h3 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
        {title}
      </h3>
      <div className="space-y-1.5">
        {changes.map((change, idx) => (
          <ChangeRow key={idx} change={change} />
        ))}
      </div>
    </section>
  );
}

function ChangeRow({ change }: { change: VersionChange }) {
  const typeConfig = {
    added: { color: "#3dbf84", icon: IconPlus, label: "+" },
    removed: { color: "#c45c5c", icon: IconMinus, label: "-" },
    modified: { color: "#d4a84b", icon: IconArrowsExchange, label: "~" },
  };
  const cfg = typeConfig[change.type];

  return (
    <div className="flex items-start gap-2 rounded-md px-2 py-1.5 bg-[#131721] border border-[#2d3240]">
      <span
        className="shrink-0 inline-flex items-center justify-center w-4 h-4 rounded text-[9px] font-mono font-bold mt-0.5"
        style={{ color: cfg.color, backgroundColor: `${cfg.color}15` }}
      >
        {cfg.label}
      </span>
      <div className="flex-1 min-w-0">
        <span className="text-[10px] font-mono text-[#6f7f9a]">{change.path}</span>
        <p className="text-[10px] text-[#ece7dc]/80 mt-0.5">{change.description}</p>
      </div>
    </div>
  );
}

// ---- YAML diff content ----

function YamlDiffContent({ lines }: { lines: DiffLine[] }) {
  if (lines.length === 0) {
    return (
      <div className="flex items-center justify-center py-16 text-[#6f7f9a] text-xs">
        No YAML content to compare
      </div>
    );
  }

  let lineNum = 0;
  return (
    <div className="font-mono text-[10px] leading-5">
      {lines.map((line, idx) => {
        if (line.type !== "removed") lineNum++;
        let bg = "transparent";
        let prefix = " ";
        let textColor = "#ece7dc";

        if (line.type === "removed") {
          bg = "#c45c5c12";
          prefix = "-";
          textColor = "#c45c5c";
        } else if (line.type === "added") {
          bg = "#3dbf8412";
          prefix = "+";
          textColor = "#3dbf84";
        }

        return (
          <div
            key={idx}
            className="flex min-h-[20px] px-2"
            style={{ backgroundColor: bg }}
          >
            <span className="shrink-0 w-5 text-center select-none" style={{ color: textColor }}>
              {prefix}
            </span>
            <span className="shrink-0 w-8 text-right pr-2 select-none text-[#6f7f9a]/30">
              {line.type !== "removed" ? lineNum : ""}
            </span>
            <span className="flex-1 whitespace-pre" style={{ color: textColor }}>
              {line.text}
            </span>
          </div>
        );
      })}
    </div>
  );
}
