import { useMemo, useState } from "react";
import {
  analyzeDependencies,
  checkForUpdates,
  getBaseRulesetYaml,
} from "@/lib/workbench/catalog-deps";
import { BUILTIN_RULESETS } from "@/features/policy/builtin-rulesets";
import type { CatalogEntry } from "@/features/policy/policy-catalog";
import { cn } from "@/lib/utils";
import {
  IconGitBranch,
  IconAlertTriangle,
  IconCheck,
  IconEye,
  IconRefresh,
  IconArrowRight,
  IconInfoCircle,
} from "@tabler/icons-react";
import { YamlViewDialog } from "./yaml-view-dialog";

interface DependencyTrackerProps {
  entry: CatalogEntry;
  className?: string;
}

export function DependencyTracker({ entry, className }: DependencyTrackerProps) {
  const [showBaseYaml, setShowBaseYaml] = useState(false);

  const deps = useMemo(() => analyzeDependencies(entry), [entry]);
  const updateCheck = useMemo(
    () => checkForUpdates(entry, entry.yaml),
    [entry],
  );

  const baseRuleset = deps.extendsRuleset
    ? BUILTIN_RULESETS.find((r) => r.id === deps.extendsRuleset)
    : null;

  const baseVersion = baseRuleset
    ? (baseRuleset.yaml.match(/version:\s*["']?([^"'\s]+)/)?.[1] ?? "unknown")
    : null;

  if (!deps.extendsRuleset) {
    return (
      <div
        className={cn(
          "rounded-lg border border-[#2d3240]/40 bg-[#131721]/50 p-3",
          className,
        )}
      >
        <div className="flex items-center gap-2 text-[11px] text-[#6f7f9a]">
          <IconInfoCircle size={13} className="shrink-0" stroke={1.5} />
          <span>Standalone policy — no base ruleset dependency.</span>
        </div>
      </div>
    );
  }

  return (
    <div
      className={cn(
        "rounded-lg border border-[#2d3240]/40 bg-[#131721]/50 p-3",
        className,
      )}
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <IconGitBranch size={13} className="text-[#d4a84b] shrink-0" stroke={1.5} />
        <span className="text-[11px] font-medium text-[#ece7dc]">
          Dependencies
        </span>
      </div>

      {/* Base ruleset info */}
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10px] text-[#6f7f9a]">Based on:</span>
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono bg-[#d4a84b]/10 text-[#d4a84b] border border-[#d4a84b]/20 rounded">
          {deps.extendsRuleset}
          {baseVersion && (
            <span className="text-[#d4a84b]/60">v{baseVersion}</span>
          )}
        </span>
      </div>

      {/* Last base update */}
      {deps.lastBaseUpdate && (
        <div className="flex items-center gap-2 mb-2 text-[10px] text-[#6f7f9a]/70">
          <span>Last synced:</span>
          <span>{formatRelativeDate(deps.lastBaseUpdate)}</span>
        </div>
      )}

      {/* Update status */}
      <div
        className={cn(
          "flex items-start gap-2 rounded-md px-2.5 py-2 mt-2",
          updateCheck.hasUpdates
            ? "bg-[#d4a84b]/5 border border-[#d4a84b]/20"
            : deps.hasBreakingChanges
            ? "bg-[#c45c5c]/5 border border-[#c45c5c]/20"
            : "bg-[#3dbf84]/5 border border-[#3dbf84]/20",
        )}
      >
        {deps.hasBreakingChanges ? (
          <IconAlertTriangle
            size={12}
            className="text-[#c45c5c] shrink-0 mt-0.5"
            stroke={1.5}
          />
        ) : updateCheck.hasUpdates ? (
          <IconAlertTriangle
            size={12}
            className="text-[#d4a84b] shrink-0 mt-0.5"
            stroke={1.5}
          />
        ) : (
          <IconCheck
            size={12}
            className="text-[#3dbf84] shrink-0 mt-0.5"
            stroke={1.5}
          />
        )}
        <span
          className={cn(
            "text-[10px] leading-relaxed",
            deps.hasBreakingChanges
              ? "text-[#c45c5c]"
              : updateCheck.hasUpdates
              ? "text-[#d4a84b]"
              : "text-[#3dbf84]/80",
          )}
        >
          {deps.hasBreakingChanges
            ? "Breaking changes detected in the base ruleset. Review before updating."
            : updateCheck.summary}
        </span>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 mt-3">
        {baseRuleset && (
          <button
            onClick={() => setShowBaseYaml(true)}
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[10px] font-medium hover:text-[#ece7dc] transition-colors border border-[#2d3240]/40"
          >
            <IconEye size={11} stroke={1.5} />
            View Base
          </button>
        )}
        {(updateCheck.hasUpdates || deps.hasBreakingChanges) && (
          <button
            className="flex items-center gap-1 px-2 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[10px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
            title="Re-apply the latest base ruleset changes"
          >
            <IconRefresh size={11} stroke={1.5} />
            Update Base
          </button>
        )}
      </div>

      {/* Dependency chain visualization */}
      {deps.dependsOn.length > 0 && (
        <div className="mt-3 pt-3 border-t border-[#2d3240]/30">
          <span className="text-[10px] text-[#6f7f9a] block mb-1.5">
            Also depends on:
          </span>
          <div className="flex items-center gap-1 flex-wrap">
            {deps.dependsOn.map((depId) => (
              <span
                key={depId}
                className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono bg-[#131721] text-[#6f7f9a] border border-[#2d3240]/50 rounded"
              >
                <IconArrowRight size={9} stroke={1.5} />
                {depId}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Base YAML dialog */}
      {baseRuleset && (
        <YamlViewDialog
          open={showBaseYaml}
          onClose={() => setShowBaseYaml(false)}
          name={`Base: ${baseRuleset.name}`}
          yaml={baseRuleset.yaml}
        />
      )}
    </div>
  );
}

// ---- Helpers ----

function formatRelativeDate(isoDate: string): string {
  try {
    const date = new Date(isoDate);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return "today";
    if (diffDays === 1) return "1 day ago";
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
    return `${Math.floor(diffDays / 365)} years ago`;
  } catch {
    return isoDate;
  }
}
