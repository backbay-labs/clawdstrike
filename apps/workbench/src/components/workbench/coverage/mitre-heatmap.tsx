import { useState, useMemo, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";
import type { PolicyTab } from "@/lib/workbench/multi-policy-store";
import { FILE_TYPE_REGISTRY, type FileType } from "@/lib/workbench/file-type-registry";
import { parseSigmaYaml } from "@/lib/workbench/sigma-types";
import {
  MITRE_TECHNIQUES,
  MITRE_TACTICS,
  extractSigmaTechniques,
  extractYaraTechniques,
  extractPolicyTechniques,
  type MitreTechnique,
  type MitreTactic,
  type TechniqueCoverage,
} from "@/lib/workbench/mitre-attack-data";
import type { CoverageGapCandidate } from "@/lib/workbench/detection-workflow/shared-types";
import { CoverageGapCard } from "./coverage-gap-card";
import {
  IconShieldCheck,
  IconTarget,
  IconX,
} from "@tabler/icons-react";


// ---- Types ----

interface MitreHeatmapProps {
  tabs: PolicyTab[];
  /** Optional inferred gaps from the coverage gap engine. */
  inferredGaps?: CoverageGapCandidate[];
  /** Callback when drafting from an inferred gap cell. */
  onDraftFromGap?: (gap: CoverageGapCandidate) => void;
  /** Callback when dismissing an inferred gap cell. */
  onDismissGap?: (gapId: string) => void;
}

interface TooltipState {
  techniqueId: string;
  x: number;
  y: number;
}

function extractSigmaTechniqueIds(yaml: string): string[] {
  const { rule } = parseSigmaYaml(yaml);
  return rule?.tags ? extractSigmaTechniques(rule.tags) : [];
}

// ---- Coverage computation ----

function computeCoverage(tabs: PolicyTab[]): Map<string, TechniqueCoverage> {
  const coverageMap = new Map<string, TechniqueCoverage>();

  // Initialize all techniques with zero coverage
  for (const technique of MITRE_TECHNIQUES) {
    coverageMap.set(technique.id, {
      technique,
      ruleCount: 0,
      rules: [],
    });
  }

  for (const tab of tabs) {
    const fileType = tab.fileType;
    const name = tab.name;
    const yaml = tab.yaml;
    let techniqueIds: string[] = [];

    switch (fileType) {
      case "sigma_rule": {
        techniqueIds = extractSigmaTechniqueIds(yaml);
        break;
      }
      case "yara_rule": {
        techniqueIds = extractYaraTechniques(yaml);
        break;
      }
      case "clawdstrike_policy": {
        techniqueIds = extractPolicyTechniques(yaml);
        break;
      }
      case "ocsf_event": {
        // OCSF events don't directly map to techniques
        break;
      }
    }

    // Update coverage for each extracted technique
    for (const techId of new Set(techniqueIds)) {
      const entry = coverageMap.get(techId);
      if (entry) {
        coverageMap.set(techId, {
          technique: entry.technique,
          ruleCount: entry.ruleCount + 1,
          rules: [...entry.rules, { name, fileType }],
        });
      }
    }
  }

  return coverageMap;
}

/** Build a set of technique IDs that are inferred gaps. */
function computeGapTechniques(gaps: CoverageGapCandidate[]): Map<string, CoverageGapCandidate> {
  const map = new Map<string, CoverageGapCandidate>();
  for (const gap of gaps) {
    for (const tech of gap.techniqueHints) {
      if (!map.has(tech)) {
        map.set(tech, gap);
      }
    }
  }
  return map;
}

function groupTechniquesByTactic(): Map<MitreTactic, MitreTechnique[]> {
  const groups = new Map<MitreTactic, MitreTechnique[]>();
  for (const tactic of MITRE_TACTICS) {
    groups.set(tactic.id, []);
  }
  for (const tech of MITRE_TECHNIQUES) {
    const arr = groups.get(tech.tactic);
    if (arr) arr.push(tech);
  }
  return groups;
}

const TECHNIQUES_BY_TACTIC = groupTechniquesByTactic();


// ---- Intensity helpers ----

/** Returns fill opacity based on rule count. 0 = empty, 1 = dim, 2+ = bright. */
function intensityOpacity(ruleCount: number): number {
  if (ruleCount === 0) return 0;
  if (ruleCount === 1) return 0.5;
  if (ruleCount === 2) return 0.7;
  return Math.min(0.95, 0.7 + ruleCount * 0.08);
}

/** Blends colors from the file types that cover this technique. */
function blendedColor(rules: { name: string; fileType: FileType }[]): string {
  if (rules.length === 0) return "transparent";

  // Collect unique file type colors
  const colorSet = new Set<string>();
  for (const r of rules) {
    colorSet.add(FILE_TYPE_REGISTRY[r.fileType].iconColor);
  }
  const colors = [...colorSet];

  // If only one color, return it
  if (colors.length === 1) return colors[0];

  // For multiple colors, use the first one (dominant)
  // A true color blend would require parsing hex, averaging, etc.
  // For simplicity, pick the most frequent file type's color
  const counts = new Map<string, number>();
  for (const r of rules) {
    const c = FILE_TYPE_REGISTRY[r.fileType].iconColor;
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let maxColor = colors[0];
  let maxCount = 0;
  for (const [c, n] of counts) {
    if (n > maxCount) {
      maxCount = n;
      maxColor = c;
    }
  }
  return maxColor;
}

/** Gap color for inferred gaps (amber/orange hatched). */
const GAP_COLOR = "#d4a84b";


// ---- Component ----

export function MitreHeatmap({ tabs, inferredGaps, onDraftFromGap, onDismissGap }: MitreHeatmapProps) {
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);

  const coverageMap = useMemo(() => computeCoverage(tabs), [tabs]);

  const gapTechniqueMap = useMemo(
    () => computeGapTechniques(inferredGaps ?? []),
    [inferredGaps],
  );

  const { coveredCount, totalCount, coveragePercent, gapCount } = useMemo(() => {
    let covered = 0;
    for (const entry of coverageMap.values()) {
      if (entry.ruleCount > 0) covered++;
    }
    const total = MITRE_TECHNIQUES.length;
    // Count gap techniques that are not already covered
    let gaps = 0;
    for (const techId of gapTechniqueMap.keys()) {
      const entry = coverageMap.get(techId);
      if (!entry || entry.ruleCount === 0) gaps++;
    }
    return {
      coveredCount: covered,
      totalCount: total,
      coveragePercent: total > 0 ? Math.round((covered / total) * 100) : 0,
      gapCount: gaps,
    };
  }, [coverageMap, gapTechniqueMap]);

  const techniquesByTactic = TECHNIQUES_BY_TACTIC;

  const handleCellHover = useCallback(
    (techniqueId: string, e: React.MouseEvent) => {
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      setTooltip({
        techniqueId,
        x: rect.left + rect.width / 2,
        y: rect.top - 8,
      });
    },
    [],
  );

  const handleCellLeave = useCallback(() => {
    setTooltip(null);
  }, []);

  const handleCellClick = useCallback((techniqueId: string) => {
    setSelectedTechnique((prev) => (prev === techniqueId ? null : techniqueId));
  }, []);

  const selectedCoverage = selectedTechnique
    ? coverageMap.get(selectedTechnique) ?? null
    : null;

  const selectedGap = selectedTechnique
    ? gapTechniqueMap.get(selectedTechnique) ?? null
    : null;

  const coverageColor =
    coveragePercent >= 60 ? "#3dbf84" : coveragePercent >= 30 ? "#d4a84b" : "#c45c5c";

  return (
    <div className="flex flex-col h-full bg-[#05060a]">
      {/* Header — coverage summary */}
      <div className="px-6 py-4 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconTarget size={16} stroke={1.5} className="text-[#d4a84b]" />
            <div>
              <h3 className="font-syne font-bold text-sm text-[#ece7dc]">
                MITRE ATT&CK Coverage
              </h3>
              <p className="text-[10px] font-mono text-[#6f7f9a] mt-0.5">
                Technique coverage across {tabs.length} open{" "}
                {tabs.length === 1 ? "file" : "files"}
              </p>
            </div>
          </div>

          {/* Coverage strip */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <IconShieldCheck size={13} stroke={1.5} style={{ color: coverageColor }} />
              <span className="text-4xl font-black tabular-nums" style={{ color: coverageColor }}>
                {coveragePercent}%
              </span>
              <span className="text-[11px] font-mono text-[#6f7f9a] ml-2">
                {coveredCount} of {totalCount} techniques covered
              </span>
            </div>
            <div className="w-32 h-1.5 bg-[#2d3240] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${coveragePercent}%`,
                  backgroundColor: coverageColor,
                }}
              />
            </div>
          </div>
        </div>

        {/* Legend — compact single line */}
        <div className="flex items-center gap-3 mt-2 text-[8px] font-mono text-[#6f7f9a]/60">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm bg-[#070810] border border-[#2d3240]/40" />
            0
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "rgba(124,154,239,0.5)" }} />
            1
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "rgba(124,154,239,0.7)" }} />
            2
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: "rgba(61,191,132,0.9)" }} />
            3+
          </span>
          {gapCount > 0 && (
            <span className="flex items-center gap-1 ml-2 border-l border-[#2d3240]/40 pl-2">
              <span
                className="w-2 h-2 rounded-sm border"
                style={{
                  borderColor: `${GAP_COLOR}80`,
                  background: `repeating-linear-gradient(45deg, transparent, transparent 1px, ${GAP_COLOR}20 1px, ${GAP_COLOR}20 2px)`,
                }}
              />
              Inferred Gap ({gapCount})
            </span>
          )}
        </div>
      </div>

      {/* Matrix content */}
      <div className="flex-1 min-h-0 flex">
        {/* Grid */}
        <ScrollArea className="flex-1 overflow-auto">
          <div className="p-4">
            <div className="overflow-x-auto">
              <div className="inline-grid gap-0.5" style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(90px, 1fr))` }}>
                {/* Tactic headers */}
                {MITRE_TACTICS.map((tactic) => (
                  <div
                    key={tactic.id}
                    className="px-2 py-2 border-b-2 border-[#d4a84b]/30 pb-1"
                  >
                    <span className="text-[11px] font-bold uppercase tracking-wider text-[#ece7dc]/80 leading-tight block">
                      {tactic.shortLabel}
                    </span>
                  </div>
                ))}

                {/* Technique cells — aligned by tactic column */}
                {/* Render row by row. Max rows = max techniques per tactic */}
                {Array.from({ length: Math.max(...MITRE_TACTICS.map((t) => techniquesByTactic.get(t.id)?.length ?? 0)) }).flatMap((_, rowIdx) =>
                  MITRE_TACTICS.map((tactic) => {
                    const techniques = techniquesByTactic.get(tactic.id) ?? [];
                    const tech = techniques[rowIdx];
                    if (!tech) {
                      return (
                        <div
                          key={`empty-${tactic.id}-${rowIdx}`}
                          className="h-10"
                        />
                      );
                    }

                    const coverage = coverageMap.get(tech.id);
                    const ruleCount = coverage?.ruleCount ?? 0;
                    const rules = coverage?.rules ?? [];
                    const isGap = ruleCount === 0 && gapTechniqueMap.has(tech.id);
                    const opacity = intensityOpacity(ruleCount);
                    const fillColor = ruleCount > 0 ? blendedColor(rules) : "transparent";
                    const isSelected = selectedTechnique === tech.id;

                    return (
                      <button
                        key={tech.id}
                        className={cn(
                          "relative h-10 rounded-sm border transition-all duration-150 text-left px-1.5 py-1 group",
                          ruleCount === 0 && !isGap
                            ? "bg-[#070810] border-[#2d3240]/30 hover:border-[#2d3240]/60"
                            : "hover:scale-[1.02] hover:shadow-md cursor-pointer",
                          isSelected && "ring-1 ring-[#d4a84b] scale-[1.02]",
                        )}
                        style={{
                          backgroundColor:
                            ruleCount > 0
                              ? `color-mix(in srgb, ${fillColor} ${Math.round(opacity * 100)}%, #070810)`
                              : isGap
                                ? "#070810"
                                : "#070810",
                          borderColor:
                            ruleCount > 0
                              ? `color-mix(in srgb, ${fillColor} 40%, transparent)`
                              : isGap
                                ? `${GAP_COLOR}50`
                                : undefined,
                          // Hatched pattern for inferred gaps via background-image
                          ...(isGap
                            ? {
                                backgroundImage: `repeating-linear-gradient(45deg, transparent, transparent 2px, ${GAP_COLOR}12 2px, ${GAP_COLOR}12 4px)`,
                              }
                            : {}),
                        }}
                        onClick={() => handleCellClick(tech.id)}
                        onMouseEnter={(e) => handleCellHover(tech.id, e)}
                        onMouseLeave={handleCellLeave}
                      >
                        <span className="text-[7px] font-mono text-[#6f7f9a]/60 block leading-tight">
                          {tech.id}
                        </span>
                        <span
                          className={cn(
                            "text-[8px] font-mono leading-tight block truncate",
                            ruleCount > 0
                              ? "text-[#ece7dc]/80"
                              : isGap
                                ? "text-[#d4a84b]/60"
                                : "text-[#6f7f9a]/40",
                          )}
                        >
                          {tech.name}
                        </span>
                        {ruleCount > 0 && (
                          <span
                            className="absolute top-0.5 right-1 text-[7px] font-mono font-bold"
                            style={{ color: fillColor }}
                          >
                            {ruleCount}
                          </span>
                        )}
                        {isGap && ruleCount === 0 && (
                          <span
                            className="absolute top-0.5 right-1 text-[6px] font-mono font-bold"
                            style={{ color: GAP_COLOR }}
                          >
                            GAP
                          </span>
                        )}
                      </button>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </ScrollArea>

        {/* Detail panel (when a technique is selected) */}
        {selectedCoverage && (
          <div className="w-64 shrink-0 border-l border-[#2d3240] bg-[#0b0d13] flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#2d3240] shrink-0">
              <div className="min-w-0">
                <span className="text-[9px] font-mono text-[#6f7f9a] block">
                  {selectedCoverage.technique.id}
                </span>
                <span className="text-[11px] font-medium text-[#ece7dc] block truncate">
                  {selectedCoverage.technique.name}
                </span>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors shrink-0 ml-2"
              >
                <IconX size={14} stroke={1.5} />
              </button>
            </div>

            <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
              <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                Tactic
              </span>
              <span className="text-[10px] font-mono text-[#ece7dc] block mt-0.5">
                {MITRE_TACTICS.find((t) => t.id === selectedCoverage.technique.tactic)
                  ?.label ?? selectedCoverage.technique.tactic}
              </span>
            </div>

            <div className="px-4 py-3 shrink-0">
              <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                Covering Rules ({selectedCoverage.ruleCount})
              </span>
            </div>

            {selectedCoverage.rules.length === 0 && !selectedGap ? (
              <div className="px-4 py-4 text-center">
                <span className="text-[10px] font-mono text-[#6f7f9a]/50">
                  No rules cover this technique
                </span>
              </div>
            ) : (
              <ScrollArea className="flex-1 min-h-0">
                <div className="px-4 pb-3 space-y-1.5">
                  {selectedCoverage.rules.map((rule, idx) => {
                    const descriptor = FILE_TYPE_REGISTRY[rule.fileType];
                    return (
                      <div
                        key={`${rule.name}-${idx}`}
                        className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-[#131721]/40"
                      >
                        <span
                          className="w-1.5 h-1.5 rounded-full shrink-0"
                          style={{ backgroundColor: descriptor.iconColor }}
                        />
                        <span className="text-[10px] font-mono text-[#ece7dc] truncate flex-1">
                          {rule.name}
                        </span>
                        <span
                          className="text-[8px] font-mono uppercase tracking-wider shrink-0"
                          style={{ color: descriptor.iconColor }}
                        >
                          {descriptor.shortLabel}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            )}

            {/* Gap card when selecting a gap technique */}
            {selectedGap && selectedCoverage.ruleCount === 0 && (
              <div className="px-4 py-3 border-t border-[#2d3240]">
                <span className="text-[9px] font-mono uppercase tracking-wider text-[#d4a84b]/70 block mb-2">
                  Inferred Gap
                </span>
                <CoverageGapCard
                  gap={selectedGap}
                  compact
                  onDraft={onDraftFromGap ? () => onDraftFromGap(selectedGap) : undefined}
                  onDismiss={onDismissGap ? () => onDismissGap(selectedGap.id) : undefined}
                />
              </div>
            )}
          </div>
        )}
      </div>

      {/* Floating tooltip */}
      {tooltip && !selectedTechnique && (
        <HeatmapTooltip
          tooltip={tooltip}
          coverageMap={coverageMap}
          gapTechniqueMap={gapTechniqueMap}
        />
      )}
    </div>
  );
}


// ---- Tooltip ----

function HeatmapTooltip({
  tooltip,
  coverageMap,
  gapTechniqueMap,
}: {
  tooltip: TooltipState;
  coverageMap: Map<string, TechniqueCoverage>;
  gapTechniqueMap: Map<string, CoverageGapCandidate>;
}) {
  const coverage = coverageMap.get(tooltip.techniqueId);
  if (!coverage) return null;

  const isGap = coverage.ruleCount === 0 && gapTechniqueMap.has(tooltip.techniqueId);

  return (
    <div
      className="fixed z-50 pointer-events-none"
      style={{
        left: tooltip.x,
        top: tooltip.y,
        transform: "translate(-50%, -100%)",
      }}
    >
      <div className="bg-[#131721] border border-[#2d3240] rounded-lg shadow-xl px-3 py-2 max-w-[220px]">
        <div className="flex items-center gap-1.5 mb-1">
          <span className="text-[8px] font-mono text-[#6f7f9a]">
            {coverage.technique.id}
          </span>
          <span className="text-[10px] font-medium text-[#ece7dc]">
            {coverage.technique.name}
          </span>
        </div>
        {isGap ? (
          <span className="text-[9px] font-mono text-[#d4a84b]/70">
            Inferred gap — click to view details
          </span>
        ) : coverage.ruleCount === 0 ? (
          <span className="text-[9px] font-mono text-[#c45c5c]/70">
            No coverage
          </span>
        ) : (
          <div className="space-y-0.5">
            <span className="text-[9px] font-mono text-[#3dbf84]">
              {coverage.ruleCount} rule{coverage.ruleCount !== 1 ? "s" : ""}
            </span>
            {coverage.rules.slice(0, 3).map((r, i) => (
              <div key={i} className="flex items-center gap-1">
                <span
                  className="w-1 h-1 rounded-full shrink-0"
                  style={{
                    backgroundColor: FILE_TYPE_REGISTRY[r.fileType].iconColor,
                  }}
                />
                <span className="text-[8px] font-mono text-[#6f7f9a] truncate">
                  {r.name}
                </span>
              </div>
            ))}
            {coverage.rules.length > 3 && (
              <span className="text-[8px] font-mono text-[#6f7f9a]/50">
                +{coverage.rules.length - 3} more
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
