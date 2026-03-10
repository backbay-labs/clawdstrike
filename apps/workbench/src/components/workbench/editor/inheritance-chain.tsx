import { useState, useEffect, useRef, useMemo } from "react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import { loadBuiltinRuleset } from "@/lib/tauri-commands";
import { BUILTIN_RULESETS } from "@/lib/workbench/builtin-rulesets";
import { yamlToPolicy } from "@/lib/workbench/yaml-utils";
import type { WorkbenchPolicy, GuardId, GuardConfigMap } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconChevronDown,
  IconArrowRight,
  IconLayersLinked,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type GuardProvenance = "inherited" | "overridden" | "added" | "removed";

interface GuardProvenanceEntry {
  guardId: GuardId;
  name: string;
  provenance: GuardProvenance;
  /** Name of the base ruleset this guard comes from (for inherited / overridden / removed). */
  source: string | null;
}

interface ResolvedBase {
  name: string;
  policy: WorkbenchPolicy;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse the `extends` field into an ordered array of base names.
 * The schema allows a single string or an array; we normalise to array.
 */
function parseExtends(ext: string | string[] | undefined): string[] {
  if (!ext) return [];
  if (Array.isArray(ext)) return ext.filter((s) => s.length > 0);
  return [ext];
}

/**
 * Load a single base ruleset by name.
 * Tries the Tauri backend first, falls back to the client-side builtin set.
 */
async function loadBase(name: string): Promise<ResolvedBase | null> {
  // Try Tauri backend first
  const yaml = await loadBuiltinRuleset(name);
  if (yaml) {
    const [policy] = yamlToPolicy(yaml);
    if (policy) return { name, policy };
  }

  // Client-side fallback
  const fallback = BUILTIN_RULESETS.find((r) => r.id === name);
  if (fallback) {
    const [policy] = yamlToPolicy(fallback.yaml);
    if (policy) return { name, policy };
  }

  return null;
}

/**
 * Check whether a guard is enabled in a policy's guard config.
 * A guard is "present" if it has an entry and `enabled` is not explicitly false.
 */
function isGuardEnabled(guards: GuardConfigMap, id: GuardId): boolean {
  const cfg = guards[id] as Record<string, unknown> | undefined;
  if (!cfg) return false;
  return cfg.enabled !== false;
}

/**
 * Shallow equality check: do two guard configs differ in any key besides `enabled`?
 *
 * Both parameters are guaranteed non-null/non-undefined at the only call site
 * (inside `computeProvenance`, where `inBase.config` and `currentCfg` have
 * already been checked for truthiness).
 */
function guardConfigDiffers(
  base: Record<string, unknown>,
  current: Record<string, unknown>,
): boolean {
  const allKeys = new Set([...Object.keys(base), ...Object.keys(current)]);
  for (const key of allKeys) {
    if (key === "enabled") continue;
    if (JSON.stringify(base[key]) !== JSON.stringify(current[key])) return true;
  }
  return false;
}

/**
 * Build provenance entries for all 13 guards given a merged base and the current policy.
 */
function computeProvenance(
  bases: ResolvedBase[],
  current: WorkbenchPolicy,
): GuardProvenanceEntry[] {
  // Merge bases in order (later bases override earlier ones)
  const mergedBaseGuards: Record<string, { config: Record<string, unknown>; source: string }> = {};

  for (const base of bases) {
    for (const guard of GUARD_REGISTRY) {
      const cfg = base.policy.guards[guard.id] as Record<string, unknown> | undefined;
      if (cfg && cfg.enabled !== false) {
        mergedBaseGuards[guard.id] = { config: cfg, source: base.name };
      }
    }
  }

  const entries: GuardProvenanceEntry[] = [];

  for (const guard of GUARD_REGISTRY) {
    const inBase = mergedBaseGuards[guard.id];
    const currentCfg = current.guards[guard.id] as Record<string, unknown> | undefined;
    const currentEnabled = isGuardEnabled(current.guards, guard.id);

    if (inBase) {
      if (!currentCfg) {
        // Guard in base, not mentioned in current -> inherited
        entries.push({
          guardId: guard.id,
          name: guard.name,
          provenance: "inherited",
          source: inBase.source,
        });
      } else if (!currentEnabled) {
        // Guard in base but explicitly disabled in current -> removed
        entries.push({
          guardId: guard.id,
          name: guard.name,
          provenance: "removed",
          source: inBase.source,
        });
      } else if (guardConfigDiffers(inBase.config, currentCfg)) {
        // Guard in both but config differs -> overridden
        entries.push({
          guardId: guard.id,
          name: guard.name,
          provenance: "overridden",
          source: inBase.source,
        });
      } else {
        // Guard in both, same config -> inherited
        entries.push({
          guardId: guard.id,
          name: guard.name,
          provenance: "inherited",
          source: inBase.source,
        });
      }
    } else {
      // Not in any base
      if (currentCfg && currentEnabled) {
        entries.push({
          guardId: guard.id,
          name: guard.name,
          provenance: "added",
          source: null,
        });
      }
      // If not in base and not enabled in current, skip — not relevant
    }
  }

  return entries;
}

// ---------------------------------------------------------------------------
// Badge sub-component
// ---------------------------------------------------------------------------

const PROVENANCE_STYLES: Record<GuardProvenance, string> = {
  inherited: "bg-[#6f7f9a]/10 text-[#6f7f9a] border-[#6f7f9a]/20",
  overridden: "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20",
  added: "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20",
  removed: "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20",
};

const PROVENANCE_LABELS: Record<GuardProvenance, string> = {
  inherited: "inherited",
  overridden: "overridden",
  added: "added",
  removed: "removed",
};

function ProvenanceBadge({
  provenance,
  source,
}: {
  provenance: GuardProvenance;
  source: string | null;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0 text-[9px] font-mono border rounded select-none whitespace-nowrap",
        PROVENANCE_STYLES[provenance],
      )}
    >
      {PROVENANCE_LABELS[provenance]}
      {source && provenance !== "added" && (
        <span className="opacity-60">
          {provenance === "removed" ? "was" : "from"} {source}
        </span>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Skeleton loader
// ---------------------------------------------------------------------------

function ChainSkeleton() {
  return (
    <div className="flex flex-col gap-2 px-4 py-3">
      <div className="flex items-center gap-2">
        <div className="h-3 w-20 rounded bg-[#2d3240] animate-pulse" />
        <div className="h-3 w-4 rounded bg-[#2d3240] animate-pulse" />
        <div className="h-3 w-24 rounded bg-[#2d3240] animate-pulse" />
      </div>
      <div className="flex flex-col gap-1.5 mt-1">
        {[1, 2, 3].map((i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="h-3 w-28 rounded bg-[#2d3240]/60 animate-pulse" />
            <div className="h-3 w-16 rounded bg-[#2d3240]/40 animate-pulse" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function InheritanceChain() {
  const { state } = useWorkbench();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [resolvedBases, setResolvedBases] = useState<ResolvedBase[]>([]);
  const cacheRef = useRef<Map<string, ResolvedBase>>(new Map());

  const extendsValue = state.activePolicy.extends;
  const baseNames = useMemo(() => parseExtends(extendsValue), [extendsValue]);

  // Load base rulesets when `extends` changes
  useEffect(() => {
    if (baseNames.length === 0) {
      setResolvedBases([]);
      return;
    }

    let cancelled = false;
    setLoading(true);

    async function resolve() {
      const results: ResolvedBase[] = [];

      for (const name of baseNames) {
        // Check cache first
        const cached = cacheRef.current.get(name);
        if (cached) {
          results.push(cached);
          continue;
        }

        const base = await loadBase(name);
        if (base) {
          cacheRef.current.set(name, base);
          results.push(base);
        }
      }

      if (!cancelled) {
        setResolvedBases(results);
        setLoading(false);
      }
    }

    resolve();

    return () => {
      cancelled = true;
    };
  }, [baseNames]);

  // If no extends set, render nothing
  if (baseNames.length === 0) return null;

  const provenance = computeProvenance(resolvedBases, state.activePolicy);

  // Group by provenance for summary counts
  const counts = { inherited: 0, overridden: 0, added: 0, removed: 0 };
  for (const entry of provenance) {
    counts[entry.provenance]++;
  }

  return (
    <div className="border-b border-[#2d3240]">
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger className="flex items-center gap-2 w-full px-4 py-3 text-left cursor-pointer hover:bg-[#131721]/50 transition-colors">
          <IconLayersLinked
            size={14}
            stroke={1.5}
            className="shrink-0 text-[#6f7f9a]"
          />
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
            Inheritance Chain
          </span>

          {/* Summary badges */}
          {!loading && provenance.length > 0 && (
            <div className="flex items-center gap-1 ml-auto mr-1">
              {counts.inherited > 0 && (
                <span className="text-[9px] font-mono text-[#6f7f9a]/70">
                  {counts.inherited} inherited
                </span>
              )}
              {counts.overridden > 0 && (
                <span className="text-[9px] font-mono text-[#d4a84b]/70">
                  {counts.overridden} overridden
                </span>
              )}
              {counts.added > 0 && (
                <span className="text-[9px] font-mono text-[#3dbf84]/70">
                  {counts.added} added
                </span>
              )}
              {counts.removed > 0 && (
                <span className="text-[9px] font-mono text-[#c45c5c]/70">
                  {counts.removed} removed
                </span>
              )}
            </div>
          )}

          {loading && (
            <span className="ml-auto mr-1 text-[9px] font-mono text-[#d4a84b]/60 animate-pulse">
              loading...
            </span>
          )}

          <IconChevronDown
            size={12}
            stroke={1.5}
            className={cn(
              "shrink-0 text-[#6f7f9a] transition-transform duration-200",
              open && "rotate-180",
            )}
          />
        </CollapsibleTrigger>

        <CollapsibleContent>
          {loading ? (
            <ChainSkeleton />
          ) : (
            <div className="px-4 pb-3 flex flex-col gap-3">
              {/* Chain visualization */}
              <div className="flex items-center gap-1.5 flex-wrap">
                {resolvedBases.map((base, idx) => (
                  <span key={base.name} className="flex items-center gap-1.5">
                    {idx > 0 && (
                      <IconArrowRight
                        size={10}
                        stroke={1.5}
                        className="text-[#6f7f9a]/50"
                      />
                    )}
                    <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-mono text-[#6f7f9a] bg-[#6f7f9a]/10 border border-[#6f7f9a]/20 rounded">
                      {base.name}
                    </span>
                  </span>
                ))}
                <IconArrowRight
                  size={10}
                  stroke={1.5}
                  className="text-[#6f7f9a]/50"
                />
                <span className="inline-flex items-center px-2 py-0.5 text-[10px] font-mono text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 rounded font-medium">
                  {state.activePolicy.name || "Current Policy"}
                </span>
              </div>

              {/* Guard-level provenance list */}
              {provenance.length > 0 && (
                <div className="flex flex-col gap-1">
                  <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]/60 mb-0.5">
                    Guard Resolution
                  </span>
                  {provenance.map((entry) => (
                    <div
                      key={entry.guardId}
                      className="flex items-center gap-2 py-0.5"
                    >
                      <span
                        className={cn(
                          "text-[10px] font-mono min-w-[130px]",
                          entry.provenance === "removed"
                            ? "text-[#6f7f9a]/50 line-through"
                            : "text-[#ece7dc]/80",
                        )}
                      >
                        {entry.name}
                      </span>
                      <ProvenanceBadge
                        provenance={entry.provenance}
                        source={entry.source}
                      />
                    </div>
                  ))}
                </div>
              )}

              {provenance.length === 0 && resolvedBases.length > 0 && (
                <p className="text-[10px] font-mono text-[#6f7f9a]/60">
                  No active guards in the inheritance chain.
                </p>
              )}

              {resolvedBases.length === 0 && baseNames.length > 0 && (
                <p className="text-[10px] font-mono text-[#c45c5c]/70">
                  Could not resolve base ruleset{baseNames.length > 1 ? "s" : ""}:{" "}
                  {baseNames.join(", ")}
                </p>
              )}
            </div>
          )}
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Module-level cache shared across all useGuardProvenance instances
// ---------------------------------------------------------------------------

/** Shared cache so multiple GuardCard instances don't each trigger separate loads. */
const sharedBaseCache = new Map<string, ResolvedBase>();

// ---------------------------------------------------------------------------
// Exported helper for guard-card provenance tooltips
// ---------------------------------------------------------------------------

/**
 * Hook that returns provenance info for a single guard.
 * Returns null when `extends` is not set or bases have not loaded.
 * Designed to be called from GuardCard without duplicating base-loading logic.
 *
 * Uses a module-level cache so that when 13 GuardCards mount simultaneously,
 * only the first instance actually fires the async load; the rest resolve from cache.
 */
export function useGuardProvenance(guardId: GuardId): {
  provenance: GuardProvenance;
  source: string | null;
} | null {
  const { state } = useWorkbench();
  const [resolvedBases, setResolvedBases] = useState<ResolvedBase[]>([]);

  const extendsValue = state.activePolicy.extends;
  const baseNames = useMemo(() => parseExtends(extendsValue), [extendsValue]);

  useEffect(() => {
    if (baseNames.length === 0) {
      setResolvedBases([]);
      return;
    }

    let cancelled = false;

    async function resolve() {
      const results: ResolvedBase[] = [];
      for (const name of baseNames) {
        const cached = sharedBaseCache.get(name);
        if (cached) {
          results.push(cached);
          continue;
        }
        const base = await loadBase(name);
        if (base) {
          sharedBaseCache.set(name, base);
          results.push(base);
        }
      }
      if (!cancelled) setResolvedBases(results);
    }

    resolve();
    return () => { cancelled = true; };
  }, [baseNames]);

  return useMemo(() => {
    if (baseNames.length === 0 || resolvedBases.length === 0) return null;

    const all = computeProvenance(resolvedBases, state.activePolicy);
    return all.find((e) => e.guardId === guardId) ?? null;
  }, [baseNames, resolvedBases, state.activePolicy, guardId]);
}
