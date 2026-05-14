/**
 * useSignalCorrelator -- React hook that subscribes to the signal store
 * and automatically triggers correlation -> finding creation when signals
 * change.
 *
 * Mount this hook in a top-level component (e.g. Workbench root) to enable
 * automatic finding creation from signal clusters as signals arrive.
 *
 * Architecture:
 *   signal-store (signals change)
 *     -> debounce (2s default)
 *     -> correlateSignals() from signal-pipeline.ts
 *     -> finding-store.createFromCluster() for each new cluster
 *     -> enrichment + auto-promotion on newly created findings
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { useSignalStore } from "@/features/findings/stores/signal-store";
import { useFindingStore } from "@/features/findings/stores/finding-store";
import { correlateSignals } from "@/lib/workbench/signal-pipeline";
import type { Signal, SignalCluster } from "@/lib/workbench/signal-pipeline";
import type { Finding } from "@/lib/workbench/finding-engine";
import {
  runEnrichmentPipeline,
  checkAutoPromotion,
} from "@/lib/workbench/finding-engine";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface UseSignalCorrelatorOptions {
  /** Whether the correlator is active. Default: true. */
  enabled?: boolean;
  /** Debounce delay in ms after signal changes. Default: 2000. */
  debounceMs?: number;
  /** Minimum unassigned signals required before a run. Default: 2. */
  minSignalsForRun?: number;
}

export interface UseSignalCorrelatorReturn {
  lastRunAt: number | null;
  clustersFound: number;
  findingsCreated: number;
  isRunning: boolean;
}

// ---------------------------------------------------------------------------
// Hook implementation
// ---------------------------------------------------------------------------

/**
 * Subscribes to signal store changes and automatically creates findings
 * from correlated signal clusters after a configurable debounce.
 *
 * No manual trigger needed -- just mount the hook in a top-level component.
 */
export function useSignalCorrelator(
  options: UseSignalCorrelatorOptions = {},
): UseSignalCorrelatorReturn {
  const {
    enabled = true,
    debounceMs = 2000,
    minSignalsForRun = 2,
  } = options;

  // Subscribe to signal array changes
  const signals = useSignalStore.use.signals();

  // Local state for reporting
  const [lastRunAt, setLastRunAt] = useState<number | null>(null);
  const [clustersFound, setClustersFound] = useState(0);
  const [findingsCreated, setFindingsCreated] = useState(0);
  const [isRunning, setIsRunning] = useState(false);

  // Refs for debounce timer and preventing stale closures
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const enabledRef = useRef(enabled);
  enabledRef.current = enabled;

  const runCorrelation = useCallback(() => {
    if (!enabledRef.current) return;

    // Use getState() to avoid stale closure over signals/findings
    // (Pitfall 4 from research: stale store references in callbacks)
    const currentSignals = useSignalStore.getState().signals;
    const findingState = useFindingStore.getState();
    const existingFindings: Finding[] = findingState.findings;

    // Collect IDs of signals already accounted for in existing findings
    const existingSignalIds = new Set<string>();
    for (const finding of existingFindings) {
      for (const sid of finding.signalIds) {
        existingSignalIds.add(sid);
      }
    }

    // Filter to unassigned signals only
    const unassignedSignals = currentSignals.filter(
      (s: Signal) => s.findingId === null && !existingSignalIds.has(s.id),
    );

    if (unassignedSignals.length < minSignalsForRun) return;

    setIsRunning(true);

    try {
      // Run correlation
      const clusters: SignalCluster[] = correlateSignals(unassignedSignals);

      if (clusters.length === 0) {
        setIsRunning(false);
        setLastRunAt(Date.now());
        return;
      }

      let created = 0;

      for (const cluster of clusters) {
        // Dedup check: skip if any existing finding already contains a
        // majority of this cluster's signal IDs.
        const isDuplicate = existingFindings.some((f: Finding) => {
          const overlap = cluster.signalIds.filter((id) =>
            f.signalIds.includes(id),
          );
          return overlap.length >= Math.ceil(cluster.signalIds.length * 0.5);
        });

        if (isDuplicate) continue;

        // Create the finding through the store action (handles persistence)
        const newFinding = findingState.actions.createFromCluster(
          cluster,
          unassignedSignals,
          "signal_correlator",
        );

        if (newFinding) {
          created++;

          // Run enrichment: extract MITRE technique hints from signal flags
          const mitreHints = extractMitreHintsFromSignals(
            unassignedSignals.filter((s: Signal) =>
              cluster.signalIds.includes(s.id),
            ),
          );

          if (mitreHints.length > 0) {
            const enriched = runEnrichmentPipeline(
              newFinding,
              { mitreTechniques: mitreHints },
              "signal_correlator",
            );

            // Apply enrichments through store
            for (const enrichment of enriched.enrichments) {
              if (
                !newFinding.enrichments.some((e) => e.id === enrichment.id)
              ) {
                findingState.actions.addEnrichment(
                  newFinding.id,
                  enrichment,
                  "signal_correlator",
                );
              }
            }
          }

          // Run auto-promotion check
          // Re-fetch the finding to get the latest state (after enrichments)
          const updatedFindingState = useFindingStore.getState();
          const updatedFinding = updatedFindingState.findings.find(
            (f: Finding) => f.id === newFinding.id,
          );

          if (updatedFinding) {
            const promoted = checkAutoPromotion(
              updatedFinding,
              unassignedSignals,
            );
            if (promoted.status !== updatedFinding.status) {
              // The finding was auto-confirmed; apply through store
              updatedFindingState.actions.confirm(
                updatedFinding.id,
                "signal_correlator",
              );
            }
          }
        }
      }

      setClustersFound(clusters.length);
      setFindingsCreated(created);
      setLastRunAt(Date.now());
    } finally {
      setIsRunning(false);
    }
  }, [minSignalsForRun]);

  // Effect: debounce correlation on signal changes
  useEffect(() => {
    if (!enabled) return;

    // Clear previous timer
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
    }

    timerRef.current = setTimeout(() => {
      runCorrelation();
      timerRef.current = null;
    }, debounceMs);

    // Cleanup on unmount or before next effect run
    return () => {
      if (timerRef.current !== null) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [signals, enabled, debounceMs, runCorrelation]);

  return {
    lastRunAt,
    clustersFound,
    findingsCreated,
    isRunning,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract MITRE technique hints from signal context flags.
 * Signals with flags of type "mitre" contain technique references.
 */
function extractMitreHintsFromSignals(
  signals: Signal[],
): Array<{ id: string; name: string; tactic: string }> {
  const techniques: Array<{ id: string; name: string; tactic: string }> = [];
  const seen = new Set<string>();

  for (const signal of signals) {
    for (const flag of signal.context.flags) {
      if (flag.type === "mitre" && flag.reason && !seen.has(flag.reason)) {
        seen.add(flag.reason);
        // Parse "T1059 - Command and Scripting Interpreter (Execution)" format
        const match = flag.reason.match(
          /^(T\d+(?:\.\d+)?)\s*-\s*(.+?)(?:\s*\((.+?)\))?$/,
        );
        if (match) {
          techniques.push({
            id: match[1],
            name: match[2].trim(),
            tactic: match[3]?.trim() ?? "Unknown",
          });
        }
      }
    }
  }

  return techniques;
}
