/**
 * Hook for active coverage gap discovery.
 *
 * Bridges the coverage gap engine to React components, providing a
 * reactive interface for discovering, dismissing, and drafting from
 * coverage gaps.
 */

import { useState, useCallback, useMemo } from "react";
import type { CoverageGapCandidate } from "./shared-types";
import type { CoverageGapInput } from "./coverage-gap-engine";
import {
  discoverCoverageGaps,
  deduplicateGaps,
  rankGaps,
  suppressNoisyGaps,
} from "./coverage-gap-engine";

export interface UseCoverageGapsResult {
  /** Ranked, deduplicated gap candidates. */
  gaps: CoverageGapCandidate[];
  /** Whether gap discovery is in progress. */
  loading: boolean;
  /** Re-run gap discovery with the current input. */
  refresh: () => void;
  /** Dismiss a gap candidate (removes from local display). */
  dismiss: (gapId: string) => void;
  /** Launch draft workflow from a gap candidate. */
  draftFromGap: (gap: CoverageGapCandidate) => void;
}

export interface UseCoverageGapsOptions {
  /** Optional callback to launch draft detection from a gap. */
  onDraftFromGap?: (gap: CoverageGapCandidate) => void;
  /** Optional storage key for durable dismissal state. */
  persistenceKey?: string;
}

export function useCoverageGaps(
  input: CoverageGapInput,
  options: UseCoverageGapsOptions = {},
): UseCoverageGapsResult {
  const storageKey = options.persistenceKey ?? "clawdstrike_detection_gap_dismissals";
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(() => {
    try {
      const stored = localStorage.getItem(storageKey);
      if (!stored) return new Set<string>();
      const parsed = JSON.parse(stored) as unknown;
      return Array.isArray(parsed) ? new Set(parsed.filter((item): item is string => typeof item === "string")) : new Set<string>();
    } catch {
      return new Set<string>();
    }
  });
  const [refreshToken, setRefreshToken] = useState(0);

  const persistDismissedIds = useCallback(
    (ids: Set<string>) => {
      try {
        localStorage.setItem(storageKey, JSON.stringify([...ids]));
      } catch (error) {
        console.warn("[use-coverage-gaps] Failed to persist dismissed coverage gaps:", error);
      }
    },
    [storageKey],
  );

  const gaps = useMemo(() => {
    // Discover raw gaps
    const raw = discoverCoverageGaps(input);

    // Collect known coverage for deduplication
    const knownCoverage = [
      ...(input.openDocumentCoverage ?? []),
      ...(input.publishedCoverage ?? []),
    ];

    // Pipeline: discover -> deduplicate -> suppress noise -> rank
    const deduped = deduplicateGaps(raw, knownCoverage);
    const suppressed = suppressNoisyGaps(deduped);
    const ranked = rankGaps(suppressed);

    // Filter out dismissed
    return ranked.filter((g) => !dismissedIds.has(g.id));
    // refreshToken is included so `refresh()` triggers recomputation
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, dismissedIds, refreshToken]);

  const refresh = useCallback(() => {
    setRefreshToken((t) => t + 1);
  }, []);

  const dismiss = useCallback((gapId: string) => {
    setDismissedIds((prev) => {
      const next = new Set(prev);
      next.add(gapId);
      persistDismissedIds(next);
      return next;
    });
  }, [persistDismissedIds]);

  const draftFromGap = useCallback(
    (gap: CoverageGapCandidate) => {
      options.onDraftFromGap?.(gap);
    },
    [options.onDraftFromGap],
  );

  return {
    gaps,
    loading: false,
    refresh,
    dismiss,
    draftFromGap,
  };
}
