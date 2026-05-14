export * from "@/features/findings/stores/finding-store";

// ---------------------------------------------------------------------------
// Auto-enrichment integration (plugin ecosystem)
// ---------------------------------------------------------------------------
// The auto-enrichment manager watches for newly added findings and triggers
// enrichment pipelines automatically. This was part of the old FindingProvider
// and is now wired into the Zustand store via a subscription.

import { AutoEnrichmentManager } from "./auto-enrichment";
import { enrichmentOrchestrator } from "./enrichment-orchestrator";
import { extractIndicators } from "./indicator-extractor";
import { useFindingStore } from "@/features/findings/stores/finding-store";
import type { Finding as SentinelFinding } from "./sentinel-types";

/**
 * Singleton AutoEnrichmentManager.
 *
 * Wraps extractIndicators to work without Signal[] (passes empty array
 * since auto-enrichment triggers before signals are correlated into the store).
 * Exported so settings UI can call getConfig()/updateConfig().
 */
export const autoEnrichmentManager = new AutoEnrichmentManager({
  orchestrator: enrichmentOrchestrator,
  // Cast needed: finding-engine.Finding and sentinel-types.Finding are structurally
  // identical but TypeScript treats them as distinct nominal types (different
  // Enrichment.data shapes: Record<string, unknown> vs EnrichmentData union).
  extractIndicators: (finding) =>
    extractIndicators(finding as unknown as SentinelFinding, []),
});

// Subscribe to the Zustand store to trigger auto-enrichment when new findings appear
if (typeof window !== "undefined") {
  let prevFindingIds = new Set(
    useFindingStore.getState().findings.map((f) => f.id),
  );

  useFindingStore.subscribe((state) => {
    const currentIds = new Set(state.findings.map((f) => f.id));

    for (const finding of state.findings) {
      if (!prevFindingIds.has(finding.id)) {
        autoEnrichmentManager.processNewFinding(finding);
      }
    }

    prevFindingIds = currentIds;
  });
}
