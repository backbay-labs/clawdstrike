/**
 * Signal Correlator -- pure-function orchestrator for the automated
 * signal -> cluster -> finding -> enrichment -> auto-promotion pipeline.
 *
 * This module composes existing building blocks from signal-pipeline.ts
 * and finding-engine.ts into a single pipeline call. It does NOT import
 * from any Zustand store -- keeping it testable and side-effect-free.
 *
 * Usage: the useSignalCorrelator hook (or any other caller) passes in
 * current state and receives new findings, clusters, and skipped signal IDs.
 */

import type {
  Signal,
  SignalCluster,
  CorrelationOptions,
} from "./signal-pipeline";
import { correlateSignals } from "./signal-pipeline";

import type {
  Finding,
  MitreTechnique,
  ExtractedIoc,
  SpiderSenseResult,
  AutoPromotionRules,
} from "./finding-engine";
import {
  createFromCluster,
  runEnrichmentPipeline,
  checkAutoPromotion,
  DEFAULT_AUTO_PROMOTION_RULES,
} from "./finding-engine";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface CorrelationPipelineInput {
  signals: Signal[];
  existingFindings: Finding[];
  options?: CorrelationOptions;
  enrichmentData?: {
    mitreTechniques?: MitreTechnique[];
    extractedIocs?: ExtractedIoc[];
    spiderSenseResult?: SpiderSenseResult;
  };
  autoPromotionRules?: AutoPromotionRules;
  actor?: string; // defaults to "signal_correlator"
}

export interface CorrelationPipelineResult {
  newFindings: Finding[];
  updatedFindings: Finding[]; // existing findings with new signals added
  clusters: SignalCluster[];
  skippedSignalIds: string[]; // signals already assigned to findings
}

// ---------------------------------------------------------------------------
// Pipeline implementation
// ---------------------------------------------------------------------------

/**
 * Run the full correlation pipeline:
 *
 * 1. Filter out signals already assigned to findings (findingId !== null)
 *    or whose ID appears in any existing finding's signalIds.
 * 2. Correlate the remaining unassigned signals into clusters.
 * 3. Create a Finding from each qualifying cluster.
 * 4. Optionally run the enrichment pipeline on each new finding.
 * 5. Run auto-promotion checks (auto-confirm, auto-promote annotation).
 * 6. Return the results.
 */
export function runCorrelationPipeline(
  input: CorrelationPipelineInput,
): CorrelationPipelineResult {
  const {
    signals,
    existingFindings,
    options,
    enrichmentData,
    autoPromotionRules = DEFAULT_AUTO_PROMOTION_RULES,
    actor = "signal_correlator",
  } = input;

  // Step 1: Collect IDs of signals already accounted for in existing findings.
  const existingSignalIds = new Set<string>();
  for (const finding of existingFindings) {
    for (const sid of finding.signalIds) {
      existingSignalIds.add(sid);
    }
  }

  const skippedSignalIds: string[] = [];
  const unassignedSignals: Signal[] = [];

  for (const signal of signals) {
    if (signal.findingId !== null || existingSignalIds.has(signal.id)) {
      skippedSignalIds.push(signal.id);
    } else {
      unassignedSignals.push(signal);
    }
  }

  // Step 2: Correlate unassigned signals into clusters.
  const clusters = correlateSignals(unassignedSignals, options);

  // Step 3: Create a Finding from each qualifying cluster.
  let newFindings: Finding[] = [];

  for (const cluster of clusters) {
    const finding = createFromCluster(cluster, unassignedSignals, actor);
    if (finding !== null) {
      newFindings.push(finding);
    }
  }

  // Step 4: Run enrichment pipeline on each new finding (if data provided).
  if (enrichmentData) {
    newFindings = newFindings.map((finding) =>
      runEnrichmentPipeline(finding, {
        mitreTechniques: enrichmentData.mitreTechniques,
        extractedIocs: enrichmentData.extractedIocs,
        spiderSenseResult: enrichmentData.spiderSenseResult,
      }, actor),
    );
  }

  // Step 5: Run auto-promotion checks on each new finding.
  newFindings = newFindings.map((finding) =>
    checkAutoPromotion(finding, unassignedSignals, autoPromotionRules, actor),
  );

  return {
    newFindings,
    updatedFindings: [],
    clusters,
    skippedSignalIds,
  };
}
