/**
 * Draft Generator — high-level orchestrator for detection draft creation.
 *
 * Combines draft-mappers (seed generation) with per-format adapters to
 * produce complete drafts including starter evidence. This is the main
 * entry point for the "generate a detection from hunt data" workflow.
 */

import type { FileType } from "../file-type-registry";
import type { AgentEvent, Investigation, HuntPattern } from "../hunt-types";
import type { DraftSeed, EvidencePack, DetectionDocumentRef } from "./shared-types";
import type { DraftBuildResult } from "./execution-types";
import { getAdapter } from "./adapters";
import {
  mapEventsToDraftSeed,
  mapInvestigationToDraftSeed,
  mapPatternToDraftSeed,
  recommendFormats,
} from "./draft-mappers";
import type { MapEventsOptions } from "./draft-mappers";

// ---- Result Type ----

export interface DraftResult {
  seed: DraftSeed;
  draft: DraftBuildResult;
  starterEvidence: EvidencePack;
  recommendedFormats: FileType[];
}

// ---- Core Generator ----

/**
 * Generate a complete draft from a DraftSeed.
 *
 * Looks up the adapter for the seed's preferred format, calls buildDraft
 * and buildStarterEvidence, and returns the combined result.
 *
 * If no adapter supports the preferred format, falls back through the
 * recommended formats list until one is found.
 */
export function generateDraft(seed: DraftSeed): DraftResult {
  const recommended = recommendFormats(seed);

  // Try the seed's preferred formats first, then the recommended ones
  const candidates = [...seed.preferredFormats, ...recommended];
  // Deduplicate while preserving order
  const seen = new Set<FileType>();
  const deduped: FileType[] = [];
  for (const f of candidates) {
    if (!seen.has(f)) {
      seen.add(f);
      deduped.push(f);
    }
  }

  let selectedAdapter = null;
  for (const format of deduped) {
    const adapter = getAdapter(format);
    if (adapter && adapter.canDraftFrom(seed)) {
      selectedAdapter = adapter;
      break;
    }
  }

  if (!selectedAdapter) {
    // Last resort: try all registered adapters
    for (const format of deduped) {
      const adapter = getAdapter(format);
      if (adapter) {
        selectedAdapter = adapter;
        break;
      }
    }
  }

  if (!selectedAdapter) {
    throw new Error(
      `No adapter found for seed formats: ${deduped.join(", ")}. ` +
        `Ensure at least one format adapter is registered.`,
    );
  }

  const draft = selectedAdapter.buildDraft(seed);

  // Create a document reference for the starter evidence
  const docRef: DetectionDocumentRef = {
    documentId: crypto.randomUUID(),
    fileType: draft.fileType,
    filePath: null,
    name: draft.name,
    sourceHash: simpleHash(draft.source),
  };

  const starterEvidence = selectedAdapter.buildStarterEvidence(seed, docRef);

  return {
    seed,
    draft,
    starterEvidence,
    recommendedFormats: recommended,
  };
}

// ---- Convenience Wrappers ----

/**
 * Generate a draft directly from AgentEvents.
 * Maps events to a seed, then generates the draft.
 */
export function generateDraftFromEvents(
  events: AgentEvent[],
  options?: MapEventsOptions,
): DraftResult {
  const seed = mapEventsToDraftSeed(events, options);
  return generateDraft(seed);
}

/**
 * Generate a draft from an investigation.
 */
export function generateDraftFromInvestigation(
  investigation: Investigation,
): DraftResult {
  const seed = mapInvestigationToDraftSeed(investigation);
  return generateDraft(seed);
}

/**
 * Generate a draft from a discovered hunt pattern.
 */
export function generateDraftFromPattern(pattern: HuntPattern): DraftResult {
  const seed = mapPatternToDraftSeed(pattern);
  return generateDraft(seed);
}

// ---- Helpers ----

/**
 * Simple string hash for document references. Not cryptographic —
 * just enough to detect changes. SHA-256 is used at publication time.
 */
function simpleHash(text: string): string {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}
