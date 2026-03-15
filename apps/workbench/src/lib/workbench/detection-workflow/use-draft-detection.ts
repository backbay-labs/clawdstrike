/**
 * Hook for launching draft detection from Hunt surfaces.
 * Bridges Hunt UI -> draft generation -> editor tab creation.
 *
 * This hook encapsulates the flow of:
 *   1. Collecting hunt evidence (events, investigation, or pattern)
 *   2. Creating a DraftSeed
 *   3. Building a draft via the adapter registry
 *   4. Opening a new editor tab with the result
 *
 * If the format-specific adapters (sigma, yara, ocsf) aren't registered yet,
 * the hook falls back to creating a policy draft with a descriptive comment.
 */

import { useState, useCallback } from "react";
import { FILE_TYPE_REGISTRY } from "../file-type-registry";
import type { MultiPolicyAction } from "../multi-policy-store";
import type { AgentEvent, Investigation, HuntPattern } from "../hunt-types";
import type { CoverageGapCandidate, DraftSeed } from "./shared-types";
import type { DraftBuildResult } from "./execution-types";
import { getEvidencePackStore } from "./evidence-pack-store";
import {
  mapEventsToDraftSeed,
  mapInvestigationToDraftSeed,
  mapPatternToDraftSeed,
} from "./draft-mappers";
import { generateDraft } from "./draft-generator";

export function buildSeedFromEvents(
  events: AgentEvent[],
  selectedGap?: CoverageGapCandidate,
): DraftSeed {
  return mapEventsToDraftSeed(events, {
    extraTechniqueHints: selectedGap?.techniqueHints,
    extraDataSourceHints: selectedGap?.dataSourceHints,
    preferredFormats: selectedGap?.suggestedFormats,
  });
}

export function buildSeedFromInvestigation(
  investigation: Investigation,
  scopeEvents?: AgentEvent[],
  selectedGap?: CoverageGapCandidate,
): DraftSeed {
  return mapInvestigationToDraftSeed(investigation, scopeEvents, selectedGap);
}

export function buildSeedFromPattern(
  pattern: HuntPattern,
  selectedGap?: CoverageGapCandidate,
): DraftSeed {
  return mapPatternToDraftSeed(pattern, selectedGap);
}

// ---- Draft Building ----

/**
 * Try to build a draft using the adapter registry. Falls back to a
 * stub policy if no adapter can handle the seed.
 */
export function buildDraftFromSeed(seed: DraftSeed): DraftBuildResult {
  try {
    return generateDraft(seed).draft;
  } catch {
    return buildFallbackDraft(seed);
  }
}

function buildFallbackDraft(seed: DraftSeed): DraftBuildResult {
  const name = deriveName(seed);
  const description = deriveDescription(seed);
  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

  const yaml = `title: ${name}
id: ${seed.id}
status: experimental
description: |
    ${description}
author: "Hunt Workbench (auto-draft)"
date: ${dateStr}
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # TODO: refine selection from hunt evidence
        CommandLine|contains:
            - 'placeholder'
    condition: selection
falsepositives:
    - Requires tuning based on environment
level: medium
`;

  return {
    source: yaml,
    fileType: "sigma_rule",
    name,
    techniqueHints: seed.techniqueHints,
  };
}

function deriveName(seed: DraftSeed): string {
  const fields = seed.extractedFields;
  if (typeof fields.title === "string" && fields.title) {
    return `Draft: ${fields.title}`;
  }
  if (typeof fields.name === "string" && fields.name) {
    return `Draft: ${fields.name}`;
  }
  if (seed.kind === "hunt_event") {
    const count = seed.sourceEventIds.length;
    return `Draft from ${count} Hunt Event${count !== 1 ? "s" : ""}`;
  }
  return "Draft Detection Rule";
}

function deriveDescription(seed: DraftSeed): string {
  const parts: string[] = [];
  parts.push(`Auto-drafted from ${seed.kind.replace(/_/g, " ")} evidence.`);

  if (seed.sourceEventIds.length > 0) {
    parts.push(`Source events: ${seed.sourceEventIds.length}.`);
  }
  if (seed.techniqueHints.length > 0) {
    parts.push(`Technique hints: ${seed.techniqueHints.join(", ")}.`);
  }
  if (seed.dataSourceHints.length > 0) {
    parts.push(`Data sources: ${[...new Set(seed.dataSourceHints)].join(", ")}.`);
  }

  return parts.join(" ");
}

// ---- Hook ----

export interface UseDraftDetectionOptions {
  dispatch: React.Dispatch<MultiPolicyAction>;
  onNavigateToEditor?: () => void;
}

export interface UseDraftDetectionResult {
  /** Draft a detection rule from selected hunt events. */
  draftFromEvents: (events: AgentEvent[], selectedGap?: CoverageGapCandidate) => Promise<void>;
  /** Draft a detection rule from an investigation. */
  draftFromInvestigation: (
    investigation: Investigation,
    scopeEvents?: AgentEvent[],
    selectedGap?: CoverageGapCandidate,
  ) => Promise<void>;
  /** Draft a detection rule from a discovered pattern. */
  draftFromPattern: (pattern: HuntPattern, selectedGap?: CoverageGapCandidate) => Promise<void>;
  /** Whether a draft is currently being generated. */
  loading: boolean;
  /** Status message for the most recent draft action. */
  statusMessage: string | null;
}

export function useDraftDetection({
  dispatch,
  onNavigateToEditor,
}: UseDraftDetectionOptions): UseDraftDetectionResult {
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const generateDraftWithEvidence = useCallback(async (seed: DraftSeed) => {
    const generated = generateDraft(seed);
    const store = getEvidencePackStore();
    await store.init();
    const starterEvidence = await store.savePack(generated.starterEvidence);
    return { draft: generated.draft, starterEvidence };
  }, []);

  const openDraft = useCallback(
    (result: DraftBuildResult, documentId?: string) => {
      dispatch({
        type: "NEW_TAB",
        fileType: result.fileType,
        yaml: result.source,
        documentId,
      });
      onNavigateToEditor?.();
    },
    [dispatch, onNavigateToEditor],
  );

  const draftFromEvents = useCallback(
    async (events: AgentEvent[], selectedGap?: CoverageGapCandidate) => {
      if (events.length === 0) return;
      setLoading(true);
      setStatusMessage(null);
      try {
        const seed = buildSeedFromEvents(events, selectedGap);
        const { draft, starterEvidence } = await generateDraftWithEvidence(seed);
        openDraft(draft, starterEvidence.documentId);
        setStatusMessage(
          `Drafted "${draft.name}" as ${FILE_TYPE_REGISTRY[draft.fileType].shortLabel} with starter evidence`,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setStatusMessage(`Draft failed: ${msg}`);
        console.error("[use-draft-detection] draftFromEvents failed:", err);
      } finally {
        setLoading(false);
      }
    },
    [generateDraftWithEvidence, openDraft],
  );

  const draftFromInvestigation = useCallback(
    async (
      investigation: Investigation,
      scopeEvents?: AgentEvent[],
      selectedGap?: CoverageGapCandidate,
    ) => {
      setLoading(true);
      setStatusMessage(null);
      try {
        const seed = buildSeedFromInvestigation(investigation, scopeEvents, selectedGap);
        const { draft, starterEvidence } = await generateDraftWithEvidence(seed);
        openDraft(draft, starterEvidence.documentId);
        setStatusMessage(
          `Drafted "${draft.name}" as ${FILE_TYPE_REGISTRY[draft.fileType].shortLabel} with starter evidence`,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setStatusMessage(`Draft failed: ${msg}`);
        console.error("[use-draft-detection] draftFromInvestigation failed:", err);
      } finally {
        setLoading(false);
      }
    },
    [generateDraftWithEvidence, openDraft],
  );

  const draftFromPattern = useCallback(
    async (pattern: HuntPattern, selectedGap?: CoverageGapCandidate) => {
      setLoading(true);
      setStatusMessage(null);
      try {
        const seed = buildSeedFromPattern(pattern, selectedGap);
        const { draft, starterEvidence } = await generateDraftWithEvidence(seed);
        openDraft(draft, starterEvidence.documentId);
        setStatusMessage(
          `Drafted "${draft.name}" as ${FILE_TYPE_REGISTRY[draft.fileType].shortLabel} with starter evidence`,
        );
      } catch (err) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setStatusMessage(`Draft failed: ${msg}`);
        console.error("[use-draft-detection] draftFromPattern failed:", err);
      } finally {
        setLoading(false);
      }
    },
    [generateDraftWithEvidence, openDraft],
  );

  return {
    draftFromEvents,
    draftFromInvestigation,
    draftFromPattern,
    loading,
    statusMessage,
  };
}
