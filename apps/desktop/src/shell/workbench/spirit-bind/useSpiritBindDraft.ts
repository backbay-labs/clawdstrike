import { useState } from "react";
import type { HuntSpiritKind } from "../spirit";
import type { SpiritBindDraft, SpiritBindMode } from "./types";

const MAX_ANCHORS = 3;

export function createInitialSpiritBindDraft(input?: {
  thesis?: string | null;
  isPinned?: boolean;
}): SpiritBindDraft {
  return {
    mode: "quick-configure",
    thesis: input?.thesis ?? "",
    selectedAnchorArtifactIds: [],
    manualKind: null,
    isPinned: input?.isPinned ?? false,
  };
}

export function useSpiritBindDraft(initialState: SpiritBindDraft = createInitialSpiritBindDraft()) {
  const [draft, setDraft] = useState<SpiritBindDraft>(initialState);

  return {
    draft,
    setMode(mode: SpiritBindMode) {
      setDraft((current) => ({ ...current, mode }));
    },
    setThesis(thesis: string) {
      setDraft((current) => ({ ...current, thesis }));
    },
    toggleAnchor(artifactId: string) {
      setDraft((current) => {
        const exists = current.selectedAnchorArtifactIds.includes(artifactId);
        if (exists) {
          return {
            ...current,
            selectedAnchorArtifactIds: current.selectedAnchorArtifactIds.filter((id) => id !== artifactId),
          };
        }
        if (current.selectedAnchorArtifactIds.length >= MAX_ANCHORS) {
          return current;
        }
        return {
          ...current,
          selectedAnchorArtifactIds: [...current.selectedAnchorArtifactIds, artifactId],
        };
      });
    },
    setManualKind(manualKind: HuntSpiritKind) {
      setDraft((current) => ({ ...current, manualKind, mode: "manual" }));
    },
    setPinned(isPinned: boolean) {
      setDraft((current) => ({ ...current, isPinned }));
    },
    reset() {
      setDraft(createInitialSpiritBindDraft());
    },
  };
}

export { MAX_ANCHORS };
