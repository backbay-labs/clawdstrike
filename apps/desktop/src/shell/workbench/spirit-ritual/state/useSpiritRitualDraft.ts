import { useEffect, useMemo, useReducer, useRef } from "react";
import { deriveSpiritRitualSynthesis } from "../modes";
import { createExternalUploadItem } from "../upload";
import {
  createInitialSpiritRitualDraft,
  spiritRitualDraftReducer,
  type SpiritRitualDraftAction,
} from "./draft";
import { buildSpiritRitualCommitPayload } from "./commit";
import type {
  SpiritRitualContext,
  SpiritRitualDrawStroke,
  SpiritRitualSuggestion,
  SpiritRitualUploadItem,
} from "./types";

export function useSpiritRitualDraft(context: SpiritRitualContext) {
  const [draft, dispatch] = useReducer(
    spiritRitualDraftReducer,
    context,
    createInitialSpiritRitualDraft,
  );
  const previousHuntIdRef = useRef(context.hunt.id);

  useEffect(() => {
    if (previousHuntIdRef.current === context.hunt.id) return;
    previousHuntIdRef.current = context.hunt.id;
    dispatch({ type: "reset", draft: createInitialSpiritRitualDraft(context) });
  }, [context]);

  const synthesis = useMemo(() => deriveSpiritRitualSynthesis(context, draft), [context, draft]);

  const api = useMemo(() => ({
    setActivePanel(panel: typeof draft.activePanel) {
      dispatch({ type: "set-active-panel", panel });
    },
    setIntentionText(text: string) {
      dispatch({ type: "set-intention-text", text });
    },
    toggleIntentionSuggestion(suggestionId: string) {
      dispatch({ type: "toggle-intention-suggestion", suggestionId });
    },
    applyIntentionSuggestion(suggestion: SpiritRitualSuggestion) {
      dispatch({ type: "apply-intention-suggestion", suggestion });
    },
    replaceDrawStrokes(strokes: SpiritRitualDrawStroke[]) {
      dispatch({ type: "replace-draw-strokes", strokes });
    },
    appendDrawStroke(stroke: SpiritRitualDrawStroke) {
      dispatch({ type: "append-draw-stroke", stroke });
    },
    clearDrawStrokes() {
      dispatch({ type: "clear-draw-strokes" });
    },
    setCanvasSize(width: number, height: number) {
      dispatch({ type: "set-canvas-size", width, height });
    },
    addUploadItems(items: SpiritRitualUploadItem[]) {
      dispatch({ type: "add-upload-items", items });
    },
    addExternalUpload(input: Parameters<typeof createExternalUploadItem>[0]) {
      dispatch({ type: "add-upload-items", items: [createExternalUploadItem(input)] });
    },
    removeUploadItem(itemId: string) {
      dispatch({ type: "remove-upload-item", itemId });
    },
    toggleUploadSelection(itemId: string) {
      dispatch({ type: "toggle-upload-selection", itemId });
    },
    setPreferredAnchorIds(anchorArtifactIds: string[]) {
      dispatch({ type: "set-preferred-anchor-ids", anchorArtifactIds });
    },
    togglePinned(value?: boolean) {
      dispatch({ type: "toggle-pinned", value });
    },
    resetDraft() {
      dispatch({ type: "reset", draft: createInitialSpiritRitualDraft(context) });
    },
    dispatch(action: SpiritRitualDraftAction) {
      dispatch(action);
    },
    buildCommitPayload() {
      return buildSpiritRitualCommitPayload(context, draft, synthesis);
    },
  }), [context, draft, synthesis]);

  return {
    draft,
    synthesis,
    ...api,
  };
}
