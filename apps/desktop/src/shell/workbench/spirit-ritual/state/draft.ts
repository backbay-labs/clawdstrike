import {
  buildArtifactUploadItems,
} from "../upload";
import type {
  SpiritRitualContext,
  SpiritRitualDraft,
  SpiritRitualPanelMode,
  SpiritRitualSuggestion,
  SpiritRitualUploadItem,
} from "./types";

export const SPIRIT_RITUAL_MAX_ANCHORS = 3;
export const SPIRIT_RITUAL_DEFAULT_CANVAS = {
  width: 640,
  height: 360,
} as const;

let ritualStrokeCounter = 0;

function now(): number {
  return Date.now();
}

function limitIds(ids: string[], max = SPIRIT_RITUAL_MAX_ANCHORS): string[] {
  const deduped = [...new Set(ids.filter(Boolean))];
  return deduped.slice(0, max);
}

function preferredAnchorIds(context: SpiritRitualContext): string[] {
  return limitIds(context.hunt.spirit?.anchorArtifactIds ?? []);
}

function resolveInitialPanel(context: SpiritRitualContext): SpiritRitualPanelMode {
  if (context.hunt.spirit?.thesis) return "intention";
  if ((context.hunt.spirit?.anchorArtifactIds.length ?? 0) > 0) return "upload";
  return "intention";
}

export function createSpiritRitualStrokeId(): string {
  ritualStrokeCounter += 1;
  return `ritual-stroke-${ritualStrokeCounter}`;
}

export function createInitialSpiritRitualDraft(
  context: SpiritRitualContext,
): SpiritRitualDraft {
  const createdAt = now();
  const selectedAnchors = preferredAnchorIds(context);
  const uploadItems = buildArtifactUploadItems(context);
  const selectedItemIds = uploadItems
    .filter((item) => item.artifactId && selectedAnchors.includes(item.artifactId))
    .map((item) => item.id);

  return {
    activePanel: resolveInitialPanel(context),
    intention: {
      text: context.hunt.spirit?.thesis ?? "",
      selectedSuggestionIds: [],
    },
    draw: {
      strokes: [],
      canvasWidth: SPIRIT_RITUAL_DEFAULT_CANVAS.width,
      canvasHeight: SPIRIT_RITUAL_DEFAULT_CANVAS.height,
    },
    upload: {
      items: uploadItems,
      selectedItemIds,
      preferredAnchorIds: selectedAnchors,
    },
    isPinned: context.hunt.spirit?.isPinned ?? false,
    createdAt,
    updatedAt: createdAt,
  };
}

export type SpiritRitualDraftAction =
  | { type: "set-active-panel"; panel: SpiritRitualPanelMode }
  | { type: "set-intention-text"; text: string }
  | { type: "toggle-intention-suggestion"; suggestionId: string }
  | { type: "apply-intention-suggestion"; suggestion: SpiritRitualSuggestion }
  | { type: "replace-draw-strokes"; strokes: SpiritRitualDraft["draw"]["strokes"] }
  | { type: "append-draw-stroke"; stroke: SpiritRitualDraft["draw"]["strokes"][number] }
  | { type: "clear-draw-strokes" }
  | { type: "set-canvas-size"; width: number; height: number }
  | { type: "add-upload-items"; items: SpiritRitualUploadItem[] }
  | { type: "remove-upload-item"; itemId: string }
  | { type: "toggle-upload-selection"; itemId: string }
  | { type: "set-preferred-anchor-ids"; anchorArtifactIds: string[] }
  | { type: "toggle-pinned"; value?: boolean }
  | { type: "reset"; draft: SpiritRitualDraft };

function appendPromptFragment(current: string, fragment: string): string {
  const trimmedCurrent = current.trim();
  const trimmedFragment = fragment.trim();
  if (!trimmedFragment) return trimmedCurrent;
  if (!trimmedCurrent) return trimmedFragment;
  if (trimmedCurrent.toLowerCase().includes(trimmedFragment.toLowerCase())) {
    return trimmedCurrent;
  }
  return `${trimmedCurrent}. ${trimmedFragment}`;
}

function alignPreferredAnchors(
  preferredAnchorIds: string[],
  items: SpiritRitualUploadItem[],
): string[] {
  const available = new Set(
    items
      .map((item) => item.artifactId)
      .filter((artifactId): artifactId is string => Boolean(artifactId)),
  );
  return limitIds(preferredAnchorIds.filter((artifactId) => available.has(artifactId)));
}

export function spiritRitualDraftReducer(
  state: SpiritRitualDraft,
  action: SpiritRitualDraftAction,
): SpiritRitualDraft {
  const nextUpdatedAt = now();

  switch (action.type) {
    case "set-active-panel":
      return { ...state, activePanel: action.panel, updatedAt: nextUpdatedAt };
    case "set-intention-text":
      return {
        ...state,
        intention: {
          ...state.intention,
          text: action.text,
        },
        updatedAt: nextUpdatedAt,
      };
    case "toggle-intention-suggestion": {
      const selected = new Set(state.intention.selectedSuggestionIds);
      if (selected.has(action.suggestionId)) {
        selected.delete(action.suggestionId);
      } else {
        selected.add(action.suggestionId);
      }
      return {
        ...state,
        intention: {
          ...state.intention,
          selectedSuggestionIds: [...selected],
        },
        updatedAt: nextUpdatedAt,
      };
    }
    case "apply-intention-suggestion": {
      const selected = new Set(state.intention.selectedSuggestionIds);
      selected.add(action.suggestion.id);
      return {
        ...state,
        activePanel: "intention",
        intention: {
          text: appendPromptFragment(state.intention.text, action.suggestion.promptFragment),
          selectedSuggestionIds: [...selected],
        },
        updatedAt: nextUpdatedAt,
      };
    }
    case "replace-draw-strokes":
      return {
        ...state,
        draw: {
          ...state.draw,
          strokes: action.strokes,
        },
        updatedAt: nextUpdatedAt,
      };
    case "append-draw-stroke":
      return {
        ...state,
        draw: {
          ...state.draw,
          strokes: [...state.draw.strokes, action.stroke],
        },
        updatedAt: nextUpdatedAt,
      };
    case "clear-draw-strokes":
      return {
        ...state,
        draw: {
          ...state.draw,
          strokes: [],
        },
        updatedAt: nextUpdatedAt,
      };
    case "set-canvas-size":
      return {
        ...state,
        draw: {
          ...state.draw,
          canvasWidth: action.width,
          canvasHeight: action.height,
        },
        updatedAt: nextUpdatedAt,
      };
    case "add-upload-items": {
      const nextItems = [...state.upload.items];
      const existing = new Set(nextItems.map((item) => item.id));
      const nextSelectedItemIds = new Set(state.upload.selectedItemIds);
      const nextPreferredAnchorIds = [...state.upload.preferredAnchorIds];
      for (const item of action.items) {
        if (existing.has(item.id)) continue;
        nextItems.push(item);
        nextSelectedItemIds.add(item.id);
        if (item.artifactId) {
          nextPreferredAnchorIds.push(item.artifactId);
        }
      }
      return {
        ...state,
        upload: {
          items: nextItems,
          selectedItemIds: [...nextSelectedItemIds],
          preferredAnchorIds: alignPreferredAnchors(limitIds(nextPreferredAnchorIds), nextItems),
        },
        updatedAt: nextUpdatedAt,
      };
    }
    case "remove-upload-item": {
      const nextItems = state.upload.items.filter((item) => item.id !== action.itemId);
      const removedItem = state.upload.items.find((item) => item.id === action.itemId) ?? null;
      return {
        ...state,
        upload: {
          items: nextItems,
          selectedItemIds: state.upload.selectedItemIds.filter((itemId) => itemId !== action.itemId),
          preferredAnchorIds: limitIds(
            state.upload.preferredAnchorIds.filter((artifactId) => artifactId !== removedItem?.artifactId),
          ),
        },
        updatedAt: nextUpdatedAt,
      };
    }
    case "toggle-upload-selection": {
      const selected = new Set(state.upload.selectedItemIds);
      const preferred = new Set(state.upload.preferredAnchorIds);
      const item = state.upload.items.find((candidate) => candidate.id === action.itemId) ?? null;
      if (selected.has(action.itemId)) {
        selected.delete(action.itemId);
        if (item?.artifactId) {
          preferred.delete(item.artifactId);
        }
      } else {
        selected.add(action.itemId);
        if (item?.artifactId) {
          preferred.add(item.artifactId);
        }
      }
      return {
        ...state,
        upload: {
          ...state.upload,
          selectedItemIds: [...selected],
          preferredAnchorIds: limitIds([...preferred]),
        },
        updatedAt: nextUpdatedAt,
      };
    }
    case "set-preferred-anchor-ids":
      return {
        ...state,
        upload: {
          ...state.upload,
          preferredAnchorIds: limitIds(action.anchorArtifactIds),
        },
        updatedAt: nextUpdatedAt,
      };
    case "toggle-pinned":
      return {
        ...state,
        isPinned: action.value ?? !state.isPinned,
        updatedAt: nextUpdatedAt,
      };
    case "reset":
      return action.draft;
    default:
      return state;
  }
}
