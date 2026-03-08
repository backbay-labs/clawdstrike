/**
 * huntReducer — Sub-reducer for HUNT_* actions on the HuntStore slice.
 *
 * 16 action types covering hunt CRUD, artifact management, runs,
 * case promotion, and dock state.
 */
import type {
  Artifact,
  Hunt,
  HuntStore,
  Run,
  SemanticAssignmentIndex,
  SemanticAttachment,
} from "./huntTypes";
import {
  createHuntId,
  createRunId,
  createArtifactId,
  createCaseId,
  HUNT_COLORS,
  HUNT_ICONS,
} from "./huntTypes";

const MAX_RECENT = 8;

export type HuntAction =
  | { type: "HUNT_CREATE"; payload: { title: string; color?: string; icon?: string } }
  | { type: "HUNT_UPDATE"; payload: { id: string; changes: Partial<Pick<Hunt, "title" | "status" | "color" | "icon">> } }
  | { type: "HUNT_DELETE"; payload: { id: string } }
  | { type: "HUNT_SET_ACTIVE"; payload: { id: string | null } }
  | { type: "HUNT_ADD_ARTIFACT"; payload: { huntId: string; artifact: Omit<Artifact, "createdAt"> & { id?: string } } }
  | { type: "HUNT_REMOVE_ARTIFACT"; payload: { huntId: string; artifactId: string } }
  | { type: "HUNT_MOVE_ARTIFACT"; payload: { fromHuntId: string; toHuntId: string; artifactId: string } }
  | { type: "HUNT_CREATE_RUN"; payload: { huntId: string; label: string } }
  | { type: "HUNT_UPDATE_RUN"; payload: { runId: string; changes: Partial<Pick<Run, "label" | "status">> } }
  | { type: "HUNT_ATTACH_ARTIFACT_TO_RUN"; payload: { runId: string; artifactId: string; semantic?: SemanticAttachment } }
  | { type: "HUNT_PROMOTE_TO_CASE"; payload: { huntId: string; caseTitle: string } }
  | { type: "HUNT_ADD_TO_CASE"; payload: { caseId: string; huntId: string } }
  | { type: "HUNT_ATTACH_ARTIFACT_TO_CASE"; payload: { caseId: string; artifactId: string; semantic?: SemanticAttachment } }
  | { type: "HUNT_ASSIGN_ARTIFACT_SEMANTIC"; payload: { huntId: string; artifactId: string; semantic: SemanticAttachment } }
  | { type: "HUNT_SET_ARTIFACT_METADATA"; payload: { artifactId: string; patch: Record<string, unknown> } }
  | { type: "HUNT_DOCK_PIN"; payload: { huntId: string } }
  | { type: "HUNT_DOCK_UNPIN"; payload: { huntId: string } }
  | { type: "HUNT_DOCK_TOGGLE_COLLAPSE" }
  | { type: "HUNT_DOCK_SET_COLLAPSED"; payload: boolean }
  | { type: "HUNT_BUCKET_TOGGLE_COLLAPSE" }
  | { type: "HUNT_BUCKET_SET_COLLAPSED"; payload: boolean };

function addToRecent(recent: string[], id: string): string[] {
  const filtered = recent.filter((r) => r !== id);
  return [id, ...filtered].slice(0, MAX_RECENT);
}

function appendUnique(values: string[], value: string): string[] {
  return values.includes(value) ? values : [...values, value];
}

function removeArtifactFromAssignments(
  assignments: SemanticAssignmentIndex,
  artifactId: string,
): SemanticAssignmentIndex {
  const next: SemanticAssignmentIndex = {};
  for (const [semantic, ids] of Object.entries(assignments)) {
    const filtered = ids.filter((candidate) => candidate !== artifactId);
    if (filtered.length > 0) {
      next[semantic] = filtered;
    }
  }
  return next;
}

function assignArtifactSemantic(
  assignments: SemanticAssignmentIndex,
  semantic: SemanticAttachment,
  artifactId: string,
): SemanticAssignmentIndex {
  const cleared = removeArtifactFromAssignments(assignments, artifactId);
  return {
    ...cleared,
    [semantic]: appendUnique(cleared[semantic] ?? [], artifactId),
  };
}

function mergeAssignments(
  left: SemanticAssignmentIndex,
  right: SemanticAssignmentIndex,
): SemanticAssignmentIndex {
  const next: SemanticAssignmentIndex = { ...left };
  for (const [semantic, ids] of Object.entries(right)) {
    next[semantic] = ids.reduce(appendUnique, next[semantic] ?? []);
  }
  return next;
}

function findArtifactSemantic(
  assignments: SemanticAssignmentIndex,
  artifactId: string,
): SemanticAttachment | null {
  for (const [semantic, ids] of Object.entries(assignments)) {
    if (ids.includes(artifactId)) {
      return semantic as SemanticAttachment;
    }
  }
  return null;
}

export function huntReducer(state: HuntStore, action: HuntAction): HuntStore {
  switch (action.type) {
    case "HUNT_CREATE": {
      const id = createHuntId();
      const huntCount = Object.keys(state.hunts).length;
      const hunt: Hunt = {
        id,
        title: action.payload.title,
        status: "active",
        artifactIds: [],
        runIds: [],
        caseId: null,
        color: action.payload.color ?? HUNT_COLORS[huntCount % HUNT_COLORS.length],
        icon: action.payload.icon ?? HUNT_ICONS[huntCount % HUNT_ICONS.length],
        semanticAssignments: {},
      };
      return {
        ...state,
        hunts: { ...state.hunts, [id]: hunt },
        dock: {
          ...state.dock,
          activeHuntId: id,
          recentHuntIds: addToRecent(state.dock.recentHuntIds, id),
        },
      };
    }

    case "HUNT_UPDATE": {
      const hunt = state.hunts[action.payload.id];
      if (!hunt) return state;
      return {
        ...state,
        hunts: {
          ...state.hunts,
          [hunt.id]: { ...hunt, ...action.payload.changes },
        },
      };
    }

    case "HUNT_DELETE": {
      const { id } = action.payload;
      if (!state.hunts[id]) return state;
      const remainingHunts = { ...state.hunts };
      delete remainingHunts[id];
      return {
        ...state,
        hunts: remainingHunts,
        dock: {
          ...state.dock,
          activeHuntId: state.dock.activeHuntId === id ? null : state.dock.activeHuntId,
          recentHuntIds: state.dock.recentHuntIds.filter((r) => r !== id),
          pinnedHuntIds: state.dock.pinnedHuntIds.filter((p) => p !== id),
        },
      };
    }

    case "HUNT_SET_ACTIVE": {
      const { id } = action.payload;
      if (id && !state.hunts[id]) return state;
      return {
        ...state,
        dock: {
          ...state.dock,
          activeHuntId: id,
          recentHuntIds: id ? addToRecent(state.dock.recentHuntIds, id) : state.dock.recentHuntIds,
        },
      };
    }

    case "HUNT_ADD_ARTIFACT": {
      const hunt = state.hunts[action.payload.huntId];
      if (!hunt) return state;
      const artId = action.payload.artifact.id ?? createArtifactId();
      const artifact: Artifact = {
        ...action.payload.artifact,
        id: artId,
        createdAt: Date.now(),
      };
      return {
        ...state,
        artifacts: { ...state.artifacts, [artId]: artifact },
        hunts: {
          ...state.hunts,
          [hunt.id]: { ...hunt, artifactIds: [...hunt.artifactIds, artId] },
        },
      };
    }

    case "HUNT_REMOVE_ARTIFACT": {
      const hunt = state.hunts[action.payload.huntId];
      if (!hunt) return state;
      return {
        ...state,
        hunts: {
          ...state.hunts,
          [hunt.id]: {
            ...hunt,
            artifactIds: hunt.artifactIds.filter((a) => a !== action.payload.artifactId),
            semanticAssignments: removeArtifactFromAssignments(
              hunt.semanticAssignments,
              action.payload.artifactId,
            ),
          },
        },
      };
    }

    case "HUNT_MOVE_ARTIFACT": {
      const { fromHuntId, toHuntId, artifactId } = action.payload;
      const from = state.hunts[fromHuntId];
      const to = state.hunts[toHuntId];
      if (!from || !to || !from.artifactIds.includes(artifactId)) return state;
      const semantic = findArtifactSemantic(from.semanticAssignments, artifactId);
      return {
        ...state,
        hunts: {
          ...state.hunts,
          [fromHuntId]: {
            ...from,
            artifactIds: from.artifactIds.filter((a) => a !== artifactId),
            semanticAssignments: removeArtifactFromAssignments(from.semanticAssignments, artifactId),
          },
          [toHuntId]: {
            ...to,
            artifactIds: appendUnique(to.artifactIds, artifactId),
            semanticAssignments: semantic
              ? assignArtifactSemantic(to.semanticAssignments, semantic, artifactId)
              : to.semanticAssignments,
          },
        },
      };
    }

    case "HUNT_CREATE_RUN": {
      const hunt = state.hunts[action.payload.huntId];
      if (!hunt) return state;
      const runId = createRunId();
      const run: Run = {
        id: runId,
        huntId: hunt.id,
        label: action.payload.label,
        status: "running",
        artifactIds: [],
        semanticAssignments: {},
      };
      return {
        ...state,
        runs: { ...state.runs, [runId]: run },
        hunts: {
          ...state.hunts,
          [hunt.id]: { ...hunt, runIds: [...hunt.runIds, runId] },
        },
      };
    }

    case "HUNT_UPDATE_RUN": {
      const run = state.runs[action.payload.runId];
      if (!run) return state;
      return {
        ...state,
        runs: {
          ...state.runs,
          [run.id]: { ...run, ...action.payload.changes },
        },
      };
    }

    case "HUNT_ATTACH_ARTIFACT_TO_RUN": {
      const run = state.runs[action.payload.runId];
      if (!run) return state;
      return {
        ...state,
        runs: {
          ...state.runs,
          [run.id]: {
            ...run,
            artifactIds: appendUnique(run.artifactIds, action.payload.artifactId),
            semanticAssignments: action.payload.semantic
              ? assignArtifactSemantic(
                  run.semanticAssignments,
                  action.payload.semantic,
                  action.payload.artifactId,
                )
              : run.semanticAssignments,
          },
        },
      };
    }

    case "HUNT_PROMOTE_TO_CASE": {
      const hunt = state.hunts[action.payload.huntId];
      if (!hunt || hunt.caseId) return state;
      const caseId = createCaseId();
      return {
        ...state,
        cases: {
          ...state.cases,
          [caseId]: {
            id: caseId,
            title: action.payload.caseTitle,
            status: "open",
            huntIds: [hunt.id],
            artifactIds: [...hunt.artifactIds],
            semanticAssignments: { ...hunt.semanticAssignments },
          },
        },
        hunts: {
          ...state.hunts,
          [hunt.id]: { ...hunt, caseId },
        },
      };
    }

    case "HUNT_ADD_TO_CASE": {
      const { caseId, huntId } = action.payload;
      const existing = state.cases[caseId];
      const hunt = state.hunts[huntId];
      if (!existing || !hunt || existing.huntIds.includes(huntId)) return state;
      return {
        ...state,
        cases: {
          ...state.cases,
          [caseId]: {
            ...existing,
            huntIds: appendUnique(existing.huntIds, huntId),
            artifactIds: hunt.artifactIds.reduce(appendUnique, existing.artifactIds),
            semanticAssignments: mergeAssignments(existing.semanticAssignments, hunt.semanticAssignments),
          },
        },
        hunts: {
          ...state.hunts,
          [huntId]: { ...hunt, caseId },
        },
      };
    }

    case "HUNT_ATTACH_ARTIFACT_TO_CASE": {
      const existing = state.cases[action.payload.caseId];
      if (!existing) return state;
      return {
        ...state,
        cases: {
          ...state.cases,
          [existing.id]: {
            ...existing,
            artifactIds: appendUnique(existing.artifactIds, action.payload.artifactId),
            semanticAssignments: action.payload.semantic
              ? assignArtifactSemantic(
                  existing.semanticAssignments,
                  action.payload.semantic,
                  action.payload.artifactId,
                )
              : existing.semanticAssignments,
          },
        },
      };
    }

    case "HUNT_ASSIGN_ARTIFACT_SEMANTIC": {
      const hunt = state.hunts[action.payload.huntId];
      if (!hunt || !hunt.artifactIds.includes(action.payload.artifactId)) return state;
      return {
        ...state,
        hunts: {
          ...state.hunts,
          [hunt.id]: {
            ...hunt,
            semanticAssignments: assignArtifactSemantic(
              hunt.semanticAssignments,
              action.payload.semantic,
              action.payload.artifactId,
            ),
          },
        },
      };
    }

    case "HUNT_SET_ARTIFACT_METADATA": {
      const artifact = state.artifacts[action.payload.artifactId];
      if (!artifact) return state;
      return {
        ...state,
        artifacts: {
          ...state.artifacts,
          [artifact.id]: {
            ...artifact,
            metadata: {
              ...(artifact.metadata ?? {}),
              ...action.payload.patch,
            },
          },
        },
      };
    }

    case "HUNT_DOCK_PIN": {
      const { huntId } = action.payload;
      if (!state.hunts[huntId] || state.dock.pinnedHuntIds.includes(huntId)) return state;
      return {
        ...state,
        dock: {
          ...state.dock,
          pinnedHuntIds: [...state.dock.pinnedHuntIds, huntId],
        },
      };
    }

    case "HUNT_DOCK_UNPIN": {
      const { huntId } = action.payload;
      return {
        ...state,
        dock: {
          ...state.dock,
          pinnedHuntIds: state.dock.pinnedHuntIds.filter((p) => p !== huntId),
        },
      };
    }

    case "HUNT_DOCK_TOGGLE_COLLAPSE":
      return {
        ...state,
        dock: { ...state.dock, collapsed: !state.dock.collapsed },
      };

    case "HUNT_DOCK_SET_COLLAPSED":
      return {
        ...state,
        dock: { ...state.dock, collapsed: action.payload },
      };

    case "HUNT_BUCKET_TOGGLE_COLLAPSE":
      return {
        ...state,
        dock: { ...state.dock, bucketSummaryCollapsed: !state.dock.bucketSummaryCollapsed },
      };

    case "HUNT_BUCKET_SET_COLLAPSED":
      return {
        ...state,
        dock: { ...state.dock, bucketSummaryCollapsed: action.payload },
      };

    default:
      return state;
  }
}
