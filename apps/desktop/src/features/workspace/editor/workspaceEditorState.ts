export type WorkspaceEditorBufferStatus = "idle" | "loading" | "ready" | "saving" | "error";

export interface WorkspaceEditorBuffer {
  key: string;
  rootId: string;
  relativePath: string;
  title: string;
  status: WorkspaceEditorBufferStatus;
  loaded: boolean;
  savedContents: string;
  draftContents: string;
  modifiedAt?: string;
  errorMessage?: string;
}

export interface WorkspaceEditorState {
  activeKey?: string;
  buffers: Record<string, WorkspaceEditorBuffer>;
  order: string[];
}

export interface WorkspaceEditorBufferIdentity {
  rootId: string;
  relativePath: string;
  title: string;
}

export function getWorkspaceEditorBufferKey(rootId: string, relativePath: string): string {
  return `${rootId}::${relativePath}`;
}

export function createWorkspaceEditorState(): WorkspaceEditorState {
  return {
    buffers: {},
    order: [],
  };
}

export function getWorkspaceEditorBuffer(
  state: WorkspaceEditorState,
  rootId?: string,
  relativePath?: string,
): WorkspaceEditorBuffer | undefined {
  if (!rootId || !relativePath) {
    return undefined;
  }

  return state.buffers[getWorkspaceEditorBufferKey(rootId, relativePath)];
}

export function ensureWorkspaceEditorBuffer(
  state: WorkspaceEditorState,
  identity: WorkspaceEditorBufferIdentity,
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(identity.rootId, identity.relativePath);
  const existing = state.buffers[key];

  return {
    activeKey: key,
    buffers: {
      ...state.buffers,
      [key]: existing
        ? {
            ...existing,
            title: identity.title,
          }
        : {
            key,
            rootId: identity.rootId,
            relativePath: identity.relativePath,
            title: identity.title,
            status: "idle",
            loaded: false,
            savedContents: "",
            draftContents: "",
          },
    },
    order: existing ? state.order : [...state.order, key],
  };
}

export function beginWorkspaceEditorBufferLoad(
  state: WorkspaceEditorState,
  rootId: string,
  relativePath: string,
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(rootId, relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        status: "loading",
        errorMessage: undefined,
      },
    },
  };
}

export function applyWorkspaceEditorBufferLoad(
  state: WorkspaceEditorState,
  payload: {
    rootId: string;
    relativePath: string;
    contents: string;
    modifiedAt?: string;
  },
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(payload.rootId, payload.relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        status: "ready",
        loaded: true,
        savedContents: payload.contents,
        draftContents: payload.contents,
        modifiedAt: payload.modifiedAt,
        errorMessage: undefined,
      },
    },
  };
}

export function failWorkspaceEditorBufferLoad(
  state: WorkspaceEditorState,
  payload: {
    rootId: string;
    relativePath: string;
    errorMessage: string;
  },
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(payload.rootId, payload.relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        status: "error",
        errorMessage: payload.errorMessage,
      },
    },
  };
}

export function updateWorkspaceEditorBufferDraft(
  state: WorkspaceEditorState,
  payload: {
    rootId: string;
    relativePath: string;
    contents: string;
  },
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(payload.rootId, payload.relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        draftContents: payload.contents,
        status: existing.status === "error" ? "ready" : existing.status,
        errorMessage: undefined,
      },
    },
  };
}

export function beginWorkspaceEditorBufferSave(
  state: WorkspaceEditorState,
  rootId: string,
  relativePath: string,
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(rootId, relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        status: "saving",
        errorMessage: undefined,
      },
    },
  };
}

export function completeWorkspaceEditorBufferSave(
  state: WorkspaceEditorState,
  payload: {
    rootId: string;
    relativePath: string;
    contents: string;
    modifiedAt?: string;
  },
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(payload.rootId, payload.relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  const nextDraftContents = existing.draftContents;

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        status: "ready",
        loaded: true,
        savedContents: payload.contents,
        draftContents: nextDraftContents,
        modifiedAt: payload.modifiedAt,
        errorMessage: undefined,
      },
    },
  };
}

export function failWorkspaceEditorBufferSave(
  state: WorkspaceEditorState,
  payload: {
    rootId: string;
    relativePath: string;
    errorMessage: string;
  },
): WorkspaceEditorState {
  const key = getWorkspaceEditorBufferKey(payload.rootId, payload.relativePath);
  const existing = state.buffers[key];
  if (!existing) {
    return state;
  }

  return {
    ...state,
    buffers: {
      ...state.buffers,
      [key]: {
        ...existing,
        status: "error",
        errorMessage: payload.errorMessage,
      },
    },
  };
}

export function isWorkspaceEditorBufferDirty(buffer?: WorkspaceEditorBuffer): boolean {
  if (!buffer) {
    return false;
  }

  return buffer.draftContents !== buffer.savedContents;
}
