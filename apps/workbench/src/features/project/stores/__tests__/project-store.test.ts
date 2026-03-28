import { beforeEach, describe, expect, it, vi } from "vitest";
import { getActivePaneRoute, usePaneStore } from "@/features/panes/pane-store";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { getDocumentIdentityStore } from "@/lib/workbench/detection-workflow/document-identity-store";
import type {
  TauriWorkspaceRegistrySnapshot,
  TauriWorkspaceRootRecord,
  TauriWorkspaceTreeEntry,
} from "@/lib/tauri-commands";
import {
  canonicalizeWorkspaceConsumerPath,
  getCanonicalWorkspaceRootPaths,
  getDefaultWorkspaceConsumerRootPath,
  getProjectFileStatusKey,
  isWorkspaceConsumerRootReady,
  useProjectStore,
  type DetectionProject,
  type ProjectFile,
} from "../project-store";

const originalProjectActions = useProjectStore.getState().actions;

const { tauriBridgeMocks, tauriCommandMocks } = vi.hoisted(() => ({
  tauriBridgeMocks: {
    createDetectionFile: vi.fn(),
  },
  tauriCommandMocks: {
    addWorkspaceRootNative: vi.fn(),
    removeWorkspaceRootNative: vi.fn(),
    readWorkspaceTreeNative: vi.fn(),
    renameWorkspaceEntryNative: vi.fn(),
    deleteWorkspaceEntryNative: vi.fn(),
    createWorkspaceDirectoryNative: vi.fn(),
  },
}));

vi.mock("@/lib/tauri-bridge", () => tauriBridgeMocks);

vi.mock("@/lib/tauri-commands", async () => {
  const actual = await vi.importActual<typeof import("@/lib/tauri-commands")>(
    "@/lib/tauri-commands",
  );
  return {
    ...actual,
    addWorkspaceRootNative: tauriCommandMocks.addWorkspaceRootNative,
    removeWorkspaceRootNative: tauriCommandMocks.removeWorkspaceRootNative,
    readWorkspaceTreeNative: tauriCommandMocks.readWorkspaceTreeNative,
    renameWorkspaceEntryNative: tauriCommandMocks.renameWorkspaceEntryNative,
    deleteWorkspaceEntryNative: tauriCommandMocks.deleteWorkspaceEntryNative,
    createWorkspaceDirectoryNative: tauriCommandMocks.createWorkspaceDirectoryNative,
  };
});

function makeRootRecord(
  rootId: string,
  displayPath: string,
  options?: Partial<TauriWorkspaceRootRecord>,
): TauriWorkspaceRootRecord {
  return {
    rootId,
    canonicalPath: displayPath,
    displayPath,
    label: displayPath.split("/").filter(Boolean).pop() ?? displayPath,
    kind: "mounted_folder",
    provenance: "user_added",
    isDefault: false,
    aliases: [],
    ...options,
  };
}

function makeSnapshot(
  roots: TauriWorkspaceRootRecord[],
  defaultRootId: string | null = roots[0]?.rootId ?? null,
): TauriWorkspaceRegistrySnapshot {
  return {
    version: 1,
    defaultRootId,
    orderedRootIds: roots.map((root) => root.rootId),
    roots,
  };
}

function makeProject(rootId: string, rootPath: string): DetectionProject {
  const file: ProjectFile = {
    path: "policies/default.yaml",
    name: "default.yaml",
    fileType: "clawdstrike_policy",
    isDirectory: false,
    depth: 1,
  };

  return {
    rootId,
    rootPath,
    name: rootPath.split("/").pop() ?? rootPath,
    expandedDirs: new Set(["policies"]),
    files: [
      {
        path: "policies",
        name: "policies",
        fileType: "clawdstrike_policy",
        isDirectory: true,
        depth: 0,
        children: [file],
      },
    ],
  };
}

function hasPath(files: ProjectFile[], targetPath: string): boolean {
  return files.some((file) => {
    if (file.path === targetPath) return true;
    return file.children ? hasPath(file.children, targetPath) : false;
  });
}

describe("useProjectStore", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    usePaneStore.getState()._reset();
    usePolicyTabsStore.getState()._reset();
    getDocumentIdentityStore().clear();
    tauriCommandMocks.renameWorkspaceEntryNative.mockResolvedValue({
      ok: true,
      data: {
        oldRelativePath: "policies/default.yaml",
        newRelativePath: "policies/renamed.yaml",
      },
    });
    tauriCommandMocks.deleteWorkspaceEntryNative.mockResolvedValue({
      ok: true,
      data: {
        relativePath: "policies/default.yaml",
        kind: "file",
      },
    });
    tauriCommandMocks.createWorkspaceDirectoryNative.mockResolvedValue({
      ok: true,
      data: {
        relativePath: "workspace/new-folder",
      },
    });
    tauriCommandMocks.readWorkspaceTreeNative.mockResolvedValue({
      ok: true,
      data: { entries: [] },
    });

    const alphaRoot = makeRootRecord("root-alpha", "/workspace/alpha", {
      isDefault: true,
      kind: "default_home",
      provenance: "bootstrap",
    });
    const bravoRoot = makeRootRecord("root-bravo", "/workspace/bravo");

    useProjectStore.setState({
      project: makeProject("root-alpha", "/workspace/alpha"),
      loading: false,
      error: null,
      filter: "",
      formatFilter: null,
      fileStatuses: new Map(),
      defaultRootId: "root-alpha",
      orderedRootIds: ["root-alpha", "root-bravo"],
      rootsById: new Map([
        ["root-alpha", alphaRoot],
        ["root-bravo", bravoRoot],
      ]),
      rootStatusById: new Map([
        ["root-alpha", "ready"],
        ["root-bravo", "ready"],
      ]),
      rootErrorById: new Map([
        ["root-alpha", null],
        ["root-bravo", null],
      ]),
      rootRequestedVersionById: new Map([
        ["root-alpha", 1],
        ["root-bravo", 1],
      ]),
      rootCommittedVersionById: new Map([
        ["root-alpha", 1],
        ["root-bravo", 1],
      ]),
      rootMutationById: new Map([
        ["root-alpha", null],
        ["root-bravo", null],
      ]),
      projectsById: new Map([
        ["root-alpha", makeProject("root-alpha", "/workspace/alpha")],
        ["root-bravo", makeProject("root-bravo", "/workspace/bravo")],
      ]),
      projectRoots: ["/workspace/alpha", "/workspace/bravo"],
      projects: new Map([
        ["/workspace/alpha", makeProject("root-alpha", "/workspace/alpha")],
        ["/workspace/bravo", makeProject("root-bravo", "/workspace/bravo")],
      ]),
      actions: {
        ...originalProjectActions,
        loadRoot: vi.fn(async () => {}),
      },
    });
  });

  it("routes rename and file status migration through the owning workspace", async () => {
    const actions = useProjectStore.getState().actions;
    const originalPath = "/workspace/bravo/policies/default.yaml";
    const renamedPath = "/workspace/bravo/policies/renamed.yaml";
    actions.setFileStatus(originalPath, { modified: true });
    getDocumentIdentityStore().register(originalPath, "doc-bravo");

    usePolicyTabsStore
      .getState()
      .openTabOrSwitch(
        originalPath,
        "clawdstrike_policy",
        'name: "Bravo"\nversion: "1.0.0"\n',
        "default.yaml",
      );
    usePolicyTabsStore.setState((state) => ({
      ...state,
      tabs: state.tabs.map((tab) =>
        tab.filePath === originalPath
          ? { ...tab, name: "default.yaml" }
          : tab,
      ),
    }));
    usePaneStore.getState().openFile(originalPath, "default.yaml");

    const renamed = await actions.renameFile(originalPath, "renamed.yaml");

    expect(renamed).toBe(true);
    expect(tauriCommandMocks.renameWorkspaceEntryNative).toHaveBeenCalledWith(
      "root-bravo",
      "policies/default.yaml",
      "policies/renamed.yaml",
    );

    const state = useProjectStore.getState();
    expect(
      hasPath(
        state.projects.get("/workspace/alpha")?.files ?? [],
        "policies/default.yaml",
      ),
    ).toBe(true);
    expect(
      hasPath(
        state.projects.get("/workspace/bravo")?.files ?? [],
        "policies/renamed.yaml",
      ),
    ).toBe(true);
    expect(
      hasPath(
        state.projects.get("/workspace/bravo")?.files ?? [],
        "policies/default.yaml",
      ),
    ).toBe(false);
    expect(
      state.fileStatuses.get(
        getProjectFileStatusKey("/workspace/bravo", "policies/renamed.yaml"),
      ),
    ).toEqual({ modified: true });
    expect(
      state.fileStatuses.has(
        getProjectFileStatusKey("/workspace/bravo", "policies/default.yaml"),
      ),
    ).toBe(false);
    const renamedTab = usePolicyTabsStore.getState().tabs.find(
      (tab) => tab.filePath === renamedPath,
    );
    expect(renamedTab).toBeTruthy();
    expect(renamedTab?.name).toBe("renamed.yaml");
    expect(getDocumentIdentityStore().resolve(originalPath)).toBeNull();
    expect(getDocumentIdentityStore().resolve(renamedPath)).toBe("doc-bravo");
    expect(
      getActivePaneRoute(usePaneStore.getState().root, usePaneStore.getState().activePaneId),
    ).toBe(`/file/${renamedPath}`);
  });

  it("rejects rename inputs that contain path components", async () => {
    const renamed = await useProjectStore.getState().actions.renameFile(
      "/workspace/bravo/policies/default.yaml",
      "../outside.yaml",
    );

    expect(renamed).toBe(false);
    expect(tauriCommandMocks.renameWorkspaceEntryNative).not.toHaveBeenCalled();
  });

  it("closes open tabs and clears stale metadata on delete", async () => {
    const actions = useProjectStore.getState().actions;
    const targetPath = "/workspace/bravo/policies/default.yaml";
    actions.setFileStatus(targetPath, { modified: true });
    getDocumentIdentityStore().register(targetPath, "doc-bravo");
    usePolicyTabsStore
      .getState()
      .openTabOrSwitch(
        targetPath,
        "clawdstrike_policy",
        'name: "Bravo"\nversion: "1.0.0"\n',
        "default.yaml",
      );

    const deleted = await actions.deleteFile(targetPath);

    expect(deleted).toBe(true);
    expect(tauriCommandMocks.deleteWorkspaceEntryNative).toHaveBeenCalledWith(
      "root-bravo",
      "policies/default.yaml",
    );
    expect(
      hasPath(
        useProjectStore.getState().projects.get("/workspace/bravo")?.files ?? [],
        "policies/default.yaml",
      ),
    ).toBe(false);
    expect(
      useProjectStore.getState().fileStatuses.has(
        getProjectFileStatusKey("/workspace/bravo", "policies/default.yaml"),
      ),
    ).toBe(false);
    expect(
      usePolicyTabsStore.getState().tabs.some((tab) => tab.filePath === targetPath),
    ).toBe(false);
    expect(getDocumentIdentityStore().resolve(targetPath)).toBeNull();
  });
});

describe("workspace root loading", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    usePaneStore.getState()._reset();
    usePolicyTabsStore.getState()._reset();
    getDocumentIdentityStore().clear();
    tauriCommandMocks.readWorkspaceTreeNative.mockResolvedValue({
      ok: true,
      data: { entries: [] },
    });

    const defaultRoot = makeRootRecord("root-default", "/workspace/default", {
      isDefault: true,
      kind: "default_home",
      provenance: "bootstrap",
    });

    useProjectStore.setState({
      project: null,
      loading: false,
      error: null,
      filter: "",
      formatFilter: null,
      fileStatuses: new Map(),
      defaultRootId: "root-default",
      orderedRootIds: ["root-default"],
      rootsById: new Map([["root-default", defaultRoot]]),
      rootStatusById: new Map([["root-default", "idle"]]),
      rootErrorById: new Map([["root-default", null]]),
      rootRequestedVersionById: new Map([["root-default", 0]]),
      rootCommittedVersionById: new Map([["root-default", 0]]),
      rootMutationById: new Map([["root-default", null]]),
      projectsById: new Map(),
      projectRoots: ["/workspace/default"],
      projects: new Map(),
      actions: originalProjectActions,
    });
  });

  it("publishes a placeholder project before the native scan resolves", async () => {
    let resolveTreeRead: ((value: { ok: true; data: { entries: never[] } }) => void) | null = null;
    tauriCommandMocks.readWorkspaceTreeNative.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveTreeRead = resolve;
        }),
    );

    const loadPromise = useProjectStore.getState().actions.loadRoot("/workspace/default");

    expect(useProjectStore.getState().projects.get("/workspace/default")).toMatchObject({
      rootPath: "/workspace/default",
      name: "default",
      files: [],
    });
    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("loading");

    await Promise.resolve();
    expect(resolveTreeRead).not.toBeNull();
    resolveTreeRead!({ ok: true, data: { entries: [] } });
    await loadPromise;
    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("empty");
    expect(useProjectStore.getState().rootCommittedVersionById.get("root-default")).toBe(1);
  });

  it("initializes hydrated registry roots without awaiting their scans", async () => {
    tauriCommandMocks.readWorkspaceTreeNative.mockImplementationOnce(
      () => new Promise(() => {}),
    );

    await useProjectStore.getState().actions.initFromWorkspaceRegistry();

    expect(useProjectStore.getState().projects.get("/workspace/default")).toMatchObject({
      rootId: "root-default",
      rootPath: "/workspace/default",
      name: "default",
      files: [],
    });
    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("loading");
  });

  it("returns pending root ids when readiness times out", async () => {
    tauriCommandMocks.readWorkspaceTreeNative.mockImplementationOnce(
      () => new Promise(() => {}),
    );

    await useProjectStore.getState().actions.initFromWorkspaceRegistry();
    const result = await useProjectStore.getState().actions.waitForRootsReady(10);

    expect(result.ready).toBe(false);
    expect(result.pendingRootIds).toEqual(["root-default"]);
    expect(result.elapsedMs).toBeGreaterThanOrEqual(10);
  });

  it("ignores stale scan results when a newer request completes first", async () => {
    let resolveFirst: ((value: { ok: true; data: { entries: TauriWorkspaceTreeEntry[] } }) => void) | null = null;
    let resolveSecond: ((value: { ok: true; data: { entries: TauriWorkspaceTreeEntry[] } }) => void) | null = null;

    tauriCommandMocks.readWorkspaceTreeNative
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFirst = resolve;
          }),
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveSecond = resolve;
          }),
      );

    const firstLoad = useProjectStore.getState().actions.loadRoot("/workspace/default");
    const secondLoad = useProjectStore.getState().actions.loadRoot("/workspace/default");

    expect(resolveSecond).not.toBeNull();
    resolveSecond!({
      ok: true,
      data: {
        entries: [{ path: "policies/new.yaml", kind: "file" }],
      },
    });
    await secondLoad;

    expect(resolveFirst).not.toBeNull();
    resolveFirst!({
      ok: true,
      data: {
        entries: [{ path: "policies/old.yaml", kind: "file" }],
      },
    });
    await firstLoad;

    const project = useProjectStore.getState().projects.get("/workspace/default");
    expect(hasPath(project?.files ?? [], "policies/new.yaml")).toBe(true);
    expect(hasPath(project?.files ?? [], "policies/old.yaml")).toBe(false);
    expect(useProjectStore.getState().rootCommittedVersionById.get("root-default")).toBe(2);
    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("ready");
  });

  it("marks an initial missing native tree response as an error", async () => {
    tauriCommandMocks.readWorkspaceTreeNative.mockResolvedValueOnce(null);

    await useProjectStore.getState().actions.loadRoot("/workspace/default");

    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("error");
    expect(useProjectStore.getState().rootErrorById.get("root-default")).toContain(
      "returned no response",
    );
    expect(useProjectStore.getState().rootCommittedVersionById.get("root-default")).toBe(0);
  });

  it("marks a failed refresh as stale while preserving the previously committed tree", async () => {
    const readyProject = makeProject("root-default", "/workspace/default");
    useProjectStore.setState((state) => ({
      ...state,
      project: readyProject,
      rootStatusById: new Map([["root-default", "ready"]]),
      rootErrorById: new Map([["root-default", null]]),
      rootRequestedVersionById: new Map([["root-default", 1]]),
      rootCommittedVersionById: new Map([["root-default", 1]]),
      rootMutationById: new Map([["root-default", null]]),
      projectsById: new Map([["root-default", readyProject]]),
      projects: new Map([["/workspace/default", readyProject]]),
    }));
    tauriCommandMocks.readWorkspaceTreeNative.mockResolvedValueOnce({
      ok: false,
      error: {
        code: "io_error",
        message: "disk offline",
      },
    });

    await useProjectStore.getState().actions.loadRoot("/workspace/default");

    expect(hasPath(useProjectStore.getState().projects.get("/workspace/default")?.files ?? [], "policies/default.yaml")).toBe(true);
    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("stale");
    expect(useProjectStore.getState().rootErrorById.get("root-default")).toBe("disk offline");
    expect(useProjectStore.getState().rootCommittedVersionById.get("root-default")).toBe(1);
  });

  it("marks a pending mutation as error when the follow-up refresh fails", async () => {
    const readyProject = makeProject("root-default", "/workspace/default");
    useProjectStore.setState((state) => ({
      ...state,
      project: readyProject,
      rootStatusById: new Map([["root-default", "ready"]]),
      rootErrorById: new Map([["root-default", null]]),
      rootRequestedVersionById: new Map([["root-default", 1]]),
      rootCommittedVersionById: new Map([["root-default", 1]]),
      rootMutationById: new Map([
        [
          "root-default",
          {
            kind: "rename",
            status: "pending",
            rootId: "root-default",
            rootPath: "/workspace/default",
            targetRelativePath: "policies/default.yaml",
            targetLabel: "default.yaml",
            message: null,
            updatedAt: 1,
          },
        ],
      ]),
      projectsById: new Map([["root-default", readyProject]]),
      projects: new Map([["/workspace/default", readyProject]]),
    }));
    tauriCommandMocks.readWorkspaceTreeNative.mockResolvedValueOnce({
      ok: false,
      error: {
        code: "io_error",
        message: "disk offline",
      },
    });

    await useProjectStore.getState().actions.loadRoot("/workspace/default");

    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("stale");
    expect(useProjectStore.getState().rootMutationById.get("root-default")).toMatchObject({
      status: "error",
      targetRelativePath: "policies/default.yaml",
      message: "disk offline",
    });
  });

  it("clears mutation state after the next successful committed scan", async () => {
    const readyProject = makeProject("root-default", "/workspace/default");
    useProjectStore.setState((state) => ({
      ...state,
      project: readyProject,
      rootStatusById: new Map([["root-default", "stale"]]),
      rootErrorById: new Map([["root-default", "disk offline"]]),
      rootRequestedVersionById: new Map([["root-default", 1]]),
      rootCommittedVersionById: new Map([["root-default", 1]]),
      rootMutationById: new Map([
        [
          "root-default",
          {
            kind: "create_folder",
            status: "error",
            rootId: "root-default",
            rootPath: "/workspace/default",
            targetRelativePath: "workspace/new-folder",
            targetLabel: "new-folder",
            message: "disk offline",
            updatedAt: 1,
          },
        ],
      ]),
      projectsById: new Map([["root-default", readyProject]]),
      projects: new Map([["/workspace/default", readyProject]]),
    }));
    tauriCommandMocks.readWorkspaceTreeNative.mockResolvedValueOnce({
      ok: true,
      data: {
        entries: [{ path: "workspace/new-folder", kind: "directory" }],
      },
    });

    await useProjectStore.getState().actions.loadRoot("/workspace/default");

    expect(useProjectStore.getState().rootStatusById.get("root-default")).toBe("ready");
    expect(useProjectStore.getState().rootErrorById.get("root-default")).toBeNull();
    expect(useProjectStore.getState().rootMutationById.get("root-default")).toBeNull();
  });
});

describe("workspace registry hydration", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
    useProjectStore.setState({
      project: null,
      loading: false,
      error: null,
      filter: "",
      formatFilter: null,
      fileStatuses: new Map(),
      defaultRootId: null,
      orderedRootIds: [],
      rootsById: new Map(),
      rootStatusById: new Map(),
      rootErrorById: new Map(),
      rootRequestedVersionById: new Map(),
      rootCommittedVersionById: new Map(),
      rootMutationById: new Map(),
      projectsById: new Map(),
      projectRoots: [],
      projects: new Map(),
      actions: originalProjectActions,
    });
  });

  it("hydrates snapshot state into rootId and compatibility views", () => {
    const snapshot = makeSnapshot([
      makeRootRecord("root-default", "/Users/test/.clawdstrike", {
        isDefault: true,
        kind: "default_home",
        provenance: "bootstrap",
        aliases: ["/Users/test/.clawdstrike/workspace"],
      }),
      makeRootRecord("root-repo", "/Users/test/repo"),
    ], "root-default");

    useProjectStore.getState().actions.hydrateWorkspaceRegistry(snapshot);

    const state = useProjectStore.getState();
    expect(state.defaultRootId).toBe("root-default");
    expect(state.orderedRootIds).toEqual(["root-default", "root-repo"]);
    expect(state.rootsById.get("root-default")?.displayPath).toBe("/Users/test/.clawdstrike");
    expect(state.projectsById.get("root-default")).toMatchObject({
      rootId: "root-default",
      rootPath: "/Users/test/.clawdstrike",
    });
    expect(state.projectRoots).toEqual([
      "/Users/test/.clawdstrike",
      "/Users/test/repo",
    ]);
    expect(state.projects.get("/Users/test/.clawdstrike")?.rootId).toBe("root-default");
    expect(state.project?.rootId).toBe("root-default");
  });

  it("adds and removes roots by hydrating backend registry snapshots", async () => {
    const initialSnapshot = makeSnapshot([
      makeRootRecord("root-default", "/Users/test/.clawdstrike", {
        isDefault: true,
        kind: "default_home",
        provenance: "bootstrap",
      }),
    ], "root-default");
    const addedSnapshot = makeSnapshot([
      initialSnapshot.roots[0],
      makeRootRecord("root-repo", "/Users/test/repo"),
    ], "root-default");
    tauriCommandMocks.addWorkspaceRootNative.mockResolvedValue(addedSnapshot);
    tauriCommandMocks.removeWorkspaceRootNative.mockResolvedValue(initialSnapshot);

    useProjectStore.getState().actions.hydrateWorkspaceRegistry(initialSnapshot);

    await useProjectStore.getState().actions.addRoot("/Users/test/repo");
    expect(useProjectStore.getState().projectRoots).toEqual([
      "/Users/test/.clawdstrike",
      "/Users/test/repo",
    ]);
    expect(tauriCommandMocks.addWorkspaceRootNative).toHaveBeenCalledWith("/Users/test/repo");

    await useProjectStore.getState().actions.removeRoot("/Users/test/repo");
    expect(useProjectStore.getState().projectRoots).toEqual(["/Users/test/.clawdstrike"]);
    expect(tauriCommandMocks.removeWorkspaceRootNative).toHaveBeenCalledWith("root-repo");
  });

  it("routes alias paths through the canonical root for file status compatibility", () => {
    const snapshot = makeSnapshot([
      makeRootRecord("root-default", "/Users/test/.clawdstrike", {
        isDefault: true,
        kind: "default_home",
        provenance: "bootstrap",
        aliases: ["/Users/test/.clawdstrike/workspace"],
      }),
    ], "root-default");

    useProjectStore.getState().actions.hydrateWorkspaceRegistry(snapshot);
    useProjectStore.getState().actions.setFileStatus(
      "/Users/test/.clawdstrike/workspace/policies/default.yaml",
      { modified: true },
    );

    expect(
      useProjectStore
        .getState()
        .fileStatuses.get(
          getProjectFileStatusKey(
            "/Users/test/.clawdstrike",
            "workspace/policies/default.yaml",
          ),
        ),
    ).toEqual({ modified: true });
  });

  it("canonicalizes aliased absolute paths through the workspace consumer contract", () => {
    const snapshot = makeSnapshot([
      makeRootRecord("root-default", "/Users/test/.clawdstrike", {
        isDefault: true,
        kind: "default_home",
        provenance: "bootstrap",
        aliases: ["/Users/test/.clawdstrike/workspace"],
      }),
    ], "root-default");

    useProjectStore.getState().actions.hydrateWorkspaceRegistry(snapshot);

    expect(
      canonicalizeWorkspaceConsumerPath(
        useProjectStore.getState(),
        "/Users/test/.clawdstrike/workspace",
      ),
    ).toBe("/Users/test/.clawdstrike");
    expect(
      canonicalizeWorkspaceConsumerPath(
        useProjectStore.getState(),
        "/Users/test/.clawdstrike/workspace/policies/default.yaml",
      ),
    ).toBe("/Users/test/.clawdstrike/workspace/policies/default.yaml");
  });

  it("derives canonical workspace root paths and default consumer root", () => {
    const snapshot = makeSnapshot([
      makeRootRecord("root-default", "/Users/test/.clawdstrike", {
        isDefault: true,
        kind: "default_home",
        provenance: "bootstrap",
      }),
      makeRootRecord("root-repo", "/Users/test/repo"),
    ], "root-default");

    useProjectStore.getState().actions.hydrateWorkspaceRegistry(snapshot);

    expect(getCanonicalWorkspaceRootPaths(useProjectStore.getState())).toEqual([
      "/Users/test/.clawdstrike",
      "/Users/test/repo",
    ]);
    expect(getDefaultWorkspaceConsumerRootPath(useProjectStore.getState())).toBe(
      "/Users/test/.clawdstrike",
    );
  });

  it("reports root readiness from the per-root terminal-state contract", () => {
    const snapshot = makeSnapshot([
      makeRootRecord("root-default", "/Users/test/.clawdstrike", {
        isDefault: true,
        kind: "default_home",
        provenance: "bootstrap",
      }),
    ], "root-default");

    useProjectStore.getState().actions.hydrateWorkspaceRegistry(snapshot);
    useProjectStore.setState((state) => ({
      ...state,
      rootStatusById: new Map([["root-default", "loading"]]),
    }));
    expect(isWorkspaceConsumerRootReady(useProjectStore.getState(), "root-default")).toBe(false);

    useProjectStore.setState((state) => ({
      ...state,
      rootStatusById: new Map([["root-default", "ready"]]),
    }));
    expect(
      isWorkspaceConsumerRootReady(useProjectStore.getState(), "/Users/test/.clawdstrike"),
    ).toBe(true);
  });
});
