import { clsx } from "clsx";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getWorkspaceShellSnapshot,
  registerWorkspaceRoot,
  type WorkspaceEntry,
  type WorkspaceRoot,
  type WorkspaceServiceError,
} from "@/services/workspace";
import { WorkspaceEditorPane } from "@/features/workspace/editor";
import {
  createWorkspaceSurfaceState,
  focusWorkspacePane,
  getWorkspaceActiveTab,
  selectWorkspacePath,
  setWorkspaceAccessDenied,
  setWorkspaceActiveRoot,
  toggleWorkspaceTreePath,
  upsertWorkspaceTab,
  type WorkspaceRouteSection,
  type WorkspaceSurfaceState,
} from "@/features/workspace/state/workspaceShellState";
import { WORKSPACE_OPEN_FOLDER_EVENT } from "@/features/workspace/shell/workspaceCommands";
import { WorkspaceBreadcrumbs, findWorkspaceEntryByPath } from "@/features/workspace/tree/WorkspaceBreadcrumbs";
import { WorkspaceTreeView } from "@/features/workspace/tree/WorkspaceTreeView";

interface WorkspaceShellScreenProps {
  section?: WorkspaceRouteSection;
}

const SECTION_LABELS: Record<WorkspaceRouteSection, string> = {
  workspace: "Overview",
  tree: "Tree",
  search: "Search",
  git: "Git",
  terminal: "Terminal",
  file: "File",
};

const PANEL_BUTTONS: Array<{ id: WorkspaceRouteSection; label: string }> = [
  { id: "tree", label: "Explorer" },
  { id: "search", label: "Search" },
  { id: "git", label: "Git" },
  { id: "terminal", label: "Terminal" },
];

export function WorkspaceShellScreen({ section = "workspace" }: WorkspaceShellScreenProps) {
  const [state, setState] = useState<WorkspaceSurfaceState>(() =>
    createWorkspaceSurfaceState({ roots: [], tree: [], suggestedTabs: [] }),
  );
  const [isLoading, setIsLoading] = useState(true);
  const [dirtyBuffers, setDirtyBuffers] = useState<Record<string, boolean>>({});
  const [registerRootPath, setRegisterRootPath] = useState("");

  const updateDirtyBufferState = useCallback((rootId: string, relativePath: string, isDirty: boolean) => {
    const dirtyKey = `${rootId}::${relativePath}`;
    setDirtyBuffers((current) => {
      if (!isDirty && !current[dirtyKey]) {
        return current;
      }

      if (!isDirty) {
        const nextState = { ...current };
        delete nextState[dirtyKey];
        return nextState;
      }

      return {
        ...current,
        [dirtyKey]: true,
      };
    });
  }, []);

  const applySnapshot = useCallback(
    (snapshot: Awaited<ReturnType<typeof getWorkspaceShellSnapshot>>) => {
      const nextState = createWorkspaceSurfaceState(snapshot);
      setDirtyBuffers({});
      setState({
        ...nextState,
        route: { section, activeFilePath: nextState.route.activeFilePath },
      });
    },
    [section],
  );

  useEffect(() => {
    let cancelled = false;

    async function loadSnapshot() {
      setIsLoading(true);
      try {
        const snapshot = await getWorkspaceShellSnapshot();
        if (cancelled) return;

        applySnapshot(snapshot);
      } catch (error) {
        if (cancelled) return;

        const serviceError = error as WorkspaceServiceError;
        setState((current) =>
          setWorkspaceAccessDenied(current, {
            code: serviceError.code ?? "workspace_request_failed",
            message: serviceError.message,
          }),
        );
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    loadSnapshot();
    return () => {
      cancelled = true;
    };
  }, [applySnapshot]);

  const activeRoot = useMemo(
    () => state.roots.find((root) => root.id === state.activeRootId) ?? state.roots[0],
    [state.activeRootId, state.roots],
  );

  const activeEntry = useMemo(
    () => findWorkspaceEntryByPath(state.rootTree, state.route.activeFilePath),
    [state.rootTree, state.route.activeFilePath],
  );

  const activeTab = useMemo(() => getWorkspaceActiveTab(state), [state]);

  const handleSelectEntry = useCallback((entry: WorkspaceEntry) => {
    setState((current) => {
      if (entry.kind === "directory") {
        return focusWorkspacePane(current, "workspace-tree");
      }

      const existingTab = current.tabs.find((candidate) => candidate.relativePath === entry.relativePath);

      return upsertWorkspaceTab(
        selectWorkspacePath(current, entry.relativePath),
        existingTab ?? {
          id: `workspace-${entry.relativePath}`,
          title: entry.name,
          relativePath: entry.relativePath,
          kind: "file",
        },
      );
    });
  }, []);

  const handleTrustRoot = useCallback(async () => {
    const candidate = registerRootPath.trim() || window.prompt?.("Candidate workspace path")?.trim();
    if (!candidate) return;

    setIsLoading(true);
    try {
      await registerWorkspaceRoot(candidate);
      const snapshot = await getWorkspaceShellSnapshot();
      applySnapshot(snapshot);
      setRegisterRootPath("");
    } catch (error) {
      const serviceError = error as WorkspaceServiceError;
      setState((current) =>
        setWorkspaceAccessDenied(current, {
          code: serviceError.code ?? "workspace_request_failed",
          message: serviceError.message,
        }),
      );
    } finally {
      setIsLoading(false);
    }
  }, [applySnapshot, registerRootPath]);

  useEffect(() => {
    const handleOpenFolder = () => {
      void handleTrustRoot();
    };

    window.addEventListener(WORKSPACE_OPEN_FOLDER_EVENT, handleOpenFolder);
    return () => {
      window.removeEventListener(WORKSPACE_OPEN_FOLDER_EVENT, handleOpenFolder);
    };
  }, [handleTrustRoot]);

  const rootSummary = activeRoot
    ? `${activeRoot.name} · ${activeRoot.canonicalPath}`
    : "No trusted root selected";

  return (
    <div className="flex h-full flex-col gap-4 p-5 text-sdr-text-primary">
      <header className="premium-panel rounded-2xl p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="origin-label text-[10px] uppercase tracking-[0.18em] text-[color:rgba(213,173,87,0.86)]">
              Workspace Shell
            </div>
            <h1 className="mt-2 text-2xl font-semibold">Trusted roots and route-aware authoring</h1>
            <p className="mt-2 max-w-3xl text-sm text-sdr-text-muted">
              This WS3 scaffold reserves the tree, breadcrumbs, tab frame, and pane-state contract before
              Monaco, PTY, git, or search UX lands in later lanes.
            </p>
          </div>
          <div className="min-w-[280px] rounded-xl border border-sdr-border bg-sdr-bg-primary/40 p-3 text-sm">
            <div className="text-sdr-text-secondary">Active route</div>
            <div className="mt-1 font-medium">{SECTION_LABELS[state.route.section]}</div>
            <div className="mt-3 text-sdr-text-secondary">Root summary</div>
            <div className="mt-1 break-all text-xs text-sdr-text-muted">{rootSummary}</div>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          {PANEL_BUTTONS.map((panel) => (
            <button
              key={panel.id}
              type="button"
              onClick={() => setState((current) => ({ ...current, route: { section: panel.id } }))}
              className={clsx(
                "rounded-full border px-3 py-1.5 text-xs uppercase tracking-[0.12em]",
                state.route.section === panel.id
                  ? "border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] text-sdr-text-primary"
                  : "border-sdr-border text-sdr-text-muted hover:text-sdr-text-primary",
              )}
            >
              {panel.label}
            </button>
          ))}
        </div>
      </header>

      {isLoading ? (
        <WorkspaceStatusCard title="Loading workspace shell" description="Fetching trusted roots and initial tree snapshot." />
      ) : state.access === "denied" ? (
        <WorkspaceDeniedState errorMessage={state.lastError?.message} registerRootPath={registerRootPath} onChangeRegisterRootPath={setRegisterRootPath} onTrustRoot={handleTrustRoot} />
      ) : state.access === "empty" ? (
        <WorkspaceEmptyState registerRootPath={registerRootPath} onChangeRegisterRootPath={setRegisterRootPath} onTrustRoot={handleTrustRoot} />
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-[minmax(260px,300px)_minmax(0,1fr)_320px] gap-4">
          <section className="premium-panel flex min-h-0 flex-col rounded-2xl p-3">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">Explorer</div>
                <div className="text-xs text-sdr-text-muted">Tree state stays local; trust stays backend-owned.</div>
              </div>
              {state.roots.length > 1 ? (
                <select
                  aria-label="Trusted workspace roots"
                  value={activeRoot?.id}
                  onChange={(event) => setState((current) => setWorkspaceActiveRoot(current, event.target.value))}
                  className="rounded-lg border border-sdr-border bg-sdr-bg-primary/60 px-2 py-1 text-xs text-sdr-text-primary"
                >
                  {state.roots.map((root) => (
                    <option key={root.id} value={root.id}>
                      {root.name}
                    </option>
                  ))}
                </select>
              ) : null}
            </div>

            <div className="min-h-0 flex-1 overflow-auto rounded-xl border border-sdr-border bg-sdr-bg-primary/30 p-2">
              <WorkspaceTreeView
                entries={state.rootTree}
                expandedPaths={state.tree.expandedPaths}
                selectedPath={state.tree.selectedPath}
                onToggleDirectory={(relativePath) =>
                  setState((current) => toggleWorkspaceTreePath(current, relativePath))
                }
                onSelectEntry={handleSelectEntry}
              />
            </div>
          </section>

          <section className="flex min-h-0 flex-col gap-4">
            <div className="premium-panel rounded-2xl p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <WorkspaceBreadcrumbs
                  rootName={activeRoot?.name}
                  activePath={state.route.activeFilePath}
                  onSelectPath={(relativePath) =>
                    relativePath ? setState((current) => selectWorkspacePath(current, relativePath)) : undefined
                  }
                />
                <div className="text-xs uppercase tracking-[0.12em] text-sdr-text-muted">
                  Focused pane: {state.focusedPane}
                </div>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                {state.tabs.length ? (
                  state.tabs.map((tab) => {
                    const isActive = tab.relativePath === state.route.activeFilePath;
                    const isDirty = Boolean(
                      activeRoot && dirtyBuffers[`${activeRoot.id}::${tab.relativePath}`],
                    );
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() =>
                          setState((current) => ({
                            ...current,
                            route: { section: "file", activeFilePath: tab.relativePath },
                          }))
                        }
                        className={clsx(
                          "rounded-full border px-3 py-1.5 text-xs",
                          isActive
                            ? "border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] text-sdr-text-primary"
                            : "border-sdr-border text-sdr-text-muted",
                        )}
                      >
                        <span className="inline-flex items-center gap-2">
                          <span>{tab.title}</span>
                          {isDirty ? <span className="text-[color:rgba(238,220,166,0.96)]">•</span> : null}
                        </span>
                      </button>
                    );
                  })
                ) : (
                  <div className="rounded-xl border border-dashed border-sdr-border px-3 py-2 text-xs text-sdr-text-muted">
                    No workspace tabs yet. Selecting a file will seed the editor frame for WS4.
                  </div>
                )}
              </div>
            </div>

            <div className="grid min-h-0 flex-1 grid-rows-[minmax(0,1fr)_180px] gap-4">
              <section
                className="premium-panel min-h-0 rounded-2xl p-4"
                onClick={() => setState((current) => focusWorkspacePane(current, "main"))}
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-medium">{SECTION_LABELS[state.route.section]} pane</div>
                    <div className="text-xs text-sdr-text-muted">
                      {activeEntry?.relativePath ?? "Route-scoped workspace overview"}
                    </div>
                  </div>
                  <div className="rounded-full border border-sdr-border px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-sdr-text-muted">
                    Main pane
                  </div>
                </div>

                <div className="mt-4 h-[calc(100%-2.5rem)] overflow-auto rounded-xl border border-sdr-border bg-sdr-bg-primary/30 p-4">
                  <WorkspaceMainPane
                    section={state.route.section}
                    activeRoot={activeRoot}
                    activeTabTitle={activeTab?.title}
                    activeFilePath={state.route.activeFilePath}
                    onDirtyStateChange={updateDirtyBufferState}
                  />
                </div>
              </section>

              <section
                className="premium-panel rounded-2xl p-4"
                onClick={() => setState((current) => focusWorkspacePane(current, "bottom"))}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium">Bottom panel</div>
                    <div className="text-xs text-sdr-text-muted">Command output, tasks, and terminals anchor here later.</div>
                  </div>
                  <div className="rounded-full border border-sdr-border px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-sdr-text-muted">
                    Reserved
                  </div>
                </div>

                <div className="mt-4 grid gap-2 text-sm text-sdr-text-secondary">
                  <PanelRow label="Command entry" value="Ready for workspace palette integration" />
                  <PanelRow label="Search lane" value="WS6 deep-links into this panel" />
                  <PanelRow label="Terminal lane" value="WS5 mounts PTY tabs here" />
                </div>
              </section>
            </div>
          </section>

          <section
            className="premium-panel flex min-h-0 flex-col rounded-2xl p-4"
            onClick={() => setState((current) => focusWorkspacePane(current, "right"))}
          >
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-medium">Inspector</div>
                <div className="text-xs text-sdr-text-muted">Trust-root metadata and pane state live here.</div>
              </div>
              <div className="rounded-full border border-sdr-border px-2 py-1 text-[11px] uppercase tracking-[0.12em] text-sdr-text-muted">
                Right pane
              </div>
            </div>

            <div className="mt-4 space-y-3 overflow-auto text-sm">
              <InspectorCard title="Trusted root" body={activeRoot?.name ?? "No active root"} />
              <InspectorCard title="Canonical path" body={activeRoot?.canonicalPath ?? "Awaiting trust registration"} />
              <InspectorCard title="Focused route" body={SECTION_LABELS[state.route.section]} />
              <InspectorCard title="Selected path" body={state.tree.selectedPath ?? "Nothing selected"} />
              <InspectorCard
                title="Merge note"
                body="ORCH owns shell registration. This WS3 surface is integration-ready and confined to workspace-owned paths."
              />
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function WorkspaceMainPane({
  section,
  activeRoot,
  activeTabTitle,
  activeFilePath,
  onDirtyStateChange,
}: {
  section: WorkspaceRouteSection;
  activeRoot?: WorkspaceRoot;
  activeTabTitle?: string;
  activeFilePath?: string;
  onDirtyStateChange: (rootId: string, relativePath: string, isDirty: boolean) => void;
}) {
  if (section === "workspace") {
    return (
      <div className="space-y-3 text-sm text-sdr-text-secondary">
        <p>Workspace overview keeps shell state coherent while the backend owns trust roots and file truth.</p>
        <PanelRow label="Active root" value={activeRoot?.name ?? "None"} />
        <PanelRow label="Tabs scaffolded" value={activeTabTitle ? "Yes" : "Not yet"} />
        <PanelRow label="Command model" value="Route-based, not legacy plugin-card based" />
      </div>
    );
  }

  if (section === "search") {
    return <PlaceholderPanel title="Search reserved for WS6" description="Quick-open and content-search results will stream into this pane." />;
  }

  if (section === "git") {
    return <PlaceholderPanel title="Git status reserved for WS6" description="Branch, ahead/behind, and changed-file summary will anchor here." />;
  }

  if (section === "terminal") {
    return <PlaceholderPanel title="Terminal reserved for WS5" description="PTY-backed shell and task sessions mount here without taking over the explorer." />;
  }

  return (
    <WorkspaceEditorPane
      rootId={activeRoot?.id}
      activeFilePath={activeFilePath}
      activeTabTitle={activeTabTitle}
      onDirtyStateChange={onDirtyStateChange}
    />
  );
}

function WorkspaceEmptyState({
  registerRootPath,
  onChangeRegisterRootPath,
  onTrustRoot,
}: {
  registerRootPath: string;
  onChangeRegisterRootPath: (value: string) => void;
  onTrustRoot: () => void;
}) {
  return (
    <WorkspaceStatusCard title="No trusted roots yet" description="Register a workspace root before tree, search, Monaco, PTY, or git features activate.">
      <WorkspaceRootForm registerRootPath={registerRootPath} onChangeRegisterRootPath={onChangeRegisterRootPath} onTrustRoot={onTrustRoot} actionLabel="Register trusted root" />
    </WorkspaceStatusCard>
  );
}

function WorkspaceDeniedState({
  errorMessage,
  registerRootPath,
  onChangeRegisterRootPath,
  onTrustRoot,
}: {
  errorMessage?: string;
  registerRootPath: string;
  onChangeRegisterRootPath: (value: string) => void;
  onTrustRoot: () => void;
}) {
  return (
    <WorkspaceStatusCard title="Workspace access denied" description={errorMessage ?? "The backend rejected the requested root or path."}>
      <WorkspaceRootForm registerRootPath={registerRootPath} onChangeRegisterRootPath={onChangeRegisterRootPath} onTrustRoot={onTrustRoot} actionLabel="Try another candidate path" />
    </WorkspaceStatusCard>
  );
}

function WorkspaceRootForm({
  registerRootPath,
  onChangeRegisterRootPath,
  onTrustRoot,
  actionLabel,
}: {
  registerRootPath: string;
  onChangeRegisterRootPath: (value: string) => void;
  onTrustRoot: () => void;
  actionLabel: string;
}) {
  return (
    <div className="mt-4 flex flex-wrap items-center gap-3">
      <input
        type="text"
        value={registerRootPath}
        onChange={(event) => onChangeRegisterRootPath(event.target.value)}
        placeholder="/path/to/trusted/root"
        className="min-w-[280px] flex-1 rounded-xl border border-sdr-border bg-sdr-bg-primary/50 px-3 py-2 text-sm text-sdr-text-primary placeholder:text-sdr-text-muted"
      />
      <button
        type="button"
        onClick={onTrustRoot}
        className="rounded-xl border border-[color:rgba(213,173,87,0.8)] bg-[rgba(213,173,87,0.12)] px-4 py-2 text-sm text-sdr-text-primary"
      >
        {actionLabel}
      </button>
    </div>
  );
}

function WorkspaceStatusCard({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <section className="premium-panel rounded-2xl p-6">
      <div className="max-w-2xl">
        <div className="text-lg font-semibold text-sdr-text-primary">{title}</div>
        <p className="mt-2 text-sm text-sdr-text-muted">{description}</p>
        {children}
      </div>
    </section>
  );
}

function PlaceholderPanel({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-xl border border-dashed border-sdr-border p-4 text-sm text-sdr-text-secondary">
      <div className="font-medium text-sdr-text-primary">{title}</div>
      <p className="mt-2 text-sdr-text-muted">{description}</p>
    </div>
  );
}

function InspectorCard({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-sdr-border bg-sdr-bg-primary/30 p-3">
      <div className="text-xs uppercase tracking-[0.12em] text-sdr-text-muted">{title}</div>
      <div className="mt-2 break-words text-sdr-text-primary">{body}</div>
    </div>
  );
}

function PanelRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-xl border border-sdr-border bg-sdr-bg-primary/20 px-3 py-2">
      <span className="text-sdr-text-muted">{label}</span>
      <span className="text-right text-sdr-text-primary">{value}</span>
    </div>
  );
}
