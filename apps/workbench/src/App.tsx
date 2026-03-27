import { Component, Suspense, useEffect, useRef } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { HashRouter, useRoutes } from "react-router-dom";
import { ToastProvider } from "@/components/ui/toast";
import { HintSettingsProvider, useHintSettingsSafe } from "@/features/settings/use-hint-settings";
import { DesktopLayout } from "@/components/desktop/desktop-layout";
import { IdentityPrompt } from "@/components/workbench/identity/identity-prompt";
import { useOperator } from "@/features/operator/stores/operator-store";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { usePresenceConnection } from "@/features/presence/use-presence-connection";
import { usePresenceFileTracking } from "@/features/presence/use-presence-file-tracking";
import { usePolicyBootstrap } from "@/features/policy/hooks/use-policy-bootstrap";
import { secureStore, migrateCredentialsToStronghold } from "@/features/settings/secure-store";
import { bootstrapThreatIntelPlugins } from "@/lib/plugins/threat-intel/bootstrap";
import { useProjectStore } from "@/features/project/stores/project-store";
import { useToast } from "@/components/ui/toast";
import { usePaneStore } from "@/features/panes/pane-store";
import { useSignalCorrelator } from "@/features/findings/hooks/use-signal-correlator";

function LoadingFallback() {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        width: "100%",
        backgroundColor: "#05060a",
        color: "#6f7f9a",
        fontFamily:
          '"JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace',
        fontSize: "0.75rem",
        letterSpacing: "0.06em",
      }}
    >
      <div
        style={{
          width: 32,
          height: 2,
          backgroundColor: "#d4a84b",
          borderRadius: 1,
          marginBottom: 14,
          animation: "loading-bar 1.2s ease-in-out infinite",
        }}
      />
      <span
        style={{
          animation: "pulse 1.5s ease-in-out infinite",
          textTransform: "uppercase",
        }}
      >
        Loading&#8230;
      </span>
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.3; }
          50% { opacity: 0.8; }
        }
        @keyframes loading-bar {
          0%, 100% { transform: scaleX(0.3); opacity: 0.4; }
          50% { transform: scaleX(1); opacity: 1; }
        }
      `}</style>
    </div>
  );
}

/**
 * Bootstrap the workspace on first launch or restore persisted roots.
 *
 * - Always ensures ~/.clawdstrike/workspace/ exists (creates it if missing).
 * - If persisted roots exist (subsequent launches), restores them. If the
 *   default workspace path is not among the persisted roots it is added
 *   automatically so the Explorer never shows the raw ~/.clawdstrike config
 *   directory.
 * - If no roots exist (first launch), scaffolds the default workspace
 *   at ~/.clawdstrike/workspace/ and mounts it.
 *
 * Fire-and-forget: errors are logged but never thrown.
 */
/** Guard against StrictMode double-mount firing concurrent inits. */
let workspaceInitRunning = false;

/**
 * If the projects Map has no entry for `defaultPath`, inject a skeleton
 * DetectionProject directly (no Tauri calls). This guarantees the Explorer
 * always shows the workspace root, even when Tauri IPC is completely broken.
 *
 * Returns `true` if a skeleton was injected, `false` if the project was
 * already loaded normally.
 */
function ensureSkeletonProject(defaultPath: string): boolean {
  const { projectRoots, projects } = useProjectStore.getState();
  if (projects.has(defaultPath)) return false; // already loaded — nothing to do

  const name = defaultPath.split("/").filter(Boolean).pop() ?? "workspace";
  const skeleton = {
    rootPath: defaultPath,
    name,
    files: [],
    expandedDirs: new Set<string>(),
  };
  const nextRoots = projectRoots.includes(defaultPath) ? projectRoots : [defaultPath, ...projectRoots];
  const nextProjects = new Map(projects);
  nextProjects.set(defaultPath, skeleton);
  useProjectStore.setState({
    projectRoots: nextRoots,
    projects: nextProjects,
    project: skeleton,
  });
  console.warn("[workspace-bootstrap] Tauri IPC unavailable, showing skeleton workspace for:", defaultPath);
  return true;
}

/** Race a promise against a timeout. Returns the result or `fallback` on timeout. */
function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

/**
 * Derive the default workspace path without calling any Tauri APIs.
 * Uses the persisted roots or well-known OS conventions as fallback.
 */
function inferDefaultWorkspacePath(persistedRoots: string[]): string | null {
  // Check if any persisted root looks like the default workspace.
  const match = persistedRoots.find((r) => r.includes(".clawdstrike/workspace"));
  if (match) return match;

  // macOS/Linux: /Users/<name> or /home/<name>
  // We can infer from the origin or navigator.
  if (typeof location !== "undefined" && location.pathname) {
    // Tauri dev serves from the filesystem; not useful.
  }

  // Last resort: try to extract from any persisted root.
  for (const root of persistedRoots) {
    const homeMatch = root.match(/^(\/(?:Users|home)\/[^/]+)/);
    if (homeMatch) return `${homeMatch[1]}/.clawdstrike/workspace`;
  }

  return null;
}

function useWorkspaceBootstrap(toastRef: React.RefObject<ReturnType<typeof useToast>["toast"] | null>) {
  useEffect(() => {
    if (workspaceInitRunning) return;
    workspaceInitRunning = true;

    async function init() {
      const { isDesktop } = await import("@/lib/tauri-bridge");
      const { getWorkbenchE2EBridge } = await import("@/lib/workbench/e2e-bridge");
      const isWorkbenchE2E = getWorkbenchE2EBridge() !== null;
      if (!isDesktop() && !isWorkbenchE2E) return;

      const store = useProjectStore.getState();
      store.actions.setLoading(true);

      try {
        if (!isDesktop()) {
          if (store.projectRoots.length > 0) {
            await store.actions.initFromPersistedRoots();
          }
          return;
        }

        // Resolve the default workspace path. Use the Tauri path API with a
        // timeout — if Tauri IPC is slow or broken (common during dev mode
        // startup), fall back to inferring the path from persisted roots or
        // OS conventions so the Explorer never hangs on "Loading workspace".
        const { bootstrapDefaultWorkspace, getDefaultWorkspacePath } = await import(
          "@/features/project/workspace-bootstrap"
        );

        const TAURI_TIMEOUT_MS = 8_000;
        const workspacePath = await withTimeout(bootstrapDefaultWorkspace(), TAURI_TIMEOUT_MS, null);
        let defaultPath = workspacePath ?? await withTimeout(getDefaultWorkspacePath(), TAURI_TIMEOUT_MS, "");

        if (!defaultPath) {
          // Tauri IPC timed out — derive the path without Tauri.
          defaultPath = inferDefaultWorkspacePath(store.projectRoots) ?? "";
          if (defaultPath) {
            console.warn("[workspace-bootstrap] Tauri IPC timed out, using inferred workspace path:", defaultPath);
          }
        }

        if (!defaultPath) {
          console.warn("[workspace-bootstrap] Unable to resolve default workspace path");
          return;
        }

        const roots = store.projectRoots;

        if (roots.length > 0) {
          // Restore persisted workspace roots (loadRoot for each).
          await withTimeout(store.actions.initFromPersistedRoots(), TAURI_TIMEOUT_MS, undefined);

          // If the default workspace path is missing from persisted roots,
          // add it so the user always sees the workspace.
          const currentRoots = useProjectStore.getState().projectRoots;
          if (!currentRoots.includes(defaultPath)) {
            store.actions.addRoot(defaultPath);
          }
        } else {
          // First launch: mount the default workspace.
          store.actions.addRoot(defaultPath);
        }

        // Always ensure the default workspace is loaded in the projects Map.
        await withTimeout(store.actions.loadRoot(defaultPath), TAURI_TIMEOUT_MS, undefined);

        // Final safety net: if the projects Map is STILL empty (Tauri IPC
        // completely broken — readDir never resolved), inject a skeleton
        // project directly so the Explorer shows the workspace root with a
        // Refresh option instead of "No folder open".
        const usedSkeleton = ensureSkeletonProject(defaultPath);

        // If we fell back to a skeleton, schedule a deferred rescan once
        // Tauri IPC likely recovers (stale callbacks clear after a few seconds).
        if (usedSkeleton) {
          setTimeout(() => {
            void useProjectStore.getState().actions.loadRoot(defaultPath);
          }, 3_000);
        }
      } finally {
        useProjectStore.getState().actions.setLoading(false);
      }

      // Restore the previous pane session AFTER workspace roots are loaded
      // so that restored file panes can resolve against mounted projects.
      const count = usePaneStore.getState().restoreSession();
      if (count > 0 && toastRef.current) {
        toastRef.current({
          type: "info",
          title: `Restored ${count} file${count === 1 ? "" : "s"}`,
          description: "Your previous session has been restored",
          duration: 3000,
        });
      }
    }
    init().catch((err) => {
      console.warn("[workspace-bootstrap] Init failed:", err);
      useProjectStore.getState().actions.setLoading(false);
    }).finally(() => {
      workspaceInitRunning = false;
    });
  }, []);
}

function WorkbenchBootstraps() {
  const { toast } = useToast();
  const toastRef = useRef<typeof toast | null>(null);
  toastRef.current = toast;

  useOperator();
  useFleetConnection();
  usePresenceConnection();
  usePresenceFileTracking();
  useHintSettingsSafe();
  usePolicyBootstrap();
  useSignalCorrelator();
  useWorkspaceBootstrap(toastRef);
  return null;
}

function WorkbenchRouter() {
  return useRoutes([
    {
      path: "*",
      element: <DesktopLayout />,
    },
  ]);
}


interface ErrorBoundaryState {
  error: Error | null;
}

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[error-boundary]", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            height: "100vh",
            width: "100vw",
            backgroundColor: "#05060a",
            color: "#ece7dc",
            fontFamily:
              '"JetBrains Mono", ui-monospace, SFMono-Regular, "SF Mono", Menlo, monospace',
            padding: 32,
            textAlign: "center",
          }}
        >
          <div
            style={{
              width: 48,
              height: 3,
              backgroundColor: "#e74c3c",
              borderRadius: 2,
              marginBottom: 24,
            }}
          />
          <h1
            style={{
              fontSize: "1.1rem",
              fontWeight: 600,
              marginBottom: 12,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
              color: "#e74c3c",
            }}
          >
            Something went wrong
          </h1>
          <p
            style={{
              fontSize: "0.8rem",
              color: "#6f7f9a",
              marginBottom: 24,
              maxWidth: 480,
              lineHeight: 1.6,
              wordBreak: "break-word",
            }}
          >
            {this.state.error.message || "An unexpected error occurred."}
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            style={{
              padding: "8px 24px",
              fontSize: "0.75rem",
              fontFamily: "inherit",
              fontWeight: 600,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: "#05060a",
              backgroundColor: "#d4a84b",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
            }}
          >
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

function AppProviders({ children }: { children: ReactNode }) {
  return (
    <HintSettingsProvider>
      <ToastProvider>{children}</ToastProvider>
    </HintSettingsProvider>
  );
}

/**
 * Root application component for the Tauri desktop workbench.
 *
 * Uses HashRouter (required for Tauri -- file:// protocol does not
 * support HTML5 history pushState).
 */
export function App() {
  // Initialise Stronghold vault, migrate legacy credentials, then bootstrap threat intel plugins.
  useEffect(() => {
    async function bootstrapSecureStore() {
      try {
        await secureStore.init();
      } catch (err) {
        console.warn("[secure-store] Startup init failed:", err);
        return;
      }

      try {
        await migrateCredentialsToStronghold();
      } catch (err) {
        console.warn("[secure-store] Credential migration failed (non-fatal):", err);
      }

      await bootstrapThreatIntelPlugins();
    }

    bootstrapSecureStore().catch((err) => {
      console.warn("[plugins] Threat intel bootstrap failed:", err);
    });
  }, []);

  return (
    <HashRouter>
      <ErrorBoundary>
        <AppProviders>
          <Suspense fallback={<LoadingFallback />}>
            <WorkbenchBootstraps />
            <IdentityPrompt />
            <WorkbenchRouter />
          </Suspense>
        </AppProviders>
      </ErrorBoundary>
    </HashRouter>
  );
}
