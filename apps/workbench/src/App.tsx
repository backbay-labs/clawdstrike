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
import {
  clearLegacyWorkspaceRoots,
  readLegacyWorkspaceRoots,
  useProjectStore,
} from "@/features/project/stores/project-store";
import { useToast } from "@/components/ui/toast";
import { usePaneStore } from "@/features/panes/pane-store";
import { useSignalCorrelator } from "@/features/findings/hooks/use-signal-correlator";
import { bootstrapWorkspaceRegistryNative } from "@/lib/tauri-commands";
import { bootstrapDefaultWorkspaceContent } from "@/features/project/workspace-bootstrap";

const WORKSPACE_READY_TIMEOUT_MS = 4_000;

function formatDiagnosticError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  return "unknown_error";
}

function logWorkspaceBootstrap(
  level: "info" | "warn" | "error",
  event: string,
  detail: Record<string, unknown>,
): void {
  console[level]("[workspace-bootstrap]", {
    event,
    ...detail,
  });
}

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

function useWorkspaceBootstrap(toastRef: React.RefObject<ReturnType<typeof useToast>["toast"] | null>) {
  useEffect(() => {
    async function init() {
      const { isDesktop } = await import("@/lib/tauri-bridge");
      if (!isDesktop()) return;

      const store = useProjectStore.getState();
      if (store.loading) return;
      store.actions.setLoading(true);
      const startedAt = Date.now();

      try {
        const legacyRoots = readLegacyWorkspaceRoots();
        logWorkspaceBootstrap("info", "init_started", {
          legacyRootCount: legacyRoots.length,
        });
        const response = await bootstrapWorkspaceRegistryNative(legacyRoots);
        if (!response) {
          logWorkspaceBootstrap("warn", "registry_bootstrap_missing_snapshot", {
            legacyRootCount: legacyRoots.length,
          });
          return;
        }

        logWorkspaceBootstrap("info", "registry_bootstrapped", {
          rootCount: response.snapshot.roots.length,
          defaultRootId: response.snapshot.defaultRootId,
          migratedLegacyRootCount: response.migratedLegacyRoots.length,
          droppedLegacyRootCount: response.droppedLegacyRoots.length,
        });
        store.actions.hydrateWorkspaceRegistry(response.snapshot);
        await store.actions.initFromWorkspaceRegistry();
        const initialReadiness = await store.actions.waitForRootsReady(WORKSPACE_READY_TIMEOUT_MS);
        if (!initialReadiness.ready) {
          logWorkspaceBootstrap("warn", "roots_ready_timeout", {
            stage: "initial",
            pendingRootIds: initialReadiness.pendingRootIds,
            elapsedMs: initialReadiness.elapsedMs,
          });
        }
        clearLegacyWorkspaceRoots();

        const defaultRoot = response.snapshot.defaultRootId
          ? response.snapshot.roots.find((root) => root.rootId === response.snapshot.defaultRootId) ?? null
          : null;
        if (defaultRoot) {
          const bootstrapped = await bootstrapDefaultWorkspaceContent(defaultRoot.displayPath);
          logWorkspaceBootstrap("info", "default_content_bootstrap_complete", {
            rootId: defaultRoot.rootId,
            rootPath: defaultRoot.displayPath,
            bootstrapped,
          });
          if (bootstrapped) {
            await store.actions.loadRoot(defaultRoot.displayPath);
            const seededReadiness = await store.actions.waitForRootsReady(WORKSPACE_READY_TIMEOUT_MS);
            if (!seededReadiness.ready) {
              logWorkspaceBootstrap("warn", "roots_ready_timeout", {
                stage: "post_seed_refresh",
                pendingRootIds: seededReadiness.pendingRootIds,
                elapsedMs: seededReadiness.elapsedMs,
              });
            }
          }
        }
        logWorkspaceBootstrap("info", "init_complete", {
          elapsedMs: Date.now() - startedAt,
          rootCount: response.snapshot.roots.length,
          defaultRootId: response.snapshot.defaultRootId,
        });
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
      logWorkspaceBootstrap("error", "init_failed", {
        message: formatDiagnosticError(err),
      });
      useProjectStore.getState().actions.setLoading(false);
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
