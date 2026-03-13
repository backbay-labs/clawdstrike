import { Component, lazy, Suspense, useEffect } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { MultiPolicyProvider } from "@/lib/workbench/multi-policy-store";
import { FleetConnectionProvider } from "@/lib/workbench/use-fleet-connection";
import { GeneralSettingsProvider } from "@/lib/workbench/use-general-settings";
import { HintSettingsProvider } from "@/lib/workbench/use-hint-settings";
import { ToastProvider } from "@/components/ui/toast";
import { DesktopLayout } from "@/components/desktop/desktop-layout";
import { secureStore, migrateCredentialsToStronghold } from "@/lib/workbench/secure-store";

// ---------------------------------------------------------------------------
// Lazy-loaded route components (code-split into separate chunks)
// ---------------------------------------------------------------------------

const PolicyEditor = lazy(() =>
  import("@/components/workbench/editor/policy-editor").then((m) => ({
    default: m.PolicyEditor,
  })),
);

const SimulatorLayout = lazy(() =>
  import("@/components/workbench/simulator/simulator-layout").then((m) => ({
    default: m.SimulatorLayout,
  })),
);

const CompareLayout = lazy(() =>
  import("@/components/workbench/compare/compare-layout").then((m) => ({
    default: m.CompareLayout,
  })),
);

const ComplianceDashboard = lazy(() =>
  import("@/components/workbench/compliance/compliance-dashboard").then(
    (m) => ({ default: m.ComplianceDashboard }),
  ),
);

const ReceiptInspector = lazy(() =>
  import("@/components/workbench/receipts/receipt-inspector").then((m) => ({
    default: m.ReceiptInspector,
  })),
);

const LibraryGallery = lazy(() =>
  import("@/components/workbench/library/library-gallery").then((m) => ({
    default: m.LibraryGallery,
  })),
);

const SettingsPage = lazy(() =>
  import("@/components/workbench/settings/settings-page").then((m) => ({
    default: m.SettingsPage,
  })),
);

const DelegationPage = lazy(() =>
  import("@/components/workbench/delegation/delegation-page").then((m) => ({
    default: m.DelegationPage,
  })),
);

const ApprovalQueue = lazy(() =>
  import("@/components/workbench/approvals/approval-queue").then((m) => ({
    default: m.ApprovalQueue,
  })),
);

const HierarchyPage = lazy(() =>
  import("@/components/workbench/hierarchy/hierarchy-page").then((m) => ({
    default: m.HierarchyPage,
  })),
);

const FleetDashboard = lazy(() =>
  import("@/components/workbench/fleet/fleet-dashboard").then((m) => ({
    default: m.FleetDashboard,
  })),
);

const AuditLog = lazy(() =>
  import("@/components/workbench/audit/audit-log").then((m) => ({
    default: m.AuditLog,
  })),
);

const HomePage = lazy(() =>
  import("@/components/workbench/home/home-page").then((m) => ({
    default: m.HomePage,
  })),
);

const HuntLayout = lazy(() =>
  import("@/components/workbench/hunt/hunt-layout").then((m) => ({
    default: m.HuntLayout,
  })),
);

const GuardsPage = lazy(() =>
  import("@/components/workbench/guards/guards-page").then((m) => ({
    default: m.GuardsPage,
  })),
);

// ---------------------------------------------------------------------------
// Loading fallback — dark-themed to prevent white flash in Tauri shell
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Error boundary — prevents white-screen-of-death on unhandled errors (#3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// App root
// ---------------------------------------------------------------------------

/**
 * Root application component for the Tauri desktop workbench.
 *
 * Uses HashRouter (required for Tauri -- file:// protocol does not
 * support HTML5 history pushState).
 */
export function App() {
  // Initialise Stronghold vault + migrate legacy localStorage credentials on first launch.
  useEffect(() => {
    secureStore.init().then(() => migrateCredentialsToStronghold()).catch((err) => {
      console.warn("[secure-store] Stronghold init failed:", err);
    });
  }, []);

  return (
    <HashRouter>
      <ErrorBoundary>
        <ToastProvider>
          <GeneralSettingsProvider>
            <HintSettingsProvider>
              <MultiPolicyProvider>
                <FleetConnectionProvider>
                  <Suspense fallback={<LoadingFallback />}>
                    <Routes>
                      <Route element={<DesktopLayout />}>
                        {/* Default redirect */}
                        <Route index element={<Navigate to="/home" replace />} />

                        {/* Workbench pages */}
                        <Route path="home" element={<HomePage />} />
                        <Route path="editor" element={<PolicyEditor />} />
                        <Route path="simulator" element={<SimulatorLayout />} />
                        <Route path="hunt" element={<HuntLayout />} />
                        <Route path="compare" element={<CompareLayout />} />
                        <Route path="compliance" element={<ComplianceDashboard />} />
                        <Route path="receipts" element={<ReceiptInspector />} />
                        <Route path="delegation" element={<DelegationPage />} />
                        <Route path="approvals" element={<ApprovalQueue />} />
                        <Route path="hierarchy" element={<HierarchyPage />} />
                        <Route path="fleet" element={<FleetDashboard />} />
                        <Route path="audit" element={<AuditLog />} />
                        <Route path="guards" element={<GuardsPage />} />
                        <Route path="library" element={<LibraryGallery />} />
                        <Route path="settings" element={<SettingsPage />} />

                        {/* Catch-all */}
                        <Route path="*" element={<Navigate to="/home" replace />} />
                      </Route>
                    </Routes>
                  </Suspense>
                </FleetConnectionProvider>
              </MultiPolicyProvider>
            </HintSettingsProvider>
          </GeneralSettingsProvider>
        </ToastProvider>
      </ErrorBoundary>
    </HashRouter>
  );
}
