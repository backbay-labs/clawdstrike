import { lazy, Suspense } from "react";
import { HashRouter, Routes, Route, Navigate } from "react-router-dom";
import { MultiPolicyProvider } from "@/lib/workbench/multi-policy-store";
import { FleetConnectionProvider } from "@/lib/workbench/use-fleet-connection";
import { ToastProvider } from "@/components/ui/toast";
import { DesktopLayout } from "@/components/desktop/desktop-layout";

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
// App root
// ---------------------------------------------------------------------------

/**
 * Root application component for the Tauri desktop workbench.
 *
 * Uses HashRouter (required for Tauri -- file:// protocol does not
 * support HTML5 history pushState).
 */
export function App() {
  return (
    <HashRouter>
      <ToastProvider>
        <MultiPolicyProvider>
          <FleetConnectionProvider>
            <Suspense fallback={<LoadingFallback />}>
              <Routes>
                <Route element={<DesktopLayout />}>
                  {/* Default redirect */}
                  <Route index element={<Navigate to="/editor" replace />} />

                  {/* Workbench pages */}
                  <Route path="editor" element={<PolicyEditor />} />
                  <Route path="simulator" element={<SimulatorLayout />} />
                  <Route path="compare" element={<CompareLayout />} />
                  <Route path="compliance" element={<ComplianceDashboard />} />
                  <Route path="receipts" element={<ReceiptInspector />} />
                  <Route path="delegation" element={<DelegationPage />} />
                  <Route path="approvals" element={<ApprovalQueue />} />
                  <Route path="hierarchy" element={<HierarchyPage />} />
                  <Route path="fleet" element={<FleetDashboard />} />
                  <Route path="audit" element={<AuditLog />} />
                  <Route path="library" element={<LibraryGallery />} />
                  <Route path="settings" element={<SettingsPage />} />

                  {/* Catch-all */}
                  <Route path="*" element={<Navigate to="/editor" replace />} />
                </Route>
              </Routes>
            </Suspense>
          </FleetConnectionProvider>
        </MultiPolicyProvider>
      </ToastProvider>
    </HashRouter>
  );
}
