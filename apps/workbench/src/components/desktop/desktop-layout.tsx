import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Titlebar } from "@/components/desktop/titlebar";
import { StatusBar } from "@/components/desktop/status-bar";
import { DesktopSidebar } from "@/components/desktop/desktop-sidebar";
import { ShortcutProvider } from "@/components/desktop/shortcut-provider";
import { CrashRecoveryBanner } from "@/components/desktop/crash-recovery-banner";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useAutoSave } from "@/lib/workbench/use-auto-save";

export function DesktopLayout() {
  const { state } = useWorkbench();
  const { pendingRecovery, dismissRecovery } = useAutoSave();
  const location = useLocation();

  // Warn on window close / reload when there are unsaved changes
  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (state.dirty) {
        e.preventDefault();
      }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [state.dirty]);

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#05060a]">
      {/* Global keyboard shortcuts */}
      <ShortcutProvider />

      {/* Top: custom titlebar */}
      <Titlebar />

      {/* Crash recovery banner (shown when autosave detected on startup) */}
      {pendingRecovery && (
        <CrashRecoveryBanner
          entry={pendingRecovery}
          onDismiss={dismissRecovery}
        />
      )}

      {/* Middle: sidebar + routed content */}
      <div className="flex flex-1 min-h-0">
        <DesktopSidebar />

        <main className="flex-1 min-w-0 overflow-auto select-text">
          <div key={location.pathname} className="h-full page-transition-enter">
            <Outlet />
          </div>
        </main>
      </div>

      {/* Bottom: status bar */}
      <StatusBar />
    </div>
  );
}
