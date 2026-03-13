import { useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { motion } from "motion/react";
import { Titlebar } from "@/components/desktop/titlebar";
import { StatusBar } from "@/components/desktop/status-bar";
import { DesktopSidebar } from "@/components/desktop/desktop-sidebar";
import { ShortcutProvider } from "@/components/desktop/shortcut-provider";
import { CommandPalette } from "@/components/desktop/command-palette";
import { CrashRecoveryBanner } from "@/components/desktop/crash-recovery-banner";
import { useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import { useAutoSave } from "@/lib/workbench/use-auto-save";

export function DesktopLayout() {
  const { tabs } = useMultiPolicy();
  const { pendingRecovery, dismissRecovery, restoreRecovery } = useAutoSave();
  const location = useLocation();
  const hasDirtyTabs = tabs.some((tab) => tab.dirty);

  // Warn on window close / reload when there are unsaved changes
  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (hasDirtyTabs) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [hasDirtyTabs]);

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#05060a]">
      {/* Global keyboard shortcuts */}
      <ShortcutProvider />
      <CommandPalette />

      {/* Top: custom titlebar */}
      <Titlebar />

      {/* Crash recovery banner (shown when autosave detected on startup) */}
      {pendingRecovery && pendingRecovery.length > 0 && (
        <CrashRecoveryBanner
          entries={pendingRecovery}
          onRestore={restoreRecovery}
          onDismiss={dismissRecovery}
        />
      )}

      {/* Middle: sidebar + routed content */}
      <div className="flex flex-1 min-h-0">
        <DesktopSidebar />

        <main className="flex-1 min-w-0 overflow-hidden select-text">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.15, ease: "easeOut" }}
            className="h-full overflow-auto"
          >
            <Outlet />
          </motion.div>
        </main>
      </div>

      {/* Bottom: status bar */}
      <StatusBar />
    </div>
  );
}
