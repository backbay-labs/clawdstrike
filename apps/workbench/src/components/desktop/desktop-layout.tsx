import { useEffect, useLayoutEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Titlebar } from "@/components/desktop/titlebar";
import { StatusBar } from "@/components/desktop/status-bar";
import { ActivityBar } from "@/features/activity-bar/components/activity-bar";
import { SidebarPanel } from "@/features/activity-bar/components/sidebar-panel";
import { SidebarResizeHandle } from "@/features/activity-bar/components/sidebar-resize-handle";
import { ShortcutProvider } from "@/components/desktop/shortcut-provider";
import { CommandPalette } from "@/components/desktop/command-palette";
import { QuickOpenDialog } from "@/features/navigation/quick-open-dialog";
import { CrashRecoveryBanner } from "@/components/desktop/crash-recovery-banner";
import { BottomPane } from "@/features/bottom-pane/bottom-pane";
import { useBottomPaneStore } from "@/features/bottom-pane/bottom-pane-store";
import { RightSidebar } from "@/features/right-sidebar/components/right-sidebar";
import { RightSidebarResizeHandle } from "@/features/right-sidebar/components/right-sidebar-resize-handle";
import { useRightSidebarStore } from "@/features/right-sidebar/stores/right-sidebar-store";
import { PaneRoot } from "@/features/panes/pane-root";
import { getActivePaneRoute, usePaneStore } from "@/features/panes/pane-store";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { InitCommands } from "@/lib/commands/init-commands";
import { SpiritFieldInjector } from "@/features/spirit/components/spirit-field-injector";
import { useMultiPolicy } from "@/features/policy/stores/multi-policy-store";
import { useAutoSave } from "@/lib/workbench/use-auto-save";
import { normalizeWorkbenchRoute } from "./workbench-routes";

export function DesktopLayout() {
  const { tabs } = useMultiPolicy();
  const { pendingRecovery, dismissRecovery, restoreRecovery } = useAutoSave();
  const location = useLocation();
  const navigate = useNavigate();
  const bottomPaneOpen = useBottomPaneStore((state) => state.isOpen);
  const bottomPaneSize = useBottomPaneStore((state) => state.size);
  const rightSidebarVisible = useRightSidebarStore((state) => state.visible);
  const activePaneRoute = usePaneStore((state) =>
    getActivePaneRoute(state.root, state.activePaneId),
  );
  const hasDirtyTabs = tabs.some((tab) => tab.dirty);
  const rawRoute = `${location.pathname}${location.search}` || "/";
  const currentRoute = normalizeWorkbenchRoute(rawRoute);

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

  useLayoutEffect(() => {
    usePaneStore.getState().syncRoute(currentRoute);
  }, [currentRoute]);

  useEffect(() => {
    if (rawRoute === currentRoute) return;
    navigate(currentRoute, { replace: true });
  }, [currentRoute, navigate, rawRoute]);

  useEffect(() => {
    if (!activePaneRoute) return;
    const latestActivePaneRoute = getActivePaneRoute(
      usePaneStore.getState().root,
      usePaneStore.getState().activePaneId,
    );
    if (activePaneRoute !== latestActivePaneRoute) {
      return;
    }
    if (rawRoute !== currentRoute) return;
    if (activePaneRoute === rawRoute) return;
    navigate(activePaneRoute);
  }, [activePaneRoute, currentRoute, rawRoute, navigate]);

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#05060a]">
      {/* Spirit CSS var injection — must be first so vars are available to all children */}
      <SpiritFieldInjector />
      {/* Command registry initialization + global keyboard shortcuts */}
      <InitCommands />
      <ShortcutProvider />
      <CommandPalette />
      <QuickOpenDialog />

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
        <ActivityBar />
        <SidebarPanel />
        <SidebarResizeHandle />

        <main className="flex flex-1 min-w-0 flex-col overflow-hidden select-text">
          {bottomPaneOpen ? (
            <ResizablePanelGroup
              direction="vertical"
              className="h-full w-full"
              onLayout={(sizes) => {
                if (sizes.length >= 2) {
                  useBottomPaneStore.getState().setSize(sizes[1]);
                }
              }}
            >
              <ResizablePanel defaultSize={100 - bottomPaneSize} minSize={30}>
                <PaneRoot />
              </ResizablePanel>
              <ResizableHandle withHandle />
              <ResizablePanel defaultSize={bottomPaneSize} minSize={16}>
                <BottomPane />
              </ResizablePanel>
            </ResizablePanelGroup>
          ) : (
            <PaneRoot />
          )}
        </main>

        {rightSidebarVisible && (
          <>
            <RightSidebarResizeHandle />
            <RightSidebar />
          </>
        )}
      </div>

      {/* Bottom: status bar */}
      <StatusBar />
    </div>
  );
}
