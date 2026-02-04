/**
 * ShellLayout - Main application layout with navigation
 */
import { Suspense, useCallback, useMemo, useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { NavRail } from "./components/NavRail";
import { CommandPalette } from "./components/CommandPalette";
import { getPlugins } from "./plugins";
import { useActiveApp, useSessionActions } from "./sessions";
import { useShellShortcuts } from "./keyboard";
import type { AppId } from "./plugins/types";

export function ShellLayout() {
  const navigate = useNavigate();
  const location = useLocation();

  const plugins = useMemo(() => getPlugins(), []);
  const routeAppId = useMemo(() => {
    const seg = location.pathname.split("/").filter(Boolean)[0];
    return seg ?? null;
  }, [location.pathname]);

  const storedActiveAppId = useActiveApp();
  const activeAppId = useMemo<AppId>(() => {
    const fromRoute = routeAppId && plugins.some((p) => p.id === routeAppId) ? routeAppId : null;
    const fromStore =
      storedActiveAppId && plugins.some((p) => p.id === storedActiveAppId)
        ? storedActiveAppId
        : null;
    return (fromRoute ?? fromStore ?? plugins[0]?.id ?? "events") as AppId;
  }, [plugins, routeAppId, storedActiveAppId]);

  const { createSession, setActiveApp } = useSessionActions();

  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  const handleSelectApp = useCallback(
    (appId: AppId) => {
      setActiveApp(appId);
      navigate(`/${appId}`);
    },
    [navigate, setActiveApp]
  );

  const handleNewSession = useCallback(() => {
    const session = createSession(activeAppId);
    navigate(`/${activeAppId}/${session.id}`);
  }, [activeAppId, createSession, navigate]);

  const handleNextApp = useCallback(() => {
    const currentIndex = plugins.findIndex((p) => p.id === activeAppId);
    const nextIndex = (currentIndex + 1) % plugins.length;
    handleSelectApp(plugins[nextIndex].id);
  }, [plugins, activeAppId, handleSelectApp]);

  const handlePrevApp = useCallback(() => {
    const currentIndex = plugins.findIndex((p) => p.id === activeAppId);
    const prevIndex = (currentIndex - 1 + plugins.length) % plugins.length;
    handleSelectApp(plugins[prevIndex].id);
  }, [plugins, activeAppId, handleSelectApp]);

  // Keyboard shortcuts
  useShellShortcuts({
    onNewSession: handleNewSession,
    onOpenPalette: () => setIsCommandPaletteOpen(true),
    onSelectApp: handleSelectApp,
    onNextApp: handleNextApp,
    onPrevApp: handlePrevApp,
    onOpenSettings: () => handleSelectApp("settings"),
    onCloseModal: () => setIsCommandPaletteOpen(false),
  });

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-sdr-bg-primary">
      {/* Left navigation rail */}
      <NavRail activeAppId={activeAppId} onSelectApp={handleSelectApp} />

      {/* Main content area */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Content */}
        <div className="flex-1 overflow-hidden">
          <Suspense
            fallback={
              <div className="flex items-center justify-center h-full text-sdr-text-secondary">
                Loading...
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </div>
      </main>

      {/* Command palette modal */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onSelectApp={handleSelectApp}
      />
    </div>
  );
}
