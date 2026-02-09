/**
 * ShellLayout - Main application layout with navigation
 */
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { NavRail } from "./components/NavRail";
import { CommandPalette } from "./components/CommandPalette";
import { SOCBackground } from "./SOCBackground";
import { getPlugins } from "./plugins";
import { useActiveApp, useSessionActions } from "./sessions";
import { useShellShortcuts } from "./keyboard";
import type { AppId } from "./plugins/types";
import { dispatchCyberNexusCommand } from "@/features/cyber-nexus/events";
import { SHELL_OPEN_COMMAND_PALETTE_EVENT } from "./events";
import { DockProvider, DockSystem } from "./dock";

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
    return (fromRoute ?? fromStore ?? plugins[0]?.id ?? "cyber-nexus") as AppId;
  }, [plugins, routeAppId, storedActiveAppId]);

  const { createSession, setActiveApp } = useSessionActions();

  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  useEffect(() => {
    const open = () => setIsCommandPaletteOpen(true);
    window.addEventListener(SHELL_OPEN_COMMAND_PALETTE_EVENT, open);
    return () => window.removeEventListener(SHELL_OPEN_COMMAND_PALETTE_EVENT, open);
  }, []);

  const showAmbientBackground = useMemo(() => {
    const appId = location.pathname.split("/").filter(Boolean)[0] ?? "";
    return !new Set(["cyber-nexus", "swarm", "threat-radar", "attack-graph", "network-map", "security-overview"]).has(appId);
  }, [location.pathname]);
  const cyberNexusCommands = useMemo(() => {
    if (activeAppId !== "cyber-nexus") return [];

    return [
      {
        id: "nexus:reset-camera",
        group: "Camera",
        title: "Reset Nexus Camera",
        description: "Reset camera to default overview",
        action: () => dispatchCyberNexusCommand({ type: "reset-camera" }),
      },
      {
        id: "nexus:open-search",
        group: "Navigation",
        title: "Open Nexus Search",
        description: "Search runs, receipts, and strikecells",
        shortcut: "Cmd+F",
        action: () => dispatchCyberNexusCommand({ type: "open-search" }),
      },
      {
        id: "nexus:focus-prev",
        group: "Navigation",
        title: "Focus previous strikecell",
        shortcut: "[",
        action: () => dispatchCyberNexusCommand({ type: "focus-prev" }),
      },
      {
        id: "nexus:focus-next",
        group: "Navigation",
        title: "Focus next strikecell",
        shortcut: "]",
        action: () => dispatchCyberNexusCommand({ type: "focus-next" }),
      },
      {
        id: "nexus:layout-radial",
        group: "View",
        title: "Set layout: Radial Burst",
        action: () => dispatchCyberNexusCommand({ type: "set-layout", layoutMode: "radial" }),
      },
      {
        id: "nexus:layout-lanes",
        group: "View",
        title: "Set layout: Typed Lanes",
        action: () =>
          dispatchCyberNexusCommand({ type: "set-layout", layoutMode: "typed-lanes" }),
      },
      {
        id: "nexus:layout-force",
        group: "View",
        title: "Set layout: Force Directed",
        action: () =>
          dispatchCyberNexusCommand({ type: "set-layout", layoutMode: "force-directed" }),
      },
      {
        id: "nexus:view-galaxy",
        group: "View",
        title: "Set view: Galaxy",
        action: () => dispatchCyberNexusCommand({ type: "set-view-mode", viewMode: "galaxy" }),
      },
      {
        id: "nexus:view-grid",
        group: "View",
        title: "Set view: Grid",
        action: () => dispatchCyberNexusCommand({ type: "set-view-mode", viewMode: "grid" }),
      },
      {
        id: "nexus:toggle-field",
        group: "View",
        title: "Toggle Nexus Field",
        action: () => dispatchCyberNexusCommand({ type: "toggle-field" }),
      },
      {
        id: "nexus:mode-observe",
        group: "Simulation",
        title: "Set mode: Observe",
        description: "Passive posture with minimal intervention",
        action: () => dispatchCyberNexusCommand({ type: "set-operation-mode", mode: "observe" }),
      },
      {
        id: "nexus:mode-trace",
        group: "Simulation",
        title: "Set mode: Trace",
        description: "Increase telemetry and follow active paths",
        action: () => dispatchCyberNexusCommand({ type: "set-operation-mode", mode: "trace" }),
      },
      {
        id: "nexus:mode-contain",
        group: "Security / Policy",
        title: "Set mode: Contain",
        description: "Constrain movement and tighten guardrails",
        action: () => dispatchCyberNexusCommand({ type: "set-operation-mode", mode: "contain" }),
      },
      {
        id: "nexus:mode-execute",
        group: "Security / Policy",
        title: "Set mode: Execute",
        description: "Run direct response actions",
        action: () => dispatchCyberNexusCommand({ type: "set-operation-mode", mode: "execute" }),
      },
      {
        id: "nexus:focus-threat-radar",
        group: "Navigation",
        title: "Focus strikecell: Threat Radar",
        action: () =>
          dispatchCyberNexusCommand({
            type: "focus-strikecell",
            strikecellId: "threat-radar",
          }),
      },
      {
        id: "nexus:focus-attack-graph",
        group: "Navigation",
        title: "Focus strikecell: Attack Graph",
        action: () =>
          dispatchCyberNexusCommand({
            type: "focus-strikecell",
            strikecellId: "attack-graph",
          }),
      },
      {
        id: "nexus:focus-network",
        group: "Navigation",
        title: "Focus strikecell: Network Map",
        action: () =>
          dispatchCyberNexusCommand({
            type: "focus-strikecell",
            strikecellId: "network-map",
          }),
      },
      {
        id: "nexus:open-workflows-drawer",
        group: "Navigation",
        title: "Open overlay drawer: Workflows",
        action: () =>
          dispatchCyberNexusCommand({
            type: "open-drawer",
            strikecellId: "workflows",
          }),
      },
      {
        id: "nexus:open-marketplace-drawer",
        group: "Navigation",
        title: "Open overlay drawer: Marketplace",
        action: () =>
          dispatchCyberNexusCommand({
            type: "open-drawer",
            strikecellId: "marketplace",
          }),
      },
    ];
  }, [activeAppId]);

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
    onFocusSearch:
      activeAppId === "cyber-nexus"
        ? () => dispatchCyberNexusCommand({ type: "open-search" })
        : undefined,
    onSelectApp: handleSelectApp,
    onNextApp: handleNextApp,
    onPrevApp: handlePrevApp,
    onOpenSettings: () => handleSelectApp("settings"),
    onCloseModal: () => setIsCommandPaletteOpen(false),
  });

  return (
    <DockProvider>
      <div className="origin-shell-bg h-screen w-screen overflow-hidden bg-sdr-bg-primary">
        <div className="flex h-full w-full overflow-hidden">
          {/* Ambient 3D background */}
          {showAmbientBackground && <SOCBackground />}

          {/* Left navigation rail */}
          <NavRail activeAppId={activeAppId} onSelectApp={handleSelectApp} />

          {/* Main content area */}
          <main className="relative z-10 flex-1 flex flex-col overflow-hidden">
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
        </div>

        {/* Dock system - floating capsules and bottom rail */}
        <DockSystem demoMode={false} />

        {/* Command palette modal */}
        <CommandPalette
          isOpen={isCommandPaletteOpen}
          onClose={() => setIsCommandPaletteOpen(false)}
          onSelectApp={handleSelectApp}
          extraCommands={cyberNexusCommands}
        />
      </div>
    </DockProvider>
  );
}
