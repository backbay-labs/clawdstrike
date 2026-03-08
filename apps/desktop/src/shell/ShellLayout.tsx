/**
 * ShellLayout - Main application layout with navigation
 */
import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import type { BlockerFunction } from "react-router-dom";
import { Outlet, useBlocker, useLocation, useNavigate } from "react-router-dom";
import { useConnection } from "@/context/ConnectionContext";
import { dispatchCyberNexusCommand } from "@/features/cyber-nexus/events";
import { ChronicleWorkbenchShelf } from "@/features/forensics/policy-workbench/ChronicleWorkbenchShelf";
import {
  POLICY_WORKBENCH_DIRTY_EVENT,
  type PolicyWorkbenchDirtyEventDetail,
} from "@/features/forensics/policy-workbench/events";
import { isPolicyWorkbenchEnabled } from "@/features/forensics/policy-workbench/featureFlags";
import { CommandPalette } from "./components/CommandPalette";
import { HuntronomerLaunchOverlay } from "./components/HuntronomerLaunchOverlay";
import { NavRail } from "./components/NavRail";
import { DockProvider, DockSystem } from "./dock";
import { SHELL_OPEN_COMMAND_PALETTE_EVENT } from "./events";
import { useShellShortcuts } from "./keyboard";
import { getPlugins, getVisiblePlugins } from "./plugins";
import type { AppId } from "./plugins/types";
import { shouldBlockDirtyPolicyDraftExit } from "./policyDraftGuard";
import { SOCBackground } from "./SOCBackground";
import { useActiveApp, useSessionActions } from "./sessions";

const HUNTRONOMER_LAUNCH_DISMISSED_KEY = "huntronomer:launch:dismissed:v1";

function shouldShowHuntronomerLaunch(): boolean {
  try {
    return globalThis.localStorage?.getItem(HUNTRONOMER_LAUNCH_DISMISSED_KEY) !== "1";
  } catch {
    return true;
  }
}

function persistHuntronomerLaunchDismissal() {
  try {
    globalThis.localStorage?.setItem(HUNTRONOMER_LAUNCH_DISMISSED_KEY, "1");
  } catch {
    // Ignore storage errors in restricted or embedded runtimes.
  }
}

export function ShellLayout() {
  const navigate = useNavigate();
  const location = useLocation();

  const plugins = useMemo(() => getPlugins(), []);
  const visiblePlugins = useMemo(() => getVisiblePlugins(), []);
  const { status: daemonStatus, daemonUrl } = useConnection();
  const policyWorkbenchEnabled = useMemo(() => isPolicyWorkbenchEnabled(), []);
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
    return (fromRoute ?? fromStore ?? visiblePlugins[0]?.id ?? plugins[0]?.id ?? "nexus") as AppId;
  }, [plugins, routeAppId, storedActiveAppId, visiblePlugins]);

  const { createSession, setActiveApp } = useSessionActions();

  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [hasPolicyWorkbenchDirtyDraft, setHasPolicyWorkbenchDirtyDraft] = useState(false);
  const [showHuntronomerLaunch, setShowHuntronomerLaunch] = useState(() =>
    shouldShowHuntronomerLaunch(),
  );
  const unsavedPolicyWarning = "You have unsaved policy changes. Leave Nexus anyway?";
  useEffect(() => {
    const open = () => setIsCommandPaletteOpen(true);
    window.addEventListener(SHELL_OPEN_COMMAND_PALETTE_EVENT, open);
    return () => window.removeEventListener(SHELL_OPEN_COMMAND_PALETTE_EVENT, open);
  }, []);

  useEffect(() => {
    const onDirtyEvent = (event: Event) => {
      const custom = event as CustomEvent<PolicyWorkbenchDirtyEventDetail>;
      setHasPolicyWorkbenchDirtyDraft(Boolean(custom.detail?.dirty));
    };

    window.addEventListener(POLICY_WORKBENCH_DIRTY_EVENT, onDirtyEvent as (event: Event) => void);
    return () =>
      window.removeEventListener(
        POLICY_WORKBENCH_DIRTY_EVENT,
        onDirtyEvent as (event: Event) => void,
      );
  }, []);

  const shouldBlockForDirtyPolicyExit = useCallback<BlockerFunction>(
    ({ currentLocation, nextLocation }) => {
      return shouldBlockDirtyPolicyDraftExit({
        hasDirtyDraft: hasPolicyWorkbenchDirtyDraft,
        currentPathname: currentLocation.pathname,
        nextPathname: nextLocation.pathname,
      });
    },
    [hasPolicyWorkbenchDirtyDraft],
  );
  const blocker = useBlocker(shouldBlockForDirtyPolicyExit);

  useEffect(() => {
    if (blocker.state !== "blocked") return;
    const proceed = globalThis.confirm?.(unsavedPolicyWarning);
    if (proceed) {
      blocker.proceed();
      return;
    }
    blocker.reset();
  }, [blocker, unsavedPolicyWarning]);

  const showAmbientBackground = useMemo(() => {
    const appId = location.pathname.split("/").filter(Boolean)[0] ?? "";
    return !new Set([
      "nexus",
      "swarm",
      "threat-radar",
      "attack-graph",
      "network-map",
      "security-overview",
    ]).has(appId);
  }, [location.pathname]);
  const cyberNexusCommands = useMemo(() => {
    if (activeAppId !== "nexus") return [];

    return [
      {
        id: "nexus:reset-camera",
        group: "Camera",
        title: "Reset Hunt Deck Camera",
        description: "Reset camera to default overview",
        action: () => dispatchCyberNexusCommand({ type: "reset-camera" }),
      },
      {
        id: "nexus:open-search",
        group: "Navigation",
        title: "Open Hunt Search",
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
        action: () => dispatchCyberNexusCommand({ type: "set-layout", layoutMode: "typed-lanes" }),
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
        title: "Toggle Hunt Field",
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

  useEffect(() => {
    setActiveApp(activeAppId);
  }, [activeAppId, setActiveApp]);

  const handleSelectApp = useCallback(
    (appId: AppId) => {
      navigate(`/${appId}`);
    },
    [navigate],
  );

  const handleNewSession = useCallback(() => {
    createSession(activeAppId);
    navigate(`/${activeAppId}`);
  }, [activeAppId, createSession, navigate]);

  const handleNextApp = useCallback(() => {
    if (visiblePlugins.length === 0) return;
    const currentIndex = visiblePlugins.findIndex((p) => p.id === activeAppId);
    const startIndex = currentIndex >= 0 ? currentIndex : 0;
    const nextIndex = (startIndex + 1) % visiblePlugins.length;
    handleSelectApp(visiblePlugins[nextIndex].id);
  }, [visiblePlugins, activeAppId, handleSelectApp]);

  const handlePrevApp = useCallback(() => {
    if (visiblePlugins.length === 0) return;
    const currentIndex = visiblePlugins.findIndex((p) => p.id === activeAppId);
    const startIndex = currentIndex >= 0 ? currentIndex : 0;
    const prevIndex = (startIndex - 1 + visiblePlugins.length) % visiblePlugins.length;
    handleSelectApp(visiblePlugins[prevIndex].id);
  }, [visiblePlugins, activeAppId, handleSelectApp]);

  const handleDismissHuntronomerLaunch = useCallback(() => {
    persistHuntronomerLaunchDismissal();
    setShowHuntronomerLaunch(false);
  }, []);

  // Keyboard shortcuts
  useShellShortcuts({
    onNewSession: handleNewSession,
    onOpenPalette: () => setIsCommandPaletteOpen(true),
    onFocusSearch:
      activeAppId === "nexus"
        ? () => dispatchCyberNexusCommand({ type: "open-search" })
        : undefined,
    onSelectApp: handleSelectApp,
    onNextApp: handleNextApp,
    onPrevApp: handlePrevApp,
    onOpenSettings: () => navigate("/operations?tab=connection"),
    onCloseModal: () => setIsCommandPaletteOpen(false),
  });

  const renderShelfContent = useCallback(
    (mode: "events" | "output" | "artifacts") => {
      if (mode !== "events") return undefined;
      return (
        <ChronicleWorkbenchShelf
          daemonUrl={daemonUrl}
          connected={daemonStatus === "connected"}
          policyWorkbenchEnabled={policyWorkbenchEnabled}
        />
      );
    },
    [daemonStatus, daemonUrl, policyWorkbenchEnabled],
  );

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
        <DockSystem demoMode={false} renderShelfContent={renderShelfContent} />

        {/* Command palette modal */}
        <CommandPalette
          isOpen={isCommandPaletteOpen}
          onClose={() => setIsCommandPaletteOpen(false)}
          onSelectApp={handleSelectApp}
          extraCommands={cyberNexusCommands}
        />

        <HuntronomerLaunchOverlay
          visible={showHuntronomerLaunch}
          onDismiss={handleDismissHuntronomerLaunch}
        />
      </div>
    </DockProvider>
  );
}
