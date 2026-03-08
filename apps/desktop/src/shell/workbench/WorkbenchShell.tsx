/**
 * WorkbenchShell - Root layout component for the Huntronomer workbench.
 *
 * CSS grid layout (Phase 3):
 *   48px Spine | auto Sidebar | 1fr Content        | auto Inspector
 *              |              | auto BottomPanel    |
 *   ──────────────────── 24px StatusBar ────────────────────────────
 *
 * Preserves all ShellLayout functionality: command palette, policy draft guard,
 * launch overlay, keyboard shortcuts, and session management.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { BlockerFunction } from "react-router-dom";
import { useBlocker, useLocation, useNavigate } from "react-router-dom";
import { useConnection } from "@/context/ConnectionContext";
import { dispatchCyberNexusCommand } from "@/features/cyber-nexus/events";
import {
  createWorkspacePaletteCommands,
  WORKSPACE_OPEN_FOLDER_EVENT,
  WORKSPACE_SAVE_ACTIVE_FILE_EVENT,
} from "@/features/workspace/shell";
import {
  POLICY_WORKBENCH_DIRTY_EVENT,
  type PolicyWorkbenchDirtyEventDetail,
} from "@/features/forensics/policy-workbench/events";

import { CommandPalette } from "@/shell/components/CommandPalette";
import { HuntronomerLaunchOverlay } from "@/shell/components/HuntronomerLaunchOverlay";
import { SHELL_OPEN_COMMAND_PALETTE_EVENT } from "@/shell/events";
import { useShellShortcuts } from "@/shell/keyboard";
import { getPlugins, getVisiblePlugins } from "@/shell/plugins";
import type { AppId } from "@/shell/plugins/types";
import { shouldBlockDirtyPolicyDraftExit } from "@/shell/policyDraftGuard";
import { useActiveApp, useSessionActions } from "@/shell/sessions";
import { ActivitySpine } from "./ActivitySpine";
import { BottomPanel } from "./BottomPanel";
import { ContextInspector } from "./ContextInspector";
import { HuntDock } from "./HuntDock";
import { LensSidebar } from "./LensSidebar";
import { SplitPaneContainer } from "./SplitPaneContainer";
import { StatusBar } from "./StatusBar";
import { WorkbenchStateProvider, useWorkbench, useWorkbenchDispatch } from "./WorkbenchStateProvider";
import { DragDropProvider, useDragState, useDropTarget } from "./DragDropContext";
import {
  AnticipationProvider,
  StagingShelf,
  StagingShelfProvider,
  useStagingShelf,
  AttachModeOverlay,
  DropIntentLabel,
  SidebarWakeAnchorProvider,
  useAnticipationContext,
} from "./anticipation";
import type { LensId, ShellMode, TabGroupState, TabState, TabKind } from "./workbenchState";

/* ── Full-viewport Welcome Screen (Cursor-style) ────────────────── */

const WELCOME_QUICK_ACTIONS = [
  {
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6a1.5 1.5 0 011.5-1.5h3L9 6h6.5A1.5 1.5 0 0117 7.5v7a1.5 1.5 0 01-1.5 1.5h-11A1.5 1.5 0 013 14.5V6z" /></svg>
    ),
    label: "Open folder",
    action: "open-folder" as const,
  },
  {
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="10" cy="10" r="5" /><circle cx="10" cy="10" r="1.5" fill="currentColor" stroke="none" /><path d="M10 3v2M10 15v2M3 10h2M15 10h2" /></svg>
    ),
    label: "Start a hunt",
    action: "start-hunt" as const,
  },
  {
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="14" height="14" rx="2" /><path d="M3 8h14" /><path d="M8 8v9" /></svg>
    ),
    label: "Command palette",
    action: "palette" as const,
  },
] as const;

function WelcomeScreen({ onAction }: { onAction: (action: string) => void }) {
  return (
    <div
      className="relative flex flex-col overflow-hidden"
      style={{ width: "100vw", height: "100vh", background: "#05060a" }}
    >
      {/* Full-bleed wallpaper */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: "url(/huntronomer-wallpaper.png)",
          backgroundSize: "cover",
          backgroundPosition: "center 40%",
          opacity: 0.35,
        }}
      />
      {/* Gradient overlay — darken edges, focus center */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 60% at 50% 45%, transparent 0%, rgba(5,6,10,0.7) 70%, rgba(5,6,10,0.92) 100%)",
        }}
      />

      {/* Centered content */}
      <div className="relative z-10 flex flex-1 flex-col items-center justify-center">
        <div className="flex flex-col items-center gap-8" style={{ marginTop: "-4vh" }}>
          {/* Wordmark */}
          <div className="flex flex-col items-center gap-1">
            <h1
              className="text-[22px] font-light tracking-[0.18em] uppercase"
              style={{ fontFamily: "var(--font-mono)", color: "rgba(213, 173, 87, 0.85)" }}
            >
              Huntronomer
            </h1>
            <p
              className="text-[12px] tracking-[0.08em]"
              style={{ color: "rgba(182, 183, 193, 0.5)" }}
            >
              Runtime security workbench
            </p>
          </div>

          {/* Quick actions */}
          <div className="flex gap-3">
            {WELCOME_QUICK_ACTIONS.map((qa) => (
              <button
                key={qa.action}
                type="button"
                className="welcome-action-card"
                onClick={() => onAction(qa.action)}
              >
                <span className="welcome-action-card__icon">{qa.icon}</span>
                <span className="welcome-action-card__label">{qa.label}</span>
              </button>
            ))}
          </div>

          {/* Recent section */}
          <div className="flex flex-col items-start gap-2" style={{ width: 380 }}>
            <span
              className="text-[11px] uppercase tracking-[0.1em]"
              style={{ fontFamily: "var(--font-mono)", color: "rgba(182, 183, 193, 0.4)" }}
            >
              Recent
            </span>
            <div className="flex w-full flex-col">
              <WelcomeRecentRow label="Default workspace" meta="~/workspace" />
              <WelcomeRecentRow label="huntronomer-config" meta="~/.config/huntronomer" />
            </div>
          </div>

          {/* Keyboard hint */}
          <p className="text-[11px]" style={{ color: "rgba(182, 183, 193, 0.3)" }}>
            Press{" "}
            <kbd className="rounded border border-[rgba(182,183,193,0.15)] px-1 py-0.5 font-mono text-[10px]">
              ⌘K
            </kbd>{" "}
            to open the command palette
          </p>
        </div>
      </div>
    </div>
  );
}

function WelcomeRecentRow({ label, meta }: { label: string; meta: string }) {
  return (
    <button
      type="button"
      className="flex h-[32px] w-full items-center justify-between rounded px-2 transition-colors hover:bg-[rgba(213,173,87,0.04)]"
    >
      <span className="text-[13px]" style={{ color: "rgba(232, 230, 222, 0.65)" }}>{label}</span>
      <span className="text-[11px]" style={{ color: "rgba(182, 183, 193, 0.3)" }}>{meta}</span>
    </button>
  );
}

/* ── Existing helpers ────────────────────────────────────────────── */

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

const LENS_BY_INDEX: LensId[] = ["scopes", "history", "files", "sandboxes", "entities", "swarms", "notes"];
const SHELL_BY_INDEX: ShellMode[] = ["wire", "hunt", "lab", "case"];

function findTabByKind(
  tabGroups: TabGroupState[],
  kind: TabKind,
): { groupId: string; tab: TabState } | null {
  for (const group of tabGroups) {
    const tab = group.tabs.find((t) => t.kind === kind);
    if (tab) return { groupId: group.id, tab };
  }
  return null;
}

function WorkbenchShellInner() {
  const navigate = useNavigate();
  const location = useLocation();
  const { state: wbState } = useWorkbench();
  const wbDispatch = useWorkbenchDispatch();
  const routeBridgeProcessed = useRef<string | null>(null);

  const plugins = useMemo(() => getPlugins(), []);
  const visiblePlugins = useMemo(() => getVisiblePlugins(), []);
  const { status: daemonStatus } = useConnection();
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

  // -- Command palette event listener --
  useEffect(() => {
    const open = () => setIsCommandPaletteOpen(true);
    window.addEventListener(SHELL_OPEN_COMMAND_PALETTE_EVENT, open);
    return () => window.removeEventListener(SHELL_OPEN_COMMAND_PALETTE_EVENT, open);
  }, []);

  // -- Policy workbench dirty state listener --
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

  // -- Policy draft navigation guard --
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

  // -- Cyber Nexus commands --
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

  // -- Workspace palette commands --
  const handleWorkspacePaletteAction = useCallback(
    (result: { kind: string; [key: string]: unknown }) => {
      if (result.kind === "navigate" && typeof result.to === "string") {
        navigate(result.to);
        return;
      }

      if (result.kind === "invoke" && typeof result.action === "string") {
        window.dispatchEvent(new Event(result.action));
        if (result.action === WORKSPACE_OPEN_FOLDER_EVENT) {
          navigate("/workspace");
        }
        if (result.action === WORKSPACE_SAVE_ACTIVE_FILE_EVENT) {
          console.info("Workspace save command is reserved for WS4 editor integration.");
        }
      }
    },
    [navigate],
  );

  const workspaceCommands = useMemo(() => {
    if (activeAppId !== "workspace") return [];

    return createWorkspacePaletteCommands(
      {
        activeScope: "workspace",
        workspaceRootId: "workspace-root",
        activeSurfaceRoute: location.pathname,
        selectedObjectIds: [],
        focusedPane: "main",
        connectivity: {
          daemon: daemonStatus === "connected" ? "connected" : "degraded",
          openclaw: daemonStatus === "connected" ? "connected" : "offline",
        },
      },
      (result) => handleWorkspacePaletteAction(result),
    );
  }, [activeAppId, daemonStatus, handleWorkspacePaletteAction, location.pathname]);

  // -- Sync active app to session store --
  useEffect(() => {
    setActiveApp(activeAppId);
  }, [activeAppId, setActiveApp]);

  // -- Route-to-tab bridge --
  // Intercept /<appId> routes, convert to OPEN_TAB dispatches, then clear URL
  useEffect(() => {
    const seg = location.pathname.split("/").filter(Boolean)[0];
    if (!seg) return;
    // Prevent re-processing the same route
    if (routeBridgeProcessed.current === location.pathname + location.search) return;
    routeBridgeProcessed.current = location.pathname + location.search;

    const plugin = plugins.find((p) => p.id === seg);
    if (!plugin?.tabKind) return;

    const existing = findTabByKind(wbState.tabGroups, plugin.tabKind);
    if (existing) {
      wbDispatch({
        type: "SET_ACTIVE_TAB",
        payload: { groupId: existing.groupId, tabId: existing.tab.id },
      });
    } else {
      wbDispatch({
        type: "OPEN_TAB",
        payload: {
          groupId: "main",
          tab: {
            kind: plugin.tabKind,
            title: plugin.name,
            isPreview: false,
            isPinned: false,
            isDirty: false,
          },
        },
      });
    }

    // Clear the route — tab state drives content now
    navigate("/", { replace: true });
  }, [location.pathname, location.search, plugins, wbState.tabGroups, wbDispatch, navigate]);

  // -- Navigation callbacks --
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

  // -- Welcome screen: show when all tab groups are empty --
  const hasAnyTabs = wbState.tabGroups.some((g) => g.tabs.length > 0);

  const handleWelcomeAction = useCallback(
    (action: string) => {
      if (action === "palette") {
        setIsCommandPaletteOpen(true);
      } else if (action === "open-folder") {
        window.dispatchEvent(new Event(WORKSPACE_OPEN_FOLDER_EVENT));
        navigate("/workspace");
      } else if (action === "start-hunt") {
        wbDispatch({
          type: "OPEN_TAB",
          payload: {
            groupId: "main",
            tab: { kind: "hunt", title: "Hunt Deck", isPreview: false, isPinned: false, isDirty: false },
          },
        });
      }
    },
    [navigate, wbDispatch],
  );

  // -- Keyboard shortcuts --
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
    isWorkbench: true,
    onSelectLens: (index: number) => {
      const lens = LENS_BY_INDEX[index - 1];
      if (lens) wbDispatch({ type: "SET_LENS", payload: lens });
    },
    onSelectShell: (index: number) => {
      const shell = SHELL_BY_INDEX[index - 1];
      if (shell) wbDispatch({ type: "SET_SHELL", payload: shell });
    },
    onToggleHuntDock: () => wbDispatch({ type: "HUNT_DOCK_TOGGLE_COLLAPSE" }),
    onToggleSidebar: () => wbDispatch({ type: "TOGGLE_SIDEBAR" }),
    onToggleBottomPanel: () => wbDispatch({ type: "TOGGLE_BOTTOM_PANEL" }),
    onToggleInspector: () => wbDispatch({ type: "TOGGLE_INSPECTOR" }),
    onCloseTab: () => {
      // Close the active tab in the first group that has one
      for (const group of wbState.tabGroups) {
        if (group.activeTabId) {
          const tab = group.tabs.find((t) => t.id === group.activeTabId);
          if (tab?.isDirty) {
            const proceed = globalThis.confirm?.(`"${tab.title}" has unsaved changes. Close anyway?`);
            if (!proceed) return;
          }
          wbDispatch({ type: "CLOSE_TAB", payload: { groupId: group.id, tabId: group.activeTabId } });
          return;
        }
      }
    },
    onNextTab: () => {
      for (const group of wbState.tabGroups) {
        if (group.activeTabId && group.tabs.length > 1) {
          const idx = group.tabs.findIndex((t) => t.id === group.activeTabId);
          const nextIdx = (idx + 1) % group.tabs.length;
          wbDispatch({ type: "SET_ACTIVE_TAB", payload: { groupId: group.id, tabId: group.tabs[nextIdx].id } });
          return;
        }
      }
    },
    onPrevTab: () => {
      for (const group of wbState.tabGroups) {
        if (group.activeTabId && group.tabs.length > 1) {
          const idx = group.tabs.findIndex((t) => t.id === group.activeTabId);
          const prevIdx = (idx - 1 + group.tabs.length) % group.tabs.length;
          wbDispatch({ type: "SET_ACTIVE_TAB", payload: { groupId: group.id, tabId: group.tabs[prevIdx].id } });
          return;
        }
      }
    },
  });

  // Full-viewport welcome when no tabs are open
  if (!hasAnyTabs) {
    return (
      <>
        <WelcomeScreen onAction={handleWelcomeAction} />

        {/* Command palette is still accessible via ⌘K on the welcome screen */}
        <CommandPalette
          isOpen={isCommandPaletteOpen}
          onClose={() => setIsCommandPaletteOpen(false)}
          onSelectApp={handleSelectApp}
          extraCommands={activeAppId === "workspace" ? workspaceCommands : cyberNexusCommands}
        />
      </>
    );
  }

  return (
    <StagingShelfProvider>
      <DragDropProvider>
        <AnticipationProvider>
          <SidebarWakeAnchorProvider>
            <div
              className="workbench-shell-grid"
              style={{
                display: "grid",
                gridTemplateAreas: `
                  "spine dock sidebar content inspector"
                  "spine dock sidebar bottom  inspector"
                  "status status status status status"
                `,
                gridTemplateColumns: "56px auto auto 1fr auto",
                gridTemplateRows: "1fr auto 24px",
                height: "100vh",
                width: "100vw",
                overflow: "hidden",
                background: "var(--color-bg-primary, #05060a)",
              }}
            >
              {/* ActivitySpine - spans rows 1-2 */}
              <div style={{ gridArea: "spine", overflow: "hidden" }}>
                <ActivitySpine />
              </div>

              {/* HuntDock - spans rows 1-2 */}
              <div style={{ gridArea: "dock", overflow: "hidden" }}>
                <HuntDock />
              </div>

              {/* LensSidebar - spans rows 1-2 */}
              <div style={{ gridArea: "sidebar", overflow: "visible", position: "relative", zIndex: 20 }}>
                <LensSidebar
                  onOpenPath={(relativePath, options) => {
                    wbDispatch({
                      type: "OPEN_TAB",
                      payload: {
                        groupId: "main",
                        openMode: options?.openMode,
                        tab: {
                          kind: "file",
                          title: relativePath.split("/").pop() ?? relativePath,
                          subtitle: relativePath,
                          sourceUri: relativePath,
                          isPreview: true,
                          isPinned: false,
                          isDirty: false,
                          metadata: options?.reason ? { anticipationReason: options.reason } : undefined,
                        },
                      },
                    });
                    wbDispatch({
                      type: "SET_SELECTION",
                      payload: {
                        entityType: "file",
                        entityId: relativePath,
                        metadata: { path: relativePath, name: relativePath.split("/").pop() ?? relativePath },
                      },
                    });
                  }}
                />
              </div>

              {/* Content area (tabbed split panes) */}
              <main
                className="relative z-10 flex flex-1 flex-col overflow-hidden"
                style={{ gridArea: "content" }}
              >
                <SplitPaneContainer />
              </main>

              {/* Bottom panel (tape, terminal, receipts, tasks, replay, diff) */}
              <div style={{ gridArea: "bottom" }}>
                <BottomPanel />
              </div>

              {/* Context inspector (right side) - spans rows 1-2 */}
              <div style={{ gridArea: "inspector", overflow: "hidden" }}>
                <ContextInspector />
              </div>

              {/* Staging shelf + Attach overlay (inside DragDropProvider) */}
              <AnticipationOverlays />

              {/* StatusBar - spans all columns */}
              <StatusBar />
            </div>
          </SidebarWakeAnchorProvider>

          {/* Command palette modal */}
          <CommandPalette
            isOpen={isCommandPaletteOpen}
            onClose={() => setIsCommandPaletteOpen(false)}
            onSelectApp={handleSelectApp}
            extraCommands={activeAppId === "workspace" ? workspaceCommands : cyberNexusCommands}
          />

          <HuntronomerLaunchOverlay
            visible={showHuntronomerLaunch}
            onDismiss={handleDismissHuntronomerLaunch}
          />
        </AnticipationProvider>
      </DragDropProvider>
    </StagingShelfProvider>
  );
}

/**
 * AnticipationOverlays — rendered inside DragDropProvider so it can
 * safely call useDragState().
 */
function AnticipationOverlays() {
  const dragState = useDragState();
  const anticipation = useAnticipationContext();
  const stagingShelf = useStagingShelf();
  const stagingDropTarget = useDropTarget("staging-shelf", "staging");

  return (
    <>
      {(stagingShelf.items.length > 0 || dragState.active) && (
        <div style={{ gridColumn: "1 / -1" }}>
          <StagingShelf
            items={stagingShelf.items}
            suggestions={stagingShelf.suggestions}
            onRemove={stagingShelf.unstageItem}
            onClear={stagingShelf.clearStaging}
            onExecuteSuggestion={() => {/* TODO: execute staging suggestion */}}
            dropActive={dragState.active}
            isDropOver={stagingDropTarget.isOver}
            dragLabel={anticipation.dropPrediction?.defaultLabel ?? null}
            dropTargetProps={stagingDropTarget.dropTargetProps}
          />
        </div>
      )}

      <AttachModeOverlay
        active={dragState.active}
        draggedKind={dragState.payload?.artifact.kind ?? null}
        defaultAction={anticipation.dropPrediction?.defaultLabel ?? null}
      />

      {/* Drop intent label — follows the drag cursor */}
      {dragState.active && anticipation.dropPrediction && (
        <div
          style={{
            position: "fixed",
            left: dragState.position.x + 16,
            top: dragState.position.y + 20,
            zIndex: 201,
            pointerEvents: "none",
          }}
        >
          <DropIntentLabel
            prediction={{
              defaultAction: anticipation.dropPrediction.defaultAction,
              defaultLabel: anticipation.dropPrediction.defaultLabel,
              explanation: {
                shortLabel: anticipation.dropPrediction.defaultLabel,
                reason: anticipation.dropPrediction.reason,
                alternates: anticipation.dropPrediction.alternateActions.map((action) => action.label),
              },
              alternateActions: anticipation.dropPrediction.alternateActions,
            }}
            visible={true}
          />
        </div>
      )}
    </>
  );
}

export function WorkbenchShell() {
  return (
    <WorkbenchStateProvider>
      <WorkbenchShellInner />
    </WorkbenchStateProvider>
  );
}
