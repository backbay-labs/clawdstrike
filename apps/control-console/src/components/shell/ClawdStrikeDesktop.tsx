import {
  Taskbar,
  useDesktopOS,
  useWindow,
  useWindowIds,
  Window,
  type WindowId,
} from "@backbay/glia-desktop";
import { memo, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSharedSSE } from "../../context/SSEContext";
import { useAlertRules } from "../../hooks/useAlertRules";
import { type ConsoleStatus, useConsoleStatus } from "../../hooks/useConsoleStatus";
import { useContextMenu } from "../../hooks/useContextMenu";
import { useLockScreen } from "../../hooks/useLockScreen";
import { useNotifications } from "../../hooks/useNotifications";
import { useSoundEffects } from "../../hooks/useSoundEffects";
import { PROCESS_ICONS, type ProcessIcon } from "../../state/processRegistry";
import {
  resolveEffectiveVariant,
  SIDEBAR_COLLAPSED_WIDTH,
  SIDEBAR_EXPANDED_WIDTH,
  type SidebarVariant,
  useShellPreferences,
} from "../../state/useShellPreferences";
import { CanvasEmptyState } from "./CanvasEmptyState";
import { CommandPalette } from "./CommandPalette";
import { ContextMenu } from "./ContextMenu";
import { DesktopWallpaper } from "./DesktopWallpaper";
import { ErrorBoundary } from "./ErrorBoundary";
import { HeaderBar } from "./HeaderBar";
import { KeyboardShortcuts } from "./KeyboardShortcuts";
import { LockScreen } from "./LockScreen";
import { NotificationCenter } from "./NotificationCenter";
import { SSENotifier } from "./SSENotifier";
import { SSETrayItem } from "./SSETrayItem";
import { Sidebar } from "./sidebar/Sidebar";

/** Fixed widths of the standalone sidebar variants (rail icon column; two-pane = section rail + app list). */
const RAIL_WIDTH = 64;
const TWOPANE_WIDTH = 60 + 220;

/**
 * Pixel width of the sidebar column for a given variant + collapsed flag. Drives
 * the shell grid track so `<main>` reflows in lockstep with the sidebar's own
 * width morph (both share the same duration + easing, so they never diverge).
 */
function sidebarColumnWidth(variant: SidebarVariant, collapsed: boolean): number {
  switch (variant) {
    case "rail":
      return RAIL_WIDTH;
    case "twopane":
      return TWOPANE_WIDTH;
    case "expanded":
      return collapsed ? SIDEBAR_COLLAPSED_WIDTH : SIDEBAR_EXPANDED_WIDTH;
  }
}

function LoadingFallback() {
  return (
    <div
      className="font-mono"
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        height: "100%",
        fontSize: 12,
        letterSpacing: "0.12em",
        textTransform: "uppercase",
        color: "rgba(154,167,181,0.6)",
      }}
    >
      INITIALIZING...
    </div>
  );
}

const WindowItem = memo(function WindowItem({ windowId }: { windowId: WindowId }) {
  const win = useWindow(windowId);
  const { processes } = useDesktopOS();

  const processId = useMemo(
    () => processes.instances.find((i) => i.windowId === windowId)?.processId,
    [processes.instances, windowId],
  );

  const definition = useMemo(
    () => (processId ? processes.getDefinition(processId) : undefined),
    [processes, processId],
  );

  if (!win || !definition) return null;

  const AppComponent = definition.component;

  return (
    <Window id={windowId}>
      {win.isMinimized ? (
        <div
          className="font-mono"
          style={{
            width: "100%",
            height: "100%",
            background: "#000000",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 11,
            letterSpacing: "0.15em",
            textTransform: "uppercase",
            color: "rgba(154,167,181,0.3)",
          }}
        >
          SUSPENDED
        </div>
      ) : (
        <ErrorBoundary
          fallback={(error, reset) => (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                height: "100%",
                padding: 24,
                background: "rgba(15,20,30,0.95)",
                color: "#e7edf6",
                fontFamily: '"Inter", sans-serif',
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontFamily: '"JetBrains Mono", monospace',
                  letterSpacing: "0.12em",
                  textTransform: "uppercase",
                  color: "#c23b3b",
                  marginBottom: 8,
                }}
              >
                WINDOW ERROR
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: "rgba(154,167,181,0.7)",
                  marginBottom: 14,
                  textAlign: "center",
                  wordBreak: "break-word",
                  maxWidth: 300,
                }}
              >
                {error.message || "An unexpected error occurred"}
              </div>
              <button
                type="button"
                onClick={reset}
                style={{
                  padding: "6px 14px",
                  borderRadius: 8,
                  border: "1px solid rgba(214,177,90,0.35)",
                  background: "rgba(214,177,90,0.1)",
                  color: "#d6b15a",
                  fontSize: 11,
                  fontFamily: '"JetBrains Mono", monospace',
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  cursor: "pointer",
                }}
              >
                Reload Window
              </button>
            </div>
          )}
        >
          <Suspense fallback={<LoadingFallback />}>
            <AppComponent windowId={windowId} />
          </Suspense>
        </ErrorBoundary>
      )}
    </Window>
  );
});

function WindowContainer() {
  const windowIds = useWindowIds();
  return (
    <div style={{ position: "absolute", inset: 0, pointerEvents: "none" }}>
      {windowIds.map((id) => (
        <WindowItem key={id} windowId={id} />
      ))}
    </div>
  );
}

const PATH_TO_PROCESS: Record<string, string> = {
  "/events": "event-stream",
  "/audit": "audit",
  "/policies": "policy",
  "/settings": "settings",
  "/settings/siem": "settings",
  "/settings/webhooks": "settings",
  "/agents": "agent-explorer",
  "/receipts": "receipt-verifier",
  "/policy-editor": "policy-editor",
  "/playground": "guard-playground",
  "/posture": "posture-map",
  "/compliance": "compliance-report",
  "/replay": "replay-mode",
  "/chat": "agent-chat",
  "/broker": "broker-mission-control",
  "/broker/mission-control": "broker-mission-control",
};

function AutoLaunch() {
  const { processes } = useDesktopOS();
  const launched = useRef(false);

  useEffect(() => {
    if (launched.current) return;
    launched.current = true;

    const base = (import.meta.env.BASE_URL || "/").replace(/\/+$/, "");
    const raw = window.location.pathname.replace(/\/+$/, "") || "/";
    const path = base && raw.startsWith(base) ? raw.slice(base.length) || "/" : raw;
    const processId = PATH_TO_PROCESS[path];

    if (processId) {
      processes.launch(processId);
    } else {
      processes.launch("monitor");
    }
  }, [processes]);

  return null;
}

/**
 * Tiny taskbar crest: a live status dot + label — the sidebar owns nav now.
 * Teal "Console online" when the SSE stream is live, crimson "Console offline"
 * when it is down. Live state is load-bearing in an EDR console, so this must
 * never be a hardcoded green light.
 */
function ConsoleCrest({ live }: { live: boolean }) {
  const tone = live ? "var(--teal)" : "var(--crimson)";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0, paddingLeft: 8 }}>
      <span
        aria-hidden="true"
        style={{
          width: 6,
          height: 6,
          borderRadius: "50%",
          background: tone,
          boxShadow: `0 0 6px ${tone}`,
        }}
      />
      <span
        className="font-mono"
        role="status"
        style={{
          fontSize: 9.5,
          letterSpacing: "0.18em",
          textTransform: "uppercase",
          color: "rgba(154,167,181,0.5)",
          whiteSpace: "nowrap",
        }}
      >
        {live ? "Console online" : "Console offline"}
      </span>
    </div>
  );
}

function TaskbarDivider() {
  return (
    <span
      aria-hidden="true"
      style={{
        width: 1,
        height: 18,
        background: "rgba(27,34,48,0.7)",
        margin: "0 2px",
        flexShrink: 0,
      }}
    />
  );
}

function RunningAppPill({
  label,
  Sigil,
  focused,
  onActivate,
}: {
  label: string;
  Sigil: ProcessIcon | undefined;
  focused: boolean;
  onActivate: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onActivate}
      className="cs-nav-focus"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 7,
        padding: "5px 12px 5px 9px",
        borderRadius: 8,
        cursor: "pointer",
        background: focused
          ? "linear-gradient(180deg, rgba(214,177,90,0.14), rgba(214,177,90,0.04))"
          : "rgba(18,21,27,0.6)",
        border: focused ? "1px solid var(--gold-edge)" : "1px solid rgba(27,34,48,0.7)",
        color: focused ? "var(--gold)" : "var(--muted)",
        boxShadow: focused ? "inset 0 1px 0 rgba(214,177,90,0.15)" : "none",
        transition: "opacity 0.12s ease",
        whiteSpace: "nowrap",
        maxWidth: 180,
      }}
      onMouseEnter={(e) => {
        if (!focused) (e.currentTarget as HTMLButtonElement).style.opacity = "0.82";
      }}
      onMouseLeave={(e) => {
        (e.currentTarget as HTMLButtonElement).style.opacity = "1";
      }}
    >
      {Sigil && (
        <span style={{ display: "flex", flexShrink: 0 }}>
          <Sigil size={14} />
        </span>
      )}
      <span
        className="font-mono"
        style={{
          fontSize: 10.5,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {label}
      </span>
    </button>
  );
}

function ComposedTaskbar({
  notifications,
  onMarkAllRead,
  onClearNotifications,
  unreadCount,
  status,
}: {
  notifications: import("../../hooks/useNotifications").AppNotification[];
  onMarkAllRead: () => void;
  onClearNotifications: () => void;
  unreadCount: number;
  status: ConsoleStatus;
}) {
  const { windows, processes } = useDesktopOS();

  const handleClick = useCallback(
    (windowId: string) => {
      if (windows.focusedId === windowId) {
        windows.minimize(windowId as WindowId);
      } else {
        windows.focus(windowId as WindowId);
      }
    },
    [windows],
  );

  return (
    <Taskbar showClock>
      <ConsoleCrest live={status.sseLive} />
      <TaskbarDivider />
      <Taskbar.RunningApps>
        {processes.instances.map((instance) => {
          const def = processes.getDefinition(instance.processId);
          return (
            <RunningAppPill
              key={instance.windowId}
              label={def?.name ?? instance.processId}
              Sigil={PROCESS_ICONS[instance.processId]}
              focused={instance.windowId === windows.focusedId}
              onActivate={() => handleClick(instance.windowId)}
            />
          );
        })}
      </Taskbar.RunningApps>
      <div style={{ flex: 1 }} />
      <NotificationCenter
        notifications={notifications}
        onMarkAllRead={onMarkAllRead}
        onClear={onClearNotifications}
        unreadCount={unreadCount}
      />
      <Taskbar.SystemTray />
    </Taskbar>
  );
}

export function ClawdStrikeDesktop() {
  const { events, connected } = useSharedSSE();
  const { locked, lock, unlock } = useLockScreen();
  const {
    notifications,
    add: addNotification,
    markAllRead,
    clear: clearNotifications,
    unreadCount,
  } = useNotifications();
  const {
    state: contextMenuState,
    show: showContextMenu,
    hide: hideContextMenu,
  } = useContextMenu();
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  const { processes, windows } = useDesktopOS();
  const windowIds = useWindowIds();
  const status = useConsoleStatus(events, connected);
  const activeProcessId = processes.instances.find(
    (i) => i.windowId === windows.focusedId,
  )?.processId;
  const { sidebarVariant, sidebarCollapsed, toggleSidebarCollapsed } = useShellPreferences();
  const effectiveVariant = resolveEffectiveVariant(sidebarVariant, sidebarCollapsed);
  // The collapse morph only applies to the expanded variant; rail/two-pane are fixed layouts.
  const collapsible = sidebarVariant === "expanded";
  const expandedCollapsed = collapsible && sidebarCollapsed;
  const sidebarWidth = sidebarColumnWidth(sidebarVariant, sidebarCollapsed);
  const hasWindows = windowIds.length > 0;

  const openCommandPalette = useCallback(() => setCommandPaletteOpen(true), []);
  const launchMonitor = useCallback(() => processes.launch("monitor"), [processes]);

  // Persistent alert evaluation — runs regardless of which windows are open
  useAlertRules(events);

  // Persistent sound effects — runs regardless of which windows are open
  const [soundsEnabled, setSoundsEnabled] = useState(
    () => localStorage.getItem("cs_sounds_enabled") === "true",
  );
  useSoundEffects(events, soundsEnabled);
  useEffect(() => {
    const handler = () => setSoundsEnabled(localStorage.getItem("cs_sounds_enabled") === "true");
    window.addEventListener("storage", handler);
    window.addEventListener("clawdstrike:sound-changed", handler);
    return () => {
      window.removeEventListener("storage", handler);
      window.removeEventListener("clawdstrike:sound-changed", handler);
    };
  }, []);

  // Push SSE violations into notification center (track by _id to handle capped arrays)
  const lastNotifiedIdRef = useRef(-1);
  useEffect(() => {
    for (const evt of events) {
      if (evt._id <= lastNotifiedIdRef.current) break; // already notified
      if (evt.allowed === false || evt.event_type === "violation") {
        addNotification(
          `Violation: ${evt.guard || evt.event_type} — ${evt.action_type || "unknown"}`,
          "error",
        );
      } else if (evt.event_type === "policy_updated") {
        addNotification("Policy updated", "warning");
      }
    }
    if (events.length > 0) lastNotifiedIdRef.current = events[0]._id;
  }, [events, addNotification]);

  const handleDesktopContextMenu = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      showContextMenu(e.clientX, e.clientY, [
        { label: "Refresh", action: () => window.location.reload() },
        { label: "Lock Screen", action: lock, separator: false },
      ]);
    },
    [showContextMenu, lock],
  );

  return (
    <div style={{ position: "fixed", inset: 0, display: "flex", flexDirection: "column" }}>
      <DesktopWallpaper />

      {/* Lock screen (outermost overlay) */}
      <LockScreen locked={locked} onUnlock={unlock} />

      {/* Shell row: sidebar (launcher) + canvas (header over the window manager).
          The taskbar is position:fixed, so reserve its height to keep the sidebar
          footer and window region clear of it. */}
      <div
        className="cs-animated"
        style={{
          flex: 1,
          // Grid drives the sidebar column width so <main> reflows smoothly as
          // the sidebar morphs (impeccable-endorsed size animation). The track
          // shares the sidebar's own duration + easing so they stay in lockstep.
          display: "grid",
          gridTemplateColumns: `${sidebarWidth}px 1fr`,
          minHeight: 0,
          position: "relative",
          zIndex: 1,
          paddingBottom: "var(--glia-spacing-taskbar-height, 44px)",
          transition: "grid-template-columns 0.22s cubic-bezier(0.22,1,0.36,1)",
        }}
      >
        {/*
         * No overflow:hidden here — the nav animates its own width in lockstep
         * with the grid track (same curve + duration), so nothing spills into
         * <main>, and right-escaping tooltips (rail nav items, the collapsed
         * Expand toggle) must not be clipped by this wrapper.
         */}
        <div style={{ minWidth: 0, display: "flex" }}>
          <Sidebar
            status={status}
            onCmdK={openCommandPalette}
            variant={effectiveVariant}
            collapsed={expandedCollapsed}
          />
        </div>

        <main
          style={{
            display: "flex",
            flexDirection: "column",
            minWidth: 0,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <HeaderBar
            variant={effectiveVariant}
            activeProcessId={activeProcessId}
            status={status}
            onCmdK={openCommandPalette}
          />

          {/* Window region — frosted header sits above; windows float freely below it */}
          <div
            style={{ flex: 1, position: "relative", minHeight: 0 }}
            onContextMenu={handleDesktopContextMenu}
          >
            <WindowContainer />
            {!hasWindows && (
              <div style={{ position: "absolute", inset: 0, display: "flex" }}>
                <CanvasEmptyState onLaunch={launchMonitor} />
              </div>
            )}
          </div>
        </main>
      </div>

      {/* System services */}
      <AutoLaunch />
      <SSETrayItem />
      <SSENotifier />
      <KeyboardShortcuts
        onToggleCommandPalette={() => setCommandPaletteOpen((v) => !v)}
        onLock={lock}
        onToggleSidebar={() => {
          // Only the expanded variant collapses; rail/two-pane are fixed layouts.
          if (collapsible) toggleSidebarCollapsed();
        }}
      />
      <CommandPalette
        open={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onLock={lock}
      />
      <ContextMenu state={contextMenuState} onClose={hideContextMenu} />

      {/* Taskbar */}
      <ComposedTaskbar
        notifications={notifications}
        onMarkAllRead={markAllRead}
        onClearNotifications={clearNotifications}
        unreadCount={unreadCount}
        status={status}
      />
    </div>
  );
}
