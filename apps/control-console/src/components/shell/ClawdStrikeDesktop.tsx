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
import { useContextMenu } from "../../hooks/useContextMenu";
import { useLockScreen } from "../../hooks/useLockScreen";
import { useNotifications } from "../../hooks/useNotifications";
import { useSoundEffects } from "../../hooks/useSoundEffects";
import { desktopIconGroups, PROCESS_ICONS } from "../../state/processRegistry";
import { CommandPalette } from "./CommandPalette";
import { ContextMenu } from "./ContextMenu";
import { DesktopWallpaper } from "./DesktopWallpaper";
import { DesktopWidgets } from "./DesktopWidgets";
import { ErrorBoundary } from "./ErrorBoundary";
import { KeyboardShortcuts } from "./KeyboardShortcuts";
import { LockScreen } from "./LockScreen";
import { NotificationCenter } from "./NotificationCenter";
import { SSENotifier } from "./SSENotifier";
import { SSETrayItem } from "./SSETrayItem";
import { StartMenu } from "./StartMenu";

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

function DesktopSurface() {
  const { processes } = useDesktopOS();

  return (
    <div
      style={{
        position: "relative",
        zIndex: 1,
        display: "flex",
        flexDirection: "column",
        alignItems: "flex-start",
        gap: 14,
        padding: 24,
        userSelect: "none",
      }}
    >
      {desktopIconGroups.map((group) => (
        <section key={group.id} style={{ width: "100%" }}>
          <div
            className="font-mono"
            style={{
              marginBottom: 8,
              fontSize: 10,
              textTransform: "uppercase",
              letterSpacing: "0.14em",
              color: "rgba(154,167,181,0.5)",
            }}
          >
            {group.label}
          </div>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              alignContent: "flex-start",
              gap: 16,
            }}
          >
            {group.icons.map((icon) => {
              const def = processes.getDefinition(icon.processId);
              const sigil = PROCESS_ICONS[icon.processId];
              return (
                <button
                  key={icon.id}
                  type="button"
                  onDoubleClick={() => processes.launch(icon.processId)}
                  className="hover-desktop-icon"
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    gap: 6,
                    width: 84,
                    padding: "8px 4px",
                    border: "none",
                    borderRadius: 8,
                    background: "transparent",
                    cursor: "pointer",
                    color: "var(--text)",
                  }}
                >
                  <span
                    style={{
                      width: 40,
                      height: 40,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      background: "linear-gradient(180deg, var(--graphite), var(--obsidian))",
                      border: "1px solid var(--gold-edge)",
                      borderRadius: 12,
                    }}
                  >
                    {sigil ?? (typeof def?.icon === "string" ? def.icon : null)}
                  </span>
                  <span
                    className="font-mono"
                    style={{
                      fontSize: 10,
                      letterSpacing: "0.06em",
                      textTransform: "uppercase",
                      textAlign: "center",
                      lineHeight: 1.3,
                      color: "var(--muted)",
                    }}
                  >
                    {icon.label}
                  </span>
                </button>
              );
            })}
          </div>
        </section>
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

function ComposedTaskbar({
  notifications,
  onMarkAllRead,
  onClearNotifications,
  unreadCount,
}: {
  notifications: import("../../hooks/useNotifications").AppNotification[];
  onMarkAllRead: () => void;
  onClearNotifications: () => void;
  unreadCount: number;
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
      <StartMenu />
      <Taskbar.RunningApps>
        {processes.instances.map((instance) => {
          const def = processes.getDefinition(instance.processId);
          const sigil = PROCESS_ICONS[instance.processId];
          const isFocused = instance.windowId === windows.focusedId;

          return (
            <div
              key={instance.windowId}
              onClick={() => handleClick(instance.windowId)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleClick(instance.windowId);
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                padding: "4px 12px",
                borderRadius: "var(--radius-control)",
                cursor: "pointer",
                background: isFocused ? "var(--gold-bloom)" : "rgba(18,21,27,0.6)",
                border: isFocused ? "1px solid var(--gold-edge)" : "1px solid rgba(27,34,48,0.5)",
                transition: "all 0.15s ease",
                whiteSpace: "nowrap",
                maxWidth: 180,
              }}
            >
              {sigil && <span style={{ display: "flex", flexShrink: 0 }}>{sigil}</span>}
              <span
                className="font-mono"
                style={{
                  fontSize: 11,
                  letterSpacing: "0.04em",
                  color: isFocused ? "var(--gold)" : "var(--muted)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {def?.name ?? instance.processId}
              </span>
            </div>
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

      {/* Desktop area */}
      <div
        style={{
          flex: 1,
          position: "relative",
          paddingBottom: "var(--glia-spacing-taskbar-height, 48px)",
        }}
        onContextMenu={handleDesktopContextMenu}
      >
        <DesktopSurface />
        <DesktopWidgets events={events} connected={connected} />
        <WindowContainer />
      </div>

      {/* System services */}
      <AutoLaunch />
      <SSETrayItem />
      <SSENotifier />
      <KeyboardShortcuts
        onToggleCommandPalette={() => setCommandPaletteOpen((v) => !v)}
        onLock={lock}
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
      />
    </div>
  );
}
