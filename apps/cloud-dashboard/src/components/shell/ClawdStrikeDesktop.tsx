import { Suspense, memo, useEffect, useRef, useMemo } from "react";
import {
  useDesktopOS,
  useWindowIds,
  useWindow,
  Window,
  Taskbar,
  type WindowId,
} from "@backbay/glia-desktop";
import { DesktopWallpaper } from "./DesktopWallpaper";
import { SSETrayItem } from "./SSETrayItem";
import { SSENotifier } from "./SSENotifier";
import { desktopIcons } from "../../state/processRegistry";

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
        color: "rgba(148,163,184,0.6)",
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
            background: "#02040a",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 11,
            letterSpacing: "0.15em",
            textTransform: "uppercase",
            color: "rgba(148,163,184,0.3)",
          }}
        >
          SUSPENDED
        </div>
      ) : (
        <Suspense fallback={<LoadingFallback />}>
          <AppComponent windowId={windowId} />
        </Suspense>
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
        flexWrap: "wrap",
        alignContent: "flex-start",
        gap: 16,
        padding: 24,
        userSelect: "none",
      }}
    >
      {desktopIcons.map((icon) => {
        const def = processes.getDefinition(icon.processId);
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
              width: 72,
              padding: "8px 4px",
              border: "none",
              borderRadius: 8,
              background: "transparent",
              cursor: "pointer",
              color: "var(--glia-color-textPrimary, #e5e7eb)",
            }}
          >
            <span style={{ fontSize: 28, lineHeight: 1 }}>
              {typeof def?.icon === "string" ? def.icon : "📁"}
            </span>
            <span
              className="font-mono"
              style={{
                fontSize: 10,
                letterSpacing: "0.06em",
                textTransform: "uppercase",
                textAlign: "center",
                lineHeight: 1.3,
                color: "rgba(229,231,235,0.85)",
                textShadow: "0 1px 4px rgba(0,0,0,0.8)",
              }}
            >
              {icon.label}
            </span>
          </button>
        );
      })}
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

export function ClawdStrikeDesktop() {
  return (
    <div style={{ position: "fixed", inset: 0, display: "flex", flexDirection: "column" }}>
      <DesktopWallpaper />

      {/* Desktop area */}
      <div
        style={{
          flex: 1,
          position: "relative",
          paddingBottom: "var(--glia-spacing-taskbar-height, 48px)",
        }}
      >
        <DesktopSurface />
        <WindowContainer />
      </div>

      {/* System services */}
      <AutoLaunch />
      <SSETrayItem />
      <SSENotifier />

      {/* Taskbar */}
      <Taskbar showClock />
    </div>
  );
}
