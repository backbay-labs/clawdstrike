/**
 * BottomPanel - Collapsible bottom panel with tabbed content.
 *
 * Renders the bottom panel region (tape, terminal, receipts, tasks, replay, diff).
 * State is driven by BottomPanelState via useBottomPanel() / useWorkbenchDispatch().
 */
import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import type { BottomPanelTabId } from "./workbenchState";
import { BOTTOM_PANEL_REGISTRY } from "./bottomPanelRegistry";
import { useBottomPanel, useWorkbenchDispatch } from "./WorkbenchStateProvider";
import { useAnticipationContext, useSidebarDirector } from "./anticipation";

const TAB_IDS: BottomPanelTabId[] = ["tape", "terminal", "receipts", "tasks", "replay", "diff"];

const TAB_STRIP_HEIGHT = 28;
const RESIZE_HANDLE_HEIGHT = 4;

export function BottomPanel() {
  const { activeTab, collapsed, height } = useBottomPanel();
  const dispatch = useWorkbenchDispatch();
  const anticipation = useAnticipationContext();
  const sidebarDirector = useSidebarDirector();
  const promotion = sidebarDirector.adjacentSurfacePromotion;

  const [isDragging, setIsDragging] = useState(false);
  const dragStartY = useRef(0);
  const dragStartHeight = useRef(0);

  const handleTabClick = useCallback(
    (tabId: BottomPanelTabId) => {
      dispatch({ type: "SET_BOTTOM_PANEL_TAB", payload: tabId });
    },
    [dispatch],
  );

  const handleToggle = useCallback(() => {
    dispatch({ type: "TOGGLE_BOTTOM_PANEL" });
  }, [dispatch]);

  // -- Drag-to-resize --
  const handleResizePointerDown = useCallback(
    (e: React.PointerEvent) => {
      e.preventDefault();
      setIsDragging(true);
      dragStartY.current = e.clientY;
      dragStartHeight.current = height;
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
    },
    [height],
  );

  useEffect(() => {
    if (!isDragging) return;

    const handleMove = (e: PointerEvent) => {
      const delta = dragStartY.current - e.clientY;
      dispatch({ type: "SET_BOTTOM_PANEL_HEIGHT", payload: dragStartHeight.current + delta });
    };

    const handleUp = () => {
      setIsDragging(false);
    };

    window.addEventListener("pointermove", handleMove);
    window.addEventListener("pointerup", handleUp);
    return () => {
      window.removeEventListener("pointermove", handleMove);
      window.removeEventListener("pointerup", handleUp);
    };
  }, [isDragging, dispatch]);

  useEffect(() => {
    if (
      !promotion.bottomPanelTab ||
      !promotion.shouldOpenBottomPanel ||
      (!collapsed && activeTab === promotion.bottomPanelTab)
    ) {
      return;
    }

    dispatch({ type: "SET_BOTTOM_PANEL_TAB", payload: promotion.bottomPanelTab });
  }, [
    activeTab,
    collapsed,
    dispatch,
    promotion.bottomPanelTab,
    promotion.shouldOpenBottomPanel,
  ]);

  const entry = BOTTOM_PANEL_REGISTRY[activeTab];
  const ContentComponent = entry?.component;
  const showReason =
    Boolean(promotion.bottomPanelTab)
    && Boolean(promotion.reason)
    && (promotion.shouldOpenBottomPanel || activeTab === promotion.bottomPanelTab);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        background: "rgba(4,6,10,0.95)",
        borderTop: "1px solid var(--color-border-subtle, #1a1d2e)",
        overflow: "hidden",
      }}
    >
      {/* Resize handle */}
      <div
        role="separator"
        aria-label="Resize bottom panel"
        aria-orientation="horizontal"
        tabIndex={0}
        onPointerDown={handleResizePointerDown}
        style={{
          height: RESIZE_HANDLE_HEIGHT,
          cursor: collapsed ? "default" : "ns-resize",
          background: isDragging ? "var(--color-origin-gold, #c8a84e)" : "transparent",
          flexShrink: 0,
        }}
      />

      {/* Tab strip */}
      <div
        role="tablist"
        aria-label="Bottom panel tabs"
        style={{
          display: "flex",
          alignItems: "center",
          height: TAB_STRIP_HEIGHT,
          flexShrink: 0,
          paddingLeft: 4,
          paddingRight: 4,
          gap: 0,
          borderBottom: collapsed ? "none" : "1px solid var(--color-border-subtle, #1a1d2e)",
        }}
      >
        {/* Collapse toggle */}
        <button
          onClick={handleToggle}
          aria-label={collapsed ? "Expand bottom panel" : "Collapse bottom panel"}
          style={{
            background: "none",
            border: "none",
            color: "var(--color-text-muted, #6b7280)",
            cursor: "pointer",
            padding: "0 6px",
            fontSize: 10,
            lineHeight: `${TAB_STRIP_HEIGHT}px`,
            fontFamily: "monospace",
            flexShrink: 0,
          }}
        >
          {collapsed ? "\u25B6" : "\u25BC"}
        </button>

        {/* Tabs */}
        {TAB_IDS.map((tabId) => {
          const reg = BOTTOM_PANEL_REGISTRY[tabId];
          const isActive = tabId === activeTab;
          const isPromoted = tabId === promotion.bottomPanelTab;
          return (
            <button
              key={tabId}
              role="tab"
              aria-selected={isActive}
              aria-controls={`bottom-panel-content-${tabId}`}
              id={`bottom-panel-tab-${tabId}`}
              onClick={() => handleTabClick(tabId)}
              style={{
                background: "none",
                border: "none",
                borderBottom: isActive
                  ? "2px solid var(--color-origin-gold, #c8a84e)"
                  : isPromoted
                    ? "2px solid rgba(200,168,78,0.4)"
                    : "2px solid transparent",
                color: isActive
                  ? "var(--color-origin-gold, #c8a84e)"
                  : isPromoted
                    ? "rgba(232,230,222,0.74)"
                  : "var(--color-text-muted, #6b7280)",
                cursor: "pointer",
                padding: "0 10px",
                fontSize: 10,
                fontFamily: "monospace",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                lineHeight: `${TAB_STRIP_HEIGHT}px`,
                height: TAB_STRIP_HEIGHT,
                whiteSpace: "nowrap",
                flexShrink: 0,
              }}
            >
              {reg.label}
            </button>
          );
        })}
      </div>

      {showReason && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            minHeight: 18,
            padding: "0 10px",
            borderBottom: collapsed ? "none" : "1px solid rgba(213,173,87,0.08)",
            color: anticipation.confidence === "high"
              ? "rgba(213,173,87,0.78)"
              : "rgba(182,183,193,0.52)",
            fontFamily: "monospace",
            fontSize: 10,
            letterSpacing: "0.02em",
          }}
        >
          {promotion.reason}
        </div>
      )}

      {/* Content area */}
      <div
        role="tabpanel"
        id={`bottom-panel-content-${activeTab}`}
        aria-labelledby={`bottom-panel-tab-${activeTab}`}
        style={{
          height: collapsed ? 0 : height,
          overflow: collapsed ? "hidden" : "auto",
          transition: "height 200ms ease",
        }}
      >
        {!collapsed && ContentComponent && (
          <Suspense
            fallback={
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  height: "100%",
                  color: "var(--color-text-muted, #6b7280)",
                  fontFamily: "monospace",
                  fontSize: 11,
                }}
              >
                Loading...
              </div>
            }
          >
            <ContentComponent />
          </Suspense>
        )}
      </div>
    </div>
  );
}
