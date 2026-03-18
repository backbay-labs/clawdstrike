/**
 * ContextInspector - Right-side inspector panel with tabbed content.
 *
 * Tabs: context, graph, proof, companion.
 * State driven by InspectorState via useContextInspector() / useWorkbenchDispatch().
 */
import { Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import type { InspectorTabId } from "./workbenchState";
import { useActiveTab, useContextInspector, useWorkbenchDispatch } from "./WorkbenchStateProvider";
import { useAnticipationContext, useSidebarDirector } from "./anticipation";

const ContextTab = lazy(() =>
  import("./inspector/ContextTab").then((m) => ({ default: m.ContextTab })),
);
const GraphTab = lazy(() =>
  import("./inspector/GraphTab").then((m) => ({ default: m.GraphTab })),
);
const ProofTab = lazy(() =>
  import("./inspector/ProofTab").then((m) => ({ default: m.ProofTab })),
);
const CompanionTab = lazy(() =>
  import("./inspector/CompanionTab").then((m) => ({ default: m.CompanionTab })),
);

interface InspectorTabDef {
  id: InspectorTabId;
  label: string;
  badge?: string;
}

const INSPECTOR_TABS: InspectorTabDef[] = [
  { id: "context", label: "Context" },
  { id: "graph", label: "Graph" },
  { id: "proof", label: "Proof" },
  { id: "companion", label: "Companion", badge: "beta" },
];

const TAB_STRIP_HEIGHT = 28;
const RESIZE_HANDLE_WIDTH = 4;

function InspectorContent({ tabId }: { tabId: InspectorTabId }) {
  switch (tabId) {
    case "context":
      return <ContextTab />;
    case "graph":
      return <GraphTab />;
    case "proof":
      return <ProofTab />;
    case "companion":
      return <CompanionTab />;
  }
}

export function ContextInspector() {
  const location = useLocation();
  const { activeTab, width, visible } = useContextInspector();
  const dispatch = useWorkbenchDispatch();
  const activeWorkbenchTab = useActiveTab();
  const anticipation = useAnticipationContext();
  const sidebarDirector = useSidebarDirector();
  const promotion = sidebarDirector.adjacentSurfacePromotion;
  const inObservatoryRoute =
    location.pathname === "/nexus" || location.pathname === "/nexus/scene";
  const suppressPromotion = activeWorkbenchTab?.kind === "spirit-chamber" || inObservatoryRoute;

  const [isDragging, setIsDragging] = useState(false);
  const dragStartX = useRef(0);
  const dragStartWidth = useRef(0);

  const handleTabClick = useCallback(
    (tabId: InspectorTabId) => {
      dispatch({ type: "SET_INSPECTOR_TAB", payload: tabId });
    },
    [dispatch],
  );

  // -- Drag-to-resize (left edge) --
  const handleResizePointerDown = useCallback(
    (e: React.PointerEvent) => {
      e.preventDefault();
      setIsDragging(true);
      dragStartX.current = e.clientX;
      dragStartWidth.current = width;
      (e.target as HTMLElement).setPointerCapture(e.pointerId);
    },
    [width],
  );

  useEffect(() => {
    if (!isDragging) return;

    const handleMove = (e: PointerEvent) => {
      // Dragging left increases width, dragging right decreases
      const delta = dragStartX.current - e.clientX;
      dispatch({ type: "SET_INSPECTOR_WIDTH", payload: dragStartWidth.current + delta });
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
      suppressPromotion
      || !promotion.inspectorTab
      || !promotion.shouldShowInspector
      || !visible
      || activeTab === promotion.inspectorTab
    ) {
      return;
    }

    dispatch({ type: "SET_INSPECTOR_TAB", payload: promotion.inspectorTab });
  }, [
    activeTab,
    dispatch,
    inObservatoryRoute,
    promotion.inspectorTab,
    promotion.shouldShowInspector,
    suppressPromotion,
    visible,
  ]);

  if (!visible) return null;

  return (
    <div
      role="complementary"
      aria-label="Context inspector"
      style={{
        display: "flex",
        flexDirection: "row",
        width,
        flexShrink: 0,
        background: "rgba(4,6,10,0.95)",
        borderLeft: "1px solid var(--color-border-subtle, #1a1d2e)",
        overflow: "hidden",
        transition: isDragging ? "none" : "width 200ms ease",
      }}
    >
      {/* Resize handle (left edge) */}
      <div
        role="separator"
        aria-label="Resize inspector"
        aria-orientation="vertical"
        tabIndex={0}
        onPointerDown={handleResizePointerDown}
        style={{
          width: RESIZE_HANDLE_WIDTH,
          cursor: "ew-resize",
          background: isDragging ? "var(--color-origin-gold, #c8a84e)" : "transparent",
          flexShrink: 0,
        }}
      />

      {/* Main inspector content */}
      <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
        {/* Tab strip */}
        <div
          role="tablist"
          aria-label="Inspector tabs"
          style={{
            display: "flex",
            alignItems: "center",
            height: TAB_STRIP_HEIGHT,
            flexShrink: 0,
            paddingLeft: 4,
            paddingRight: 4,
            borderBottom: "1px solid var(--color-border-subtle, #1a1d2e)",
          }}
        >
          {INSPECTOR_TABS.map((tab) => {
            const isActive = tab.id === activeTab;
            const isPromoted = tab.id === promotion.inspectorTab;
            return (
              <button
                key={tab.id}
                role="tab"
                aria-selected={isActive}
                aria-controls={`inspector-content-${tab.id}`}
                id={`inspector-tab-${tab.id}`}
                onClick={() => handleTabClick(tab.id)}
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
                  padding: "0 8px",
                  fontSize: 10,
                  fontFamily: "monospace",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  lineHeight: `${TAB_STRIP_HEIGHT}px`,
                  height: TAB_STRIP_HEIGHT,
                  whiteSpace: "nowrap",
                  flexShrink: 0,
                  display: "flex",
                  alignItems: "center",
                  gap: 4,
                }}
              >
                {tab.label}
                {tab.badge && (
                  <span
                    style={{
                      display: "inline-block",
                      padding: "1px 4px",
                      borderRadius: 3,
                      background: "rgba(200,168,78,0.15)",
                      color: "var(--color-origin-gold, #c8a84e)",
                      fontSize: 8,
                      fontWeight: 600,
                      textTransform: "uppercase",
                      letterSpacing: "0.06em",
                      lineHeight: "12px",
                    }}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {!suppressPromotion && promotion.reason && promotion.inspectorTab && (
          <div
            style={{
              minHeight: 18,
              padding: "0 10px",
              borderBottom: "1px solid rgba(213,173,87,0.08)",
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
          id={`inspector-content-${activeTab}`}
          aria-labelledby={`inspector-tab-${activeTab}`}
          style={{ flex: 1, overflow: "auto" }}
        >
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
            <InspectorContent tabId={activeTab} />
          </Suspense>
        </div>
      </div>
    </div>
  );
}
