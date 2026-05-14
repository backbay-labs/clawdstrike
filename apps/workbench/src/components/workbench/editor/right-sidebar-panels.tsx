/**
 * RightSidebarPanels - Renders a vertical icon strip with toggle buttons for
 * built-in and plugin-contributed right sidebar panels. Plugin panels are
 * sourced from the ViewRegistry via useViewsBySlot("rightSidebarPanel") and
 * rendered through ViewContainer for ErrorBoundary + Suspense isolation.
 *
 * Returns a fragment: [panel content (if active)] + [icon strip].
 * The parent (policy-editor) positions them in the flex layout.
 */
import { useMemo } from "react";
import type { ComponentType, ReactNode } from "react";
import { useViewsBySlot } from "@/lib/plugins/view-registry";
import type { ViewRegistration, ViewProps } from "@/lib/plugins/view-registry";
import { ViewContainer } from "@/components/plugins/view-container";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A built-in panel definition provided by the caller. */
export interface BuiltInPanel {
  id: string;
  label: string;
  icon: ComponentType;
  content: ReactNode;
}

interface RightSidebarPanelsProps {
  /** Built-in panel definitions (Version History, Guard Config, etc.). */
  builtInPanels: BuiltInPanel[];
  /** Current width of the right sidebar (default 280). */
  sidebarWidth: number;
  /** ID of the currently active panel (null = sidebar closed). */
  activePanelId: string | null;
  /** Callback when user clicks a panel button. null means close sidebar. */
  onPanelChange: (panelId: string | null) => void;
}

// ---------------------------------------------------------------------------
// Internal: Plugin view wrapper that injects sidebarWidth
// ---------------------------------------------------------------------------

function RightSidebarPluginView({
  registration,
  sidebarWidth,
}: {
  registration: ViewRegistration;
  sidebarWidth: number;
}) {
  const wrappedRegistration = useMemo(
    () => ({
      ...registration,
      component: (props: ViewProps) => {
        const Component = registration.component;
        return <Component {...props} sidebarWidth={sidebarWidth} />;
      },
    }),
    [registration, sidebarWidth],
  );

  return <ViewContainer registration={wrappedRegistration} isActive={true} />;
}

// ---------------------------------------------------------------------------
// Unified panel descriptor
// ---------------------------------------------------------------------------

interface UnifiedPanel {
  id: string;
  label: string;
  icon?: ComponentType;
  type: "builtin" | "plugin";
  /** Index into builtInPanels for built-in panels. */
  builtInIndex?: number;
  /** Registration for plugin panels. */
  registration?: ViewRegistration;
}

// ---------------------------------------------------------------------------
// RightSidebarPanels
// ---------------------------------------------------------------------------

export function RightSidebarPanels({
  builtInPanels,
  sidebarWidth,
  activePanelId,
  onPanelChange,
}: RightSidebarPanelsProps) {
  const pluginViews = useViewsBySlot("rightSidebarPanel");

  const allPanels = useMemo<UnifiedPanel[]>(() => {
    const panels: UnifiedPanel[] = [];

    // Built-in panels first, in provided order
    builtInPanels.forEach((panel, index) => {
      panels.push({
        id: panel.id,
        label: panel.label,
        icon: panel.icon,
        type: "builtin",
        builtInIndex: index,
      });
    });

    // Plugin panels sorted by priority (already sorted by view-registry)
    for (const reg of pluginViews) {
      panels.push({
        id: reg.id,
        label: reg.label,
        type: "plugin",
        registration: reg,
      });
    }

    return panels;
  }, [builtInPanels, pluginViews]);

  const activePanel = activePanelId
    ? allPanels.find((p) => p.id === activePanelId)
    : undefined;

  const handleClick = (panelId: string) => {
    if (panelId === activePanelId) {
      // Toggle off -- close the sidebar
      onPanelChange(null);
    } else {
      onPanelChange(panelId);
    }
  };

  return (
    <>
      {/* Panel content (left of icon strip) */}
      {activePanel && (
        <div
          className="shrink-0 border-l border-[#2d3240] overflow-auto"
          style={{ width: sidebarWidth }}
        >
          {activePanel.type === "builtin" &&
            activePanel.builtInIndex != null &&
            builtInPanels[activePanel.builtInIndex]?.content}
          {activePanel.type === "plugin" && activePanel.registration && (
            <RightSidebarPluginView
              registration={activePanel.registration}
              sidebarWidth={sidebarWidth}
            />
          )}
        </div>
      )}

      {/* Vertical icon strip */}
      <div className="flex flex-col items-center py-1 bg-[#0b0d13] border-l border-[#2d3240] shrink-0">
        {allPanels.map((panel) => {
          const isActive = panel.id === activePanelId;
          const Icon = panel.icon;
          return (
            <button
              key={panel.id}
              type="button"
              onClick={() => handleClick(panel.id)}
              aria-label={panel.label}
              className={cn(
                "flex items-center justify-center w-8 h-8 rounded transition-colors",
                isActive
                  ? "bg-[#d4a84b]/15 text-[#d4a84b]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc]",
              )}
              title={panel.label}
            >
              {Icon && <Icon />}
            </button>
          );
        })}
      </div>
    </>
  );
}
