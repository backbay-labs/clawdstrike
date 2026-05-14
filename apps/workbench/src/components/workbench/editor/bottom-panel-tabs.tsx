/**
 * BottomPanelTabs - Renders a tab bar merging built-in and plugin-contributed
 * bottom panel tabs. Plugin tabs are sourced from the ViewRegistry via
 * useViewsBySlot("bottomPanelTab") and rendered through ViewContainer for
 * ErrorBoundary + Suspense isolation.
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

/** A built-in tab definition provided by the caller. */
export interface BuiltInTab {
  id: string;
  label: string;
  icon: ComponentType;
  content: ReactNode;
}

interface BottomPanelTabsProps {
  /** Built-in tab definitions (Problems, Test Runner, etc.). */
  builtInTabs: BuiltInTab[];
  /** Current height of the bottom panel area, passed to plugin views. */
  panelHeight: number;
  /** ID of the currently active tab (null = none). */
  activeTabId: string | null;
  /** Callback when user clicks a tab. */
  onTabChange: (tabId: string) => void;
}

// ---------------------------------------------------------------------------
// Internal: Plugin view wrapper that injects panelHeight
// ---------------------------------------------------------------------------

function BottomPanelPluginView({
  registration,
  panelHeight,
}: {
  registration: ViewRegistration;
  panelHeight: number;
}) {
  const wrappedRegistration = useMemo(
    () => ({
      ...registration,
      component: (props: ViewProps) => {
        const Component = registration.component;
        return <Component {...props} panelHeight={panelHeight} />;
      },
    }),
    [registration, panelHeight],
  );

  return <ViewContainer registration={wrappedRegistration} isActive={true} />;
}

// ---------------------------------------------------------------------------
// Unified tab descriptor
// ---------------------------------------------------------------------------

interface UnifiedTab {
  id: string;
  label: string;
  icon?: ComponentType;
  type: "builtin" | "plugin";
  /** Index into builtInTabs for built-in tabs. */
  builtInIndex?: number;
  /** Registration for plugin tabs. */
  registration?: ViewRegistration;
}

// ---------------------------------------------------------------------------
// BottomPanelTabs
// ---------------------------------------------------------------------------

export function BottomPanelTabs({
  builtInTabs,
  panelHeight,
  activeTabId,
  onTabChange,
}: BottomPanelTabsProps) {
  const pluginViews = useViewsBySlot("bottomPanelTab");

  const allTabs = useMemo<UnifiedTab[]>(() => {
    const tabs: UnifiedTab[] = [];

    // Built-in tabs first, in provided order
    builtInTabs.forEach((tab, index) => {
      tabs.push({
        id: tab.id,
        label: tab.label,
        icon: tab.icon,
        type: "builtin",
        builtInIndex: index,
      });
    });

    // Plugin tabs sorted by priority (already sorted by view-registry)
    for (const reg of pluginViews) {
      tabs.push({
        id: reg.id,
        label: reg.label,
        type: "plugin",
        registration: reg,
      });
    }

    return tabs;
  }, [builtInTabs, pluginViews]);

  // No tabs at all -- render nothing
  if (allTabs.length === 0) {
    return null;
  }

  // Resolve effective active tab: if activeTabId doesn't match any, default to first
  const effectiveActiveId =
    activeTabId && allTabs.some((t) => t.id === activeTabId)
      ? activeTabId
      : allTabs[0].id;

  const activeTab = allTabs.find((t) => t.id === effectiveActiveId);

  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div className="flex items-center bg-[#0b0d13] border-b border-[#2d3240] shrink-0">
        {allTabs.map((tab) => {
          const isActive = tab.id === effectiveActiveId;
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "inline-flex items-center gap-1 px-3 py-1.5 text-[9px] font-mono transition-colors",
                isActive
                  ? "text-[#ece7dc] border-b-2 border-[#d4a84b]"
                  : "text-[#6f7f9a] hover:text-[#ece7dc]",
              )}
            >
              {Icon && <Icon />}
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Content area */}
      <div className="flex-1 min-h-0 overflow-auto">
        {activeTab?.type === "builtin" &&
          activeTab.builtInIndex != null &&
          builtInTabs[activeTab.builtInIndex]?.content}
        {activeTab?.type === "plugin" && activeTab.registration && (
          <BottomPanelPluginView
            registration={activeTab.registration}
            panelHeight={panelHeight}
          />
        )}
      </div>
    </div>
  );
}
