/**
 * ViewTabRenderer - Keep-alive renderer for plugin editor tabs.
 *
 * Renders ALL open plugin view tabs simultaneously, hiding inactive tabs
 * via `display: none` instead of unmounting. This preserves component state
 * (scroll position, form inputs, selections) across tab switches.
 *
 * When a tab is evicted by LRU (disappears from the store), its div is
 * removed from the DOM, causing React to unmount the component.
 */
import { useCallback, useMemo, Suspense } from "react";
import { getView } from "@/lib/plugins/view-registry";
import type { ViewRegistration, ViewSlot } from "@/lib/plugins/view-registry";
import {
  usePluginViewTabs,
  useActivePluginViewTabId,
  setPluginViewTabTitle,
  setPluginViewTabDirty,
} from "@/lib/plugins/plugin-view-tab-store";
import type { PluginViewTab } from "@/lib/plugins/plugin-view-tab-store";
import { NO_OP_VIEW_STORAGE, ViewErrorBoundary } from "./view-shell";

// ---------------------------------------------------------------------------
// EditorTabLoadingFallback (internal)
// ---------------------------------------------------------------------------

function EditorTabLoadingFallback() {
  return (
    <div className="flex flex-col items-center justify-center gap-2 h-full">
      <div className="w-5 h-5 border-2 border-[#6f7f9a]/30 border-t-[#6f7f9a] rounded-full animate-spin" />
      <span className="text-[#6f7f9a] text-xs">Loading plugin view...</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// PluginEditorTabBridge (internal)
// ---------------------------------------------------------------------------

function PluginEditorTabBridge({
  registration,
  viewId,
  isActive,
}: {
  registration: ViewRegistration;
  viewId: string;
  isActive: boolean;
}) {
  const handleSetTitle = useCallback(
    (title: string) => {
      setPluginViewTabTitle(viewId, title);
    },
    [viewId],
  );

  const handleSetDirty = useCallback(
    (dirty: boolean) => {
      setPluginViewTabDirty(viewId, dirty);
    },
    [viewId],
  );

  const PluginComponent = registration.component;

  return (
    <ViewErrorBoundary>
      <Suspense fallback={<EditorTabLoadingFallback />}>
        <PluginComponent
          viewId={viewId}
          isActive={isActive}
          storage={NO_OP_VIEW_STORAGE}
          setTitle={handleSetTitle}
          setDirty={handleSetDirty}
        />
      </Suspense>
    </ViewErrorBoundary>
  );
}

// ---------------------------------------------------------------------------
// ViewTabRenderer (exported)
// ---------------------------------------------------------------------------

/**
 * Keep-alive renderer for plugin editor tabs.
 *
 * Renders a wrapper div for each open plugin view tab:
 * - Active tab: `display: block`
 * - Hidden tabs: `display: none` (preserves component state)
 *
 * Each plugin component receives full EditorTabProps:
 * viewId, isActive, storage, setTitle, setDirty
 */
export function ViewTabRenderer() {
  const tabs = usePluginViewTabs();
  const activeTabId = useActivePluginViewTabId();

  if (tabs.length === 0) {
    return null;
  }

  return (
    <>
      {tabs.map((tab) => {
        const registration = getView(tab.viewId);
        if (!registration) {
          // Plugin may have been unloaded
          return null;
        }

        const isActive = tab.viewId === activeTabId;

        return (
          <div
            key={tab.viewId}
            data-plugin-tab-id={tab.viewId}
            className="h-full w-full"
            style={{ display: isActive ? "block" : "none" }}
          >
            <PluginEditorTabBridge
              registration={registration}
              viewId={tab.viewId}
              isActive={isActive}
            />
          </div>
        );
      })}
    </>
  );
}
