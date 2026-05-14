/**
 * ViewContainer - Wraps plugin-contributed views in ErrorBoundary + Suspense.
 *
 * Every plugin view renders through this component, ensuring:
 * 1. A crashing plugin view does not take down the workbench (ErrorBoundary)
 * 2. Lazy-loaded plugin components show an appropriate loading skeleton (Suspense)
 * 3. Slot-appropriate fallbacks (full-panel spinner vs. inline skeleton)
 */
import { Suspense } from "react";
import type { ViewRegistration, ViewSlot } from "@/lib/plugins/view-registry";
import { NO_OP_VIEW_STORAGE, ViewErrorBoundary } from "./view-shell";

// ---------------------------------------------------------------------------
// ViewLoadingFallback (internal)
// ---------------------------------------------------------------------------

function ViewLoadingFallback({ slotType }: { slotType: ViewSlot }) {
  if (slotType === "editorTab" || slotType === "activityBarPanel") {
    // Full height centered spinner with text
    return (
      <div className="flex flex-col items-center justify-center gap-2 h-full">
        <div className="w-5 h-5 border-2 border-[#6f7f9a]/30 border-t-[#6f7f9a] rounded-full animate-spin" />
        <span className="text-[#6f7f9a] text-xs">Loading plugin view...</span>
      </div>
    );
  }

  if (slotType === "statusBarWidget") {
    // Inline small spinner, no text
    return (
      <span className="inline-flex items-center">
        <span className="w-[10px] h-[10px] border border-[#6f7f9a]/30 border-t-[#6f7f9a] rounded-full animate-spin" />
      </span>
    );
  }

  // All others: medium spinner with short text
  return (
    <div className="flex items-center justify-center gap-2 p-3">
      <div className="w-4 h-4 border-2 border-[#6f7f9a]/30 border-t-[#6f7f9a] rounded-full animate-spin" />
      <span className="text-[#6f7f9a] text-xs">Loading...</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ViewContainer (exported)
// ---------------------------------------------------------------------------

interface ViewContainerProps {
  registration: ViewRegistration;
  isActive?: boolean;
  slotType?: ViewSlot;
  storage?: {
    get(key: string): unknown;
    set(key: string, value: unknown): void;
  };
}

export function ViewContainer({
  registration,
  isActive = true,
  slotType,
  storage,
}: ViewContainerProps) {
  const effectiveSlotType = slotType ?? registration.slot;
  const effectiveStorage = storage ?? NO_OP_VIEW_STORAGE;
  const PluginComponent = registration.component;

  return (
    <ViewErrorBoundary>
      <Suspense fallback={<ViewLoadingFallback slotType={effectiveSlotType} />}>
        <PluginComponent
          viewId={registration.id}
          isActive={isActive}
          storage={effectiveStorage}
        />
      </Suspense>
    </ViewErrorBoundary>
  );
}
