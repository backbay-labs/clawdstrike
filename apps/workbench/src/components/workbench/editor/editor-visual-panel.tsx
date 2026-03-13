import { useState, useCallback } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { BaseRulesetSelector } from "@/components/workbench/editor/base-ruleset-selector";
import { InheritanceChain } from "@/components/workbench/editor/inheritance-chain";
import { GuardCard } from "@/components/workbench/editor/guard-card";
import { SettingsPanel } from "@/components/workbench/editor/settings-panel";
import { DeployPanel } from "@/components/workbench/editor/deploy-panel";
import { OriginEditor } from "@/components/workbench/editor/origin-editor";
import { GUARD_CATEGORIES } from "@/lib/workbench/guard-registry";
import type { GuardId } from "@/lib/workbench/types";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useNativeValidation, countNativeErrors } from "@/lib/workbench/use-native-validation";
import { useGuardOrder } from "@/lib/workbench/use-guard-order";
import { cn } from "@/lib/utils";
import {
  IconCategory,
  IconList,
  IconArrowsSort,
} from "@tabler/icons-react";

export function EditorVisualPanel() {
  const { state, dispatch } = useWorkbench();

  // Run native Rust validation on YAML changes (800ms debounce, no-op in web mode)
  useNativeValidation(state.yaml, dispatch);

  const nv = state.nativeValidation;
  const errorCount = countNativeErrors(nv);

  const {
    viewMode,
    setViewMode,
    guardOrder,
    moveGuardUp,
    moveGuardDown,
    moveGuardToIndex,
    resetOrder,
  } = useGuardOrder();

  // ---- Drag-and-drop state ----
  const [draggedId, setDraggedId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<{
    id: string;
    position: "above" | "below";
  } | null>(null);

  const handleDragStart = useCallback(
    (guardId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", guardId);
      // Use rAF so the browser captures the element snapshot before we fade it
      requestAnimationFrame(() => {
        setDraggedId(guardId);
      });
    },
    [],
  );

  const handleDragOver = useCallback(
    (guardId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      if (!draggedId || draggedId === guardId) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";

      // Determine above/below based on mouse Y relative to card midpoint
      const rect = e.currentTarget.getBoundingClientRect();
      const midY = rect.top + rect.height / 2;
      const position = e.clientY < midY ? "above" : "below";

      setDropTarget((prev) => {
        if (prev?.id === guardId && prev?.position === position) return prev;
        return { id: guardId, position };
      });
    },
    [draggedId],
  );

  const handleDragLeave = useCallback(
    (guardId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      // Only clear when truly leaving the element (not entering a child)
      const related = e.relatedTarget as Node | null;
      if (related && e.currentTarget.contains(related)) return;
      if (dropTarget?.id === guardId) {
        setDropTarget(null);
      }
    },
    [dropTarget],
  );

  const handleDrop = useCallback(
    (guardId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      const sourceId = e.dataTransfer.getData("text/plain");
      if (sourceId && sourceId !== guardId) {
        const rect = e.currentTarget.getBoundingClientRect();
        const midY = rect.top + rect.height / 2;
        const dropBelow = e.clientY >= midY;

        const targetIdx = guardOrder.indexOf(guardId);
        const sourceIdx = guardOrder.indexOf(sourceId);
        if (targetIdx >= 0 && sourceIdx >= 0) {
          // Compute final insert index, adjusting for source removal
          let insertIdx = dropBelow ? targetIdx + 1 : targetIdx;
          if (sourceIdx < insertIdx) {
            insertIdx -= 1;
          }
          moveGuardToIndex(sourceId, insertIdx);
        }
      }
      setDraggedId(null);
      setDropTarget(null);
    },
    [guardOrder, moveGuardToIndex],
  );

  const handleDragEnd = useCallback(() => {
    setDraggedId(null);
    setDropTarget(null);
  }, []);

  return (
    <ScrollArea className="h-full">
      <div className="flex flex-col">
        {/* Base ruleset selector */}
        <BaseRulesetSelector />

        {/* Inheritance chain visualization (only visible when extends is set) */}
        <InheritanceChain />

        {/* Native engine validation status badge */}
        {nv.valid !== null && (
          <div className="flex items-center gap-2 px-4 pt-3 pb-0">
            {nv.loading ? (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono text-[#d4a84b]/70 border border-[#d4a84b]/20 bg-[#d4a84b]/5 rounded animate-pulse">
                Engine: validating...
              </span>
            ) : nv.valid ? (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono text-[#3dbf84] border border-[#3dbf84]/20 bg-[#3dbf84]/5 rounded">
                <span className="w-1.5 h-1.5 rounded-full bg-[#3dbf84]" />
                Engine: valid
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono text-[#c45c5c] border border-[#c45c5c]/20 bg-[#c45c5c]/5 rounded">
                <span className="w-1.5 h-1.5 rounded-full bg-[#c45c5c]" />
                Engine: {errorCount} {errorCount === 1 ? "error" : "errors"}
              </span>
            )}
            {nv.topLevelErrors.length > 0 && (
              <div className="flex flex-col gap-0.5">
                {nv.topLevelErrors.map((msg, i) => (
                  <span key={i} className="text-[10px] font-mono text-[#c45c5c]/80 truncate max-w-[320px]">
                    {msg}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
        {nv.loading && nv.valid === null && (
          <div className="flex items-center gap-2 px-4 pt-3 pb-0">
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 text-[9px] font-mono text-[#d4a84b]/70 border border-[#d4a84b]/20 bg-[#d4a84b]/5 rounded animate-pulse">
              Engine: validating...
            </span>
          </div>
        )}

        {/* View mode toggle header */}
        <div className="flex items-center justify-between px-4 pt-4 pb-1">
          <div className="flex items-center gap-1.5">
            <IconArrowsSort size={12} stroke={1.5} className="text-[#6f7f9a]/70" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]">
              Guards
            </span>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setViewMode("category")}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                viewMode === "category"
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]"
              )}
              title="Group guards by category"
            >
              <IconCategory size={11} stroke={1.5} />
              Category
            </button>
            <button
              type="button"
              onClick={() => setViewMode("custom")}
              className={cn(
                "inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono rounded transition-colors",
                viewMode === "custom"
                  ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                  : "text-[#6f7f9a] hover:text-[#ece7dc] border border-transparent hover:border-[#2d3240]"
              )}
              title="Custom order — drag to reorder"
            >
              <IconList size={11} stroke={1.5} />
              Custom
            </button>
            {viewMode === "custom" && (
              <button
                type="button"
                onClick={resetOrder}
                className="ml-1 px-1.5 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#c45c5c] transition-colors"
                title="Reset to default order"
              >
                Reset
              </button>
            )}
          </div>
        </div>

        {/* Guard cards — Category view */}
        {viewMode === "category" && (
          <div className="flex flex-col gap-6 p-4 pt-2">
            {GUARD_CATEGORIES.map((category) => (
              <section key={category.id} className="flex flex-col gap-2">
                <h2 className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/80 px-1">
                  {category.label}
                </h2>
                <div className="flex flex-col gap-2">
                  {category.guards.map((guardId) => (
                    <GuardCard key={guardId} guardId={guardId as GuardId} />
                  ))}
                </div>
              </section>
            ))}
          </div>
        )}

        {/* Guard cards — Custom reorderable view */}
        {viewMode === "custom" && (
          <div className="flex flex-col gap-2 p-4 pt-2">
            {guardOrder.map((guardId, idx) => (
              <GuardCard
                key={guardId}
                guardId={guardId as GuardId}
                reorderable
                isFirst={idx === 0}
                isLast={idx === guardOrder.length - 1}
                onMoveUp={() => moveGuardUp(guardId)}
                onMoveDown={() => moveGuardDown(guardId)}
                onDragStart={handleDragStart(guardId)}
                onDragOver={handleDragOver(guardId)}
                onDragEnd={handleDragEnd}
                onDrop={handleDrop(guardId)}
                onDragLeave={handleDragLeave(guardId)}
                isDragging={draggedId === guardId}
                dropIndicator={
                  dropTarget?.id === guardId ? dropTarget.position : null
                }
              />
            ))}
          </div>
        )}

        {/* Origin enforcement (v1.4.0 only) */}
        <OriginEditor />

        {/* Settings panel */}
        <SettingsPanel />

        {/* Deploy panel (visible when connected to fleet) */}
        <DeployPanel />
      </div>
    </ScrollArea>
  );
}
