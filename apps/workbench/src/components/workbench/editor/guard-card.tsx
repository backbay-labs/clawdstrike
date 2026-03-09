import { useState, useCallback, useMemo } from "react";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { Switch } from "@/components/ui/switch";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { GuardConfigFields } from "@/components/workbench/editor/guard-config-fields";
import { useGuardProvenance } from "@/components/workbench/editor/inheritance-chain";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId, GuardConfigMap } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconLock,
  IconShieldCheck,
  IconNetwork,
  IconEye,
  IconFileCheck,
  IconTerminal,
  IconTool,
  IconBrain,
  IconSkull,
  IconDeviceDesktop,
  IconPlugConnected,
  IconKeyboard,
  IconSpider,
  IconChevronDown,
  IconChevronUp,
  IconAlertTriangle,
  IconGripVertical,
} from "@tabler/icons-react";

const ICON_MAP: Record<string, typeof IconLock> = {
  IconLock,
  IconShieldCheck,
  IconNetwork,
  IconEye,
  IconFileCheck,
  IconTerminal,
  IconTool,
  IconBrain,
  IconSkull,
  IconDeviceDesktop,
  IconPlugConnected,
  IconKeyboard,
  IconSpider,
};

function getGuardSummary(guardId: GuardId, config: Record<string, unknown>): string {
  const parts: string[] = [];

  // Count list-type fields
  for (const [key, val] of Object.entries(config)) {
    if (key === "enabled") continue;
    if (Array.isArray(val)) {
      parts.push(`${val.length} ${key.replace(/_/g, " ")}`);
    } else if (typeof val === "object" && val !== null) {
      // Nested config like detector
      const nested = val as Record<string, unknown>;
      for (const [nk, nv] of Object.entries(nested)) {
        if (typeof nv === "number") {
          parts.push(`${nk.replace(/_/g, " ")}: ${nv}`);
        }
      }
    } else if (typeof val === "number") {
      parts.push(`${key.replace(/_/g, " ")}: ${val}`);
    } else if (typeof val === "string" && key !== "enabled") {
      parts.push(`${key.replace(/_/g, " ")}: ${val}`);
    }
  }

  return parts.length > 0 ? parts.join(", ") : "default configuration";
}

interface GuardCardProps {
  guardId: GuardId;
  /** Enable reorder controls (up/down buttons, drag handle). Only shown in custom view. */
  reorderable?: boolean;
  /** Whether this is the first item (disables move-up). */
  isFirst?: boolean;
  /** Whether this is the last item (disables move-down). */
  isLast?: boolean;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  /** HTML5 drag-and-drop handlers for reordering. */
  onDragStart?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragOver?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragEnd?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDrop?: (e: React.DragEvent<HTMLDivElement>) => void;
  onDragLeave?: (e: React.DragEvent<HTMLDivElement>) => void;
  /** Whether this card is currently being dragged. */
  isDragging?: boolean;
  /** Drop position indicator: "above" or "below". */
  dropIndicator?: "above" | "below" | null;
}

const PROVENANCE_BADGE_STYLES: Record<string, string> = {
  inherited: "bg-[#6f7f9a]/10 text-[#6f7f9a] border-[#6f7f9a]/20",
  overridden: "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20",
  added: "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20",
  removed: "bg-[#c45c5c]/10 text-[#c45c5c] border-[#c45c5c]/20",
};

export function GuardCard({
  guardId,
  reorderable,
  isFirst,
  isLast,
  onMoveUp,
  onMoveDown,
  onDragStart,
  onDragOver,
  onDragEnd,
  onDrop,
  onDragLeave,
  isDragging,
  dropIndicator,
}: GuardCardProps) {
  const { state, dispatch } = useWorkbench();
  const [open, setOpen] = useState(false);
  const provenanceInfo = useGuardProvenance(guardId);

  const meta = GUARD_REGISTRY.find((g) => g.id === guardId);
  if (!meta) return null;

  const guardConfig = (state.activePolicy.guards[guardId] ?? {}) as Record<string, unknown>;
  const enabled = (guardConfig.enabled as boolean | undefined) ?? false;

  const Icon = ICON_MAP[meta.icon] ?? IconLock;

  // Per-guard native validation errors from the Rust engine
  const nativeErrors = state.nativeValidation.guardErrors[guardId] ?? [];
  const hasNativeErrors = nativeErrors.length > 0;

  const summary = useMemo(
    () => getGuardSummary(guardId, guardConfig),
    [guardId, guardConfig]
  );

  const handleToggle = useCallback(
    (checked: boolean | React.FormEvent<HTMLButtonElement>) => {
      const isEnabled = typeof checked === "boolean" ? checked : !enabled;
      dispatch({ type: "TOGGLE_GUARD", guardId, enabled: isEnabled });
    },
    [dispatch, guardId, enabled]
  );

  const handleConfigChange = useCallback(
    (key: string, value: unknown) => {
      // Handle nested keys like "detector.block_threshold"
      const parts = key.split(".");
      if (parts.length === 1) {
        dispatch({
          type: "UPDATE_GUARD",
          guardId,
          config: { [key]: value } as Partial<GuardConfigMap[GuardId]>,
        });
      } else {
        // Build nested update
        const [topKey, ...rest] = parts;
        const existing =
          (guardConfig[topKey] as Record<string, unknown> | undefined) ?? {};
        let nested: Record<string, unknown> = { ...existing };
        // For deep nesting we just handle 2 levels since that's all the registry uses
        if (rest.length === 1) {
          nested[rest[0]] = value;
        }
        dispatch({
          type: "UPDATE_GUARD",
          guardId,
          config: { [topKey]: nested } as Partial<GuardConfigMap[GuardId]>,
        });
      }
    },
    [dispatch, guardId, guardConfig]
  );

  return (
    <div
      className="relative"
      draggable={reorderable ? true : undefined}
      onDragStart={reorderable ? onDragStart : undefined}
      onDragOver={reorderable ? onDragOver : undefined}
      onDragEnd={reorderable ? onDragEnd : undefined}
      onDrop={reorderable ? onDrop : undefined}
      onDragLeave={reorderable ? onDragLeave : undefined}
    >
      {/* Drop indicator line — above */}
      {dropIndicator === "above" && (
        <div className="absolute top-0 left-0 right-0 h-0.5 bg-[#d4a84b] rounded-full z-10 -translate-y-1" />
      )}
    <Collapsible open={open} onOpenChange={setOpen}>
      <div
        className={cn(
          "rounded-lg border bg-[#0b0d13] guard-card-hover",
          hasNativeErrors
            ? "border-l-2 border-l-[#c45c5c] border-t-[#c45c5c]/20 border-r-[#c45c5c]/20 border-b-[#c45c5c]/20"
            : enabled
              ? "border-l-2 border-l-[#d4a84b] border-t-[#2d3240]/80 border-r-[#2d3240]/80 border-b-[#2d3240]/80"
              : "border-[#2d3240]/60 hover:border-[#2d3240]",
          isDragging && "opacity-40",
        )}
      >
        {/* Header */}
        <CollapsibleTrigger
          className="flex items-center gap-3 w-full px-3 py-3 text-left cursor-pointer hover:bg-[#131721]/50 transition-colors rounded-t-lg"
        >
          {/* Drag handle — only in custom reorder mode */}
          {reorderable && (
            <div
              className="shrink-0 cursor-grab active:cursor-grabbing text-[#6f7f9a] hover:text-[#d4a84b] transition-colors"
              onMouseDown={(e) => e.stopPropagation()}
            >
              <IconGripVertical size={14} stroke={1.5} />
            </div>
          )}
          <Icon
            size={16}
            stroke={1.5}
            className={cn(
              "shrink-0",
              hasNativeErrors ? "text-[#c45c5c]" : enabled ? "text-[#d4a84b]" : "text-[#6f7f9a]"
            )}
          />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "text-xs font-mono font-medium truncate",
                  enabled ? "text-[#ece7dc]" : "text-[#6f7f9a]"
                )}
              >
                {meta.name}
              </span>
              <VerdictBadge verdict={meta.defaultVerdict} />
              {provenanceInfo && (
                <span
                  className={cn(
                    "inline-flex items-center gap-1 px-1.5 py-0 text-[9px] font-mono border rounded select-none whitespace-nowrap",
                    PROVENANCE_BADGE_STYLES[provenanceInfo.provenance] ?? "",
                  )}
                  title={
                    provenanceInfo.source
                      ? `${provenanceInfo.provenance} ${provenanceInfo.provenance === "added" ? "" : `from ${provenanceInfo.source}`}`
                      : provenanceInfo.provenance
                  }
                >
                  {provenanceInfo.provenance === "inherited" && provenanceInfo.source
                    ? `from ${provenanceInfo.source}`
                    : provenanceInfo.provenance === "overridden" && provenanceInfo.source
                      ? "local override"
                      : provenanceInfo.provenance}
                </span>
              )}
              {hasNativeErrors && (
                <span className="inline-flex items-center gap-1 px-1.5 py-0 text-[9px] font-mono text-[#c45c5c] bg-[#c45c5c]/10 border border-[#c45c5c]/20 rounded">
                  <IconAlertTriangle size={10} stroke={1.5} />
                  {nativeErrors.length}
                </span>
              )}
            </div>
            {!open && (
              <p className="text-[10px] text-[#6f7f9a] truncate mt-0.5">
                {enabled ? summary : meta.description}
              </p>
            )}
          </div>
          <div
            className="shrink-0"
            onClick={(e) => e.stopPropagation()}
          >
            <Switch
              checked={enabled}
              onCheckedChange={handleToggle}
              size="sm"
              className="data-checked:bg-[#d4a84b]"
            />
          </div>
          {/* Move up/down buttons — only in custom reorder mode */}
          {reorderable && (
            <div
              className="shrink-0 flex flex-col gap-0"
              onClick={(e) => e.stopPropagation()}
            >
              <button
                type="button"
                disabled={isFirst}
                onClick={onMoveUp}
                className={cn(
                  "p-0.5 rounded transition-colors",
                  isFirst
                    ? "text-[#6f7f9a]/30 cursor-not-allowed"
                    : "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
                )}
                title="Move up"
              >
                <IconChevronUp size={12} stroke={1.5} />
              </button>
              <button
                type="button"
                disabled={isLast}
                onClick={onMoveDown}
                className={cn(
                  "p-0.5 rounded transition-colors",
                  isLast
                    ? "text-[#6f7f9a]/30 cursor-not-allowed"
                    : "text-[#6f7f9a] hover:text-[#d4a84b] hover:bg-[#d4a84b]/10"
                )}
                title="Move down"
              >
                <IconChevronDown size={12} stroke={1.5} />
              </button>
            </div>
          )}
          <IconChevronDown
            size={14}
            stroke={1.5}
            className={cn(
              "shrink-0 text-[#6f7f9a] transition-transform duration-200",
              open && "rotate-180"
            )}
          />
        </CollapsibleTrigger>

        {/* Native validation errors (shown below header, always visible when present) */}
        {hasNativeErrors && (
          <div className="px-3 pb-2 flex flex-col gap-1">
            {nativeErrors.map((msg, i) => (
              <div
                key={i}
                className="flex items-start gap-1.5 text-[10px] font-mono text-[#c45c5c]/90 bg-[#c45c5c]/5 border border-[#c45c5c]/10 rounded px-2 py-1"
              >
                <IconAlertTriangle size={10} stroke={1.5} className="shrink-0 mt-0.5" />
                <span>{msg}</span>
              </div>
            ))}
          </div>
        )}

        {/* Body */}
        <CollapsibleContent>
          <div className="px-3 pb-3 border-t border-[#2d3240]/50">
            <p className="text-[10px] text-[#6f7f9a] pt-2 pb-1">
              {meta.description}
            </p>
            <GuardConfigFields
              guardId={guardId}
              config={guardConfig}
              onChange={handleConfigChange}
            />
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
      {/* Drop indicator line — below */}
      {dropIndicator === "below" && (
        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-[#d4a84b] rounded-full z-10 translate-y-1" />
      )}
    </div>
  );
}
