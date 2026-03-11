import { useState, useMemo, useCallback } from "react";
import { useMultiPolicy } from "@/lib/workbench/multi-policy-store";
import type { PolicyTab } from "@/lib/workbench/multi-policy-store";
import { GUARD_REGISTRY, GUARD_CATEGORIES } from "@/lib/workbench/guard-registry";
import type { GuardId } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconShieldCheck,
  IconArrowLeft,
  IconCheck,
  IconX,
  IconMinus,
  IconToggleLeft,
  IconToggleRight,
  IconChevronDown,
  IconChevronRight,
  IconWand,
  IconShieldLock,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Returns true/false for configured guards, null for missing guards. */
function isGuardEnabled(tab: PolicyTab, guardId: string): boolean | null {
  const cfg = tab.policy.guards[guardId as GuardId];
  if (!cfg) return null; // guard not in policy at all
  if ("enabled" in cfg) return (cfg as { enabled?: boolean }).enabled === true;
  return false; // guard present but no enabled field → treat as disabled
}

function enabledGuardCount(tab: PolicyTab): number {
  return GUARD_REGISTRY.filter((g) => isGuardEnabled(tab, g.id) === true).length;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface PolicyCommandCenterProps {
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function PolicyCommandCenter({ onClose }: PolicyCommandCenterProps) {
  const { tabs, multiDispatch } = useMultiPolicy();

  const allCategoryIds = useMemo(
    () => GUARD_CATEGORIES.map((c) => c.id),
    [],
  );

  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(
    () => new Set(allCategoryIds),
  );

  const [highlightedTabId, setHighlightedTabId] = useState<string | null>(null);

  // --- Derived stats ---

  // Recompute on every render — tabs is a fresh array from the store after each dispatch
  let totalGuardsEnabled = 0;
  for (const tab of tabs) {
    totalGuardsEnabled += enabledGuardCount(tab);
  }

  // --- Callbacks ---

  const toggleCategory = useCallback((categoryId: string) => {
    setExpandedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(categoryId)) {
        next.delete(categoryId);
      } else {
        next.add(categoryId);
      }
      return next;
    });
  }, []);

  const handleCellToggle = useCallback(
    (tabId: string, guardId: string, currentEnabled: boolean | null) => {
      const newEnabled = currentEnabled !== true;
      multiDispatch({
        type: "BULK_UPDATE_GUARDS",
        updates: [{ tabId, guardId: guardId as GuardId, enabled: newEnabled }],
      });
    },
    [multiDispatch],
  );

  const handleEnableAllForGuard = useCallback(
    (guardId: string) => {
      const updates = tabs.map((tab) => ({
        tabId: tab.id,
        guardId: guardId as GuardId,
        enabled: true,
      }));
      multiDispatch({ type: "BULK_UPDATE_GUARDS", updates });
    },
    [tabs, multiDispatch],
  );

  const handleDisableAllForGuard = useCallback(
    (guardId: string) => {
      const updates = tabs.map((tab) => ({
        tabId: tab.id,
        guardId: guardId as GuardId,
        enabled: false,
      }));
      multiDispatch({ type: "BULK_UPDATE_GUARDS", updates });
    },
    [tabs, multiDispatch],
  );

  const handleEnableAllGuardsEverywhere = useCallback(() => {
    const updates = tabs.flatMap((tab) =>
      GUARD_REGISTRY.map((g) => ({
        tabId: tab.id,
        guardId: g.id as GuardId,
        enabled: true,
      })),
    );
    multiDispatch({ type: "BULK_UPDATE_GUARDS", updates });
  }, [tabs, multiDispatch]);

  const isAllEnabledForGuard = useCallback(
    (guardId: string): boolean => {
      return tabs.every((tab) => isGuardEnabled(tab, guardId) === true);
    },
    [tabs],
  );

  // --- Render helpers ---

  const renderGuardMiniBar = (tab: PolicyTab) => {
    return (
      <div className="flex gap-[2px]">
        {GUARD_REGISTRY.map((g) => {
          const enabled = isGuardEnabled(tab, g.id) === true;
          return (
            <div
              key={g.id}
              className={cn(
                "w-[6px] h-[6px] rounded-[1px]",
                enabled ? "bg-[#d4a84b]" : "bg-[#2d3240]",
              )}
            />
          );
        })}
      </div>
    );
  };

  const renderCellIcon = (status: boolean | null) => {
    if (status === true) {
      return <IconCheck size={12} className="text-[#3dbf84]" />;
    }
    if (status === false) {
      return <IconX size={12} className="text-[#c45c5c]" />;
    }
    return <IconMinus size={10} className="text-[#3a4050]" />;
  };

  return (
    <div className="flex flex-col h-full w-full bg-[#05060a] overflow-y-auto">
      {/* ---------------------------------------------------------------- */}
      {/* Header */}
      {/* ---------------------------------------------------------------- */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-[#2d3240]">
        <div className="flex items-center gap-3">
          <button
            onClick={onClose}
            className="flex items-center justify-center w-7 h-7 rounded-md bg-[#131721] border border-[#2d3240] hover:border-[#d4a84b]/40 transition-colors"
          >
            <IconArrowLeft size={14} className="text-[#6f7f9a]" />
          </button>
          <div className="flex items-center gap-2">
            <IconShieldCheck size={18} className="text-[#d4a84b]" />
            <h1 className="font-syne text-[14px] font-semibold text-[#ece7dc] tracking-wide">
              Policy Command Center
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#6f7f9a]">
            <span className="text-[#ece7dc] font-medium">{tabs.length}</span>
            <span>{tabs.length === 1 ? "policy" : "policies"}</span>
          </div>
          <div className="w-px h-3 bg-[#2d3240]" />
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#6f7f9a]">
            <span className="text-[#d4a84b] font-medium">{totalGuardsEnabled}</span>
            <span>guards enabled</span>
          </div>
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Policy Summary Cards */}
      {/* ---------------------------------------------------------------- */}
      <div className="px-5 py-3 border-b border-[#2d3240]">
        <div className="flex gap-2 overflow-x-auto pb-1 scrollbar-thin scrollbar-thumb-[#2d3240]">
          {tabs.map((tab) => {
            const count = enabledGuardCount(tab);
            const isHighlighted = highlightedTabId === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() =>
                  setHighlightedTabId(isHighlighted ? null : tab.id)
                }
                className={cn(
                  "flex-shrink-0 flex flex-col gap-1.5 px-3 py-2 rounded-md border transition-all",
                  "bg-[#131721] hover:bg-[#1a1f2e]",
                  isHighlighted
                    ? "border-[#d4a84b]/60 shadow-[0_0_8px_rgba(212,168,75,0.1)]"
                    : "border-[#2d3240] hover:border-[#3d4455]",
                )}
              >
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] font-mono text-[#ece7dc] truncate max-w-[120px]">
                    {tab.name}
                  </span>
                  {tab.dirty && (
                    <div className="w-1.5 h-1.5 rounded-full bg-[#d4a84b] flex-shrink-0" />
                  )}
                </div>
                {renderGuardMiniBar(tab)}
                <span className="text-[9px] font-mono text-[#6f7f9a]">
                  {count}/{GUARD_REGISTRY.length} guards
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Guard Coverage Matrix */}
      {/* ---------------------------------------------------------------- */}
      <div className="flex-1 px-5 py-4 overflow-x-auto">
        <div className="min-w-fit">
          {/* Matrix header row */}
          <div className="flex items-end gap-0 mb-1">
            {/* Guard name column header */}
            <div className="w-[200px] flex-shrink-0 pr-3 pb-2">
              <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                Guard
              </span>
            </div>

            {/* Policy column headers */}
            {tabs.map((tab) => (
              <div
                key={tab.id}
                className={cn(
                  "w-[72px] flex-shrink-0 flex items-end justify-center pb-2",
                  highlightedTabId === tab.id && "bg-[#d4a84b]/5 rounded-t-md",
                )}
              >
                <span
                  className="text-[9px] font-mono text-[#6f7f9a] truncate max-w-[64px] text-center block"
                  title={tab.name}
                >
                  {tab.name}
                </span>
              </div>
            ))}

            {/* Row action column header */}
            <div className="w-[80px] flex-shrink-0 flex items-end justify-center pb-2">
              <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                All
              </span>
            </div>
          </div>

          {/* Category groups */}
          {GUARD_CATEGORIES.map((category) => {
            const isExpanded = expandedCategories.has(category.id);
            const categoryGuards = GUARD_REGISTRY.filter(
              (g) => g.category === category.id,
            );

            return (
              <div key={category.id} className="mb-1">
                {/* Category header */}
                <button
                  onClick={() => toggleCategory(category.id)}
                  className="flex items-center gap-1.5 w-full py-1.5 px-2 rounded-md bg-[#0b0d13] hover:bg-[#111420] transition-colors"
                >
                  {isExpanded ? (
                    <IconChevronDown size={11} className="text-[#6f7f9a]" />
                  ) : (
                    <IconChevronRight size={11} className="text-[#6f7f9a]" />
                  )}
                  <span className="text-[9px] font-mono uppercase tracking-widest text-[#6f7f9a] font-medium">
                    {category.label}
                  </span>
                  <span className="text-[9px] font-mono text-[#3a4050]">
                    ({categoryGuards.length})
                  </span>
                </button>

                {/* Guard rows */}
                {isExpanded &&
                  categoryGuards.map((guard) => {
                    const allEnabled = isAllEnabledForGuard(guard.id);

                    return (
                      <div
                        key={guard.id}
                        className="flex items-center gap-0 py-1 hover:bg-[#0b0d13]/60 rounded-sm transition-colors"
                      >
                        {/* Guard name cell */}
                        <div className="w-[200px] flex-shrink-0 flex items-center gap-2 pr-3 pl-5">
                          <span className="text-[10px] font-mono text-[#ece7dc]" title={guard.description}>
                            {guard.name}
                          </span>
                        </div>

                        {/* Per-policy cells */}
                        {tabs.map((tab) => {
                          const status = isGuardEnabled(tab, guard.id);
                          return (
                            <button
                              key={tab.id}
                              onClick={() =>
                                handleCellToggle(tab.id, guard.id, status)
                              }
                              className={cn(
                                "w-[72px] flex-shrink-0 flex items-center justify-center py-1.5",
                                "rounded-sm hover:bg-[#1a1f2e] transition-colors cursor-pointer",
                                highlightedTabId === tab.id &&
                                  "bg-[#d4a84b]/5",
                              )}
                              title={
                                status === true
                                  ? `Disable ${guard.name} in ${tab.name}`
                                  : status === false
                                    ? `Enable ${guard.name} in ${tab.name}`
                                    : `Enable ${guard.name} in ${tab.name}`
                              }
                            >
                              {renderCellIcon(status)}
                            </button>
                          );
                        })}

                        {/* Row action: toggle all */}
                        <div className="w-[80px] flex-shrink-0 flex items-center justify-center">
                          <button
                            onClick={() =>
                              allEnabled
                                ? handleDisableAllForGuard(guard.id)
                                : handleEnableAllForGuard(guard.id)
                            }
                            className={cn(
                              "flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-mono transition-colors",
                              allEnabled
                                ? "text-[#3dbf84] hover:bg-[#3dbf84]/10"
                                : "text-[#6f7f9a] hover:bg-[#6f7f9a]/10",
                            )}
                            title={
                              allEnabled
                                ? `Disable ${guard.name} in all policies`
                                : `Enable ${guard.name} in all policies`
                            }
                          >
                            {allEnabled ? (
                              <IconToggleRight size={12} />
                            ) : (
                              <IconToggleLeft size={12} />
                            )}
                            <span>{allEnabled ? "On" : "Off"}</span>
                          </button>
                        </div>
                      </div>
                    );
                  })}
              </div>
            );
          })}
        </div>
      </div>

      {/* ---------------------------------------------------------------- */}
      {/* Quick Actions Bar */}
      {/* ---------------------------------------------------------------- */}
      <div className="flex items-center gap-2 px-5 py-3 border-t border-[#2d3240] bg-[#0b0d13]">
        <button
          disabled
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-mono",
            "bg-[#131721] border border-[#2d3240] text-[#6f7f9a]/30 cursor-not-allowed",
          )}
          title="Harden all policies (coming soon)"
        >
          <IconShieldLock size={12} />
          <span>Harden All</span>
        </button>

        <button
          onClick={() => {
            const count = tabs.length;
            if (window.confirm(`Enable all 13 guards across ${count} ${count === 1 ? "policy" : "policies"}? This will mark all policies as unsaved.`)) {
              handleEnableAllGuardsEverywhere();
            }
          }}
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-mono transition-colors",
            "bg-[#131721] border border-[#2d3240] text-[#6f7f9a]",
            "hover:border-[#3dbf84]/40 hover:text-[#3dbf84]",
          )}
          title="Enable all guards across all open policies"
        >
          <IconShieldCheck size={12} />
          <span>Enable All Guards</span>
        </button>

        <button
          disabled
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-mono",
            "bg-[#131721] border border-[#2d3240] text-[#6f7f9a]/30 cursor-not-allowed",
          )}
          title="Compliance audit (coming soon)"
        >
          <IconWand size={12} />
          <span>Compliance Audit</span>
        </button>

        <button
          disabled
          className={cn(
            "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[10px] font-mono",
            "bg-[#131721] border border-[#2d3240] text-[#6f7f9a]/30 cursor-not-allowed",
          )}
          title="Run all tests (coming soon)"
        >
          <IconShieldCheck size={12} />
          <span>Run All Tests</span>
        </button>
      </div>
    </div>
  );
}
