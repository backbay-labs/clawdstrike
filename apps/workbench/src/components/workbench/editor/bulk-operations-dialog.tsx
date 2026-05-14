import { useState, useCallback, useMemo } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { usePolicyTabs } from "@/features/policy/hooks/use-policy-actions";
import type { PolicyTab, BulkGuardUpdate } from "@/features/policy/types/policy-tab";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId, GuardConfigMap } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  IconWand,
  IconCheck,
  IconAlertTriangle,
} from "@tabler/icons-react";


type BulkOperationType = "toggle_guard" | "set_config";

interface BulkOperation {
  type: BulkOperationType;
  guardId: GuardId;
  /** For toggle_guard: the target enabled state */
  enabled?: boolean;
  /** For set_config: the config key and value */
  configKey?: string;
  configValue?: unknown;
}

interface ChangePreview {
  tabId: string;
  tabName: string;
  description: string;
  willChange: boolean;
}


export function useBulkOperations() {
  const [open, setOpen] = useState(false);
  return { open, setOpen };
}


export function BulkOperationsDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { multiDispatch, tabs } = usePolicyTabs();
  const [operation, setOperation] = useState<BulkOperation>({
    type: "toggle_guard",
    guardId: "spider_sense",
    enabled: true,
  });
  const [selectedTabIds, setSelectedTabIds] = useState<Set<string>>(
    () => new Set(tabs.map((t) => t.id)),
  );
  const [applied, setApplied] = useState(false);

  // Reset selection when dialog opens
  const handleOpenChange = useCallback(
    (next: boolean) => {
      if (next) {
        setSelectedTabIds(new Set(tabs.map((t) => t.id)));
        setApplied(false);
      }
      onOpenChange(next);
    },
    [tabs, onOpenChange],
  );

  // ---- Toggle tab selection ----
  const toggleTab = useCallback((tabId: string) => {
    setSelectedTabIds((prev) => {
      const next = new Set(prev);
      if (next.has(tabId)) {
        next.delete(tabId);
      } else {
        next.add(tabId);
      }
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelectedTabIds(new Set(tabs.map((t) => t.id)));
  }, [tabs]);

  const selectNone = useCallback(() => {
    setSelectedTabIds(new Set());
  }, []);

  // ---- Preview changes ----
  const preview: ChangePreview[] = useMemo(() => {
    return tabs.map((tab) => {
      const selected = selectedTabIds.has(tab.id);
      if (!selected) {
        return {
          tabId: tab.id,
          tabName: tab.name,
          description: "Skipped",
          willChange: false,
        };
      }

      if (operation.type === "toggle_guard") {
        const guardConfig = tab.policy.guards[operation.guardId];
        const currentlyEnabled = guardConfig && "enabled" in guardConfig && guardConfig.enabled;
        const targetEnabled = operation.enabled ?? true;

        if (currentlyEnabled === targetEnabled) {
          return {
            tabId: tab.id,
            tabName: tab.name,
            description: `${operation.guardId} already ${targetEnabled ? "enabled" : "disabled"}`,
            willChange: false,
          };
        }

        return {
          tabId: tab.id,
          tabName: tab.name,
          description: `${targetEnabled ? "Enable" : "Disable"} ${operation.guardId}`,
          willChange: true,
        };
      }

      if (operation.type === "set_config" && operation.configKey) {
        const guardConfig = tab.policy.guards[operation.guardId] as Record<string, unknown> | undefined;
        const currentValue = guardConfig?.[operation.configKey];
        const targetValue = operation.configValue;

        if (currentValue === targetValue) {
          return {
            tabId: tab.id,
            tabName: tab.name,
            description: `${operation.guardId}.${operation.configKey} already set`,
            willChange: false,
          };
        }

        return {
          tabId: tab.id,
          tabName: tab.name,
          description: `Set ${operation.guardId}.${operation.configKey} = ${JSON.stringify(targetValue)}`,
          willChange: true,
        };
      }

      return {
        tabId: tab.id,
        tabName: tab.name,
        description: "No change",
        willChange: false,
      };
    });
  }, [tabs, selectedTabIds, operation]);

  const changeCount = preview.filter((p) => p.willChange).length;

  // ---- Apply ----
  const handleApply = useCallback(() => {
    const targetTabs = tabs.filter(
      (t) => selectedTabIds.has(t.id) && preview.find((p) => p.tabId === t.id)?.willChange,
    );

    // Build a single BULK_UPDATE_GUARDS dispatch that applies all guard changes
    // across tabs atomically, avoiding the SWITCH_TAB + TOGGLE_GUARD race (#6).
    const updates: BulkGuardUpdate[] = targetTabs.map((tab) => {
      const update: BulkGuardUpdate = {
        tabId: tab.id,
        guardId: operation.guardId,
        enabled: operation.enabled ?? true,
      };

      if (operation.type === "set_config" && operation.configKey) {
        update.config = {
          [operation.configKey]: operation.configValue,
        };
      }

      return update;
    });

    if (updates.length > 0) {
      multiDispatch({ type: "BULK_UPDATE_GUARDS", updates });
    }

    setApplied(true);
  }, [tabs, selectedTabIds, preview, operation, multiDispatch]);

  // ---- Config presets for set_config mode ----
  const configPresets = useMemo(() => {
    const guard = GUARD_REGISTRY.find((g) => g.id === operation.guardId);
    if (!guard) return [];
    return guard.configFields
      .filter((f) => f.type === "select" || f.type === "toggle")
      .map((f) => ({
        key: f.key,
        label: f.label,
        type: f.type,
        options: f.options,
      }));
  }, [operation.guardId]);

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-lg bg-[#131721] border-[#2d3240] text-[#ece7dc]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-[#ece7dc]">
            <IconWand size={16} className="text-[#d4a84b]" />
            Bulk Operations
          </DialogTitle>
          <DialogDescription className="text-[#6f7f9a]">
            Apply changes across multiple open policies at once.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-4 py-2">
          {/* Operation type */}
          <div className="flex flex-col gap-2">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
              Operation
            </label>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setOperation({ ...operation, type: "toggle_guard" })}
                className={cn(
                  "px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                  operation.type === "toggle_guard"
                    ? "bg-[#d4a84b]/15 text-[#d4a84b] border-[#d4a84b]/30"
                    : "text-[#6f7f9a] border-[#2d3240] hover:border-[#6f7f9a]/40",
                )}
              >
                Toggle Guard
              </button>
              <button
                type="button"
                onClick={() =>
                  setOperation({
                    ...operation,
                    type: "set_config",
                    configKey: configPresets[0]?.key ?? "",
                  })
                }
                className={cn(
                  "px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                  operation.type === "set_config"
                    ? "bg-[#d4a84b]/15 text-[#d4a84b] border-[#d4a84b]/30"
                    : "text-[#6f7f9a] border-[#2d3240] hover:border-[#6f7f9a]/40",
                )}
              >
                Set Config
              </button>
            </div>
          </div>

          {/* Guard selector */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
              Guard
            </label>
            <Select
              value={operation.guardId}
              onValueChange={(val) => {
                setOperation({ ...operation, guardId: val as GuardId });
                setApplied(false);
              }}
            >
              <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-[#131721] border-[#2d3240]">
                {GUARD_REGISTRY.map((g) => (
                  <SelectItem
                    key={g.id}
                    value={g.id}
                    className="text-[11px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                  >
                    {g.name} ({g.id})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Toggle guard: enable/disable */}
          {operation.type === "toggle_guard" && (
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => {
                  setOperation({ ...operation, enabled: true });
                  setApplied(false);
                }}
                className={cn(
                  "px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                  operation.enabled
                    ? "bg-[#3dbf84]/15 text-[#3dbf84] border-[#3dbf84]/30"
                    : "text-[#6f7f9a] border-[#2d3240] hover:border-[#6f7f9a]/40",
                )}
              >
                Enable
              </button>
              <button
                type="button"
                onClick={() => {
                  setOperation({ ...operation, enabled: false });
                  setApplied(false);
                }}
                className={cn(
                  "px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                  operation.enabled === false
                    ? "bg-[#c45c5c]/15 text-[#c45c5c] border-[#c45c5c]/30"
                    : "text-[#6f7f9a] border-[#2d3240] hover:border-[#6f7f9a]/40",
                )}
              >
                Disable
              </button>
            </div>
          )}

          {/* Set config: key + value */}
          {operation.type === "set_config" && (
            <div className="flex flex-col gap-2">
              {configPresets.length > 0 ? (
                <>
                  <Select
                    value={operation.configKey || undefined}
                    onValueChange={(val) => {
                      setOperation({ ...operation, configKey: val as string });
                      setApplied(false);
                    }}
                  >
                    <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono">
                      <SelectValue placeholder="Select config field..." />
                    </SelectTrigger>
                    <SelectContent className="bg-[#131721] border-[#2d3240]">
                      {configPresets.map((p) => (
                        <SelectItem
                          key={p.key}
                          value={p.key}
                          className="text-[11px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                        >
                          {p.label} ({p.key})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  {operation.configKey && (() => {
                    const preset = configPresets.find((p) => p.key === operation.configKey);
                    if (!preset) return null;

                    if (preset.type === "toggle") {
                      return (
                        <div className="flex gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              setOperation({ ...operation, configValue: true });
                              setApplied(false);
                            }}
                            className={cn(
                              "px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                              operation.configValue === true
                                ? "bg-[#3dbf84]/15 text-[#3dbf84] border-[#3dbf84]/30"
                                : "text-[#6f7f9a] border-[#2d3240]",
                            )}
                          >
                            true
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setOperation({ ...operation, configValue: false });
                              setApplied(false);
                            }}
                            className={cn(
                              "px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                              operation.configValue === false
                                ? "bg-[#c45c5c]/15 text-[#c45c5c] border-[#c45c5c]/30"
                                : "text-[#6f7f9a] border-[#2d3240]",
                            )}
                          >
                            false
                          </button>
                        </div>
                      );
                    }

                    if (preset.type === "select" && preset.options) {
                      return (
                        <Select
                          value={operation.configValue ? String(operation.configValue) : undefined}
                          onValueChange={(val) => {
                            setOperation({ ...operation, configValue: val as string });
                            setApplied(false);
                          }}
                        >
                          <SelectTrigger className="h-7 text-xs bg-[#131721] border-[#2d3240] text-[#ece7dc] font-mono">
                            <SelectValue placeholder="Select value..." />
                          </SelectTrigger>
                          <SelectContent className="bg-[#131721] border-[#2d3240]">
                            {preset.options.map((opt) => (
                              <SelectItem
                                key={opt.value}
                                value={opt.value}
                                className="text-[11px] font-mono text-[#ece7dc] focus:bg-[#2d3240] focus:text-[#ece7dc]"
                              >
                                {opt.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      );
                    }

                    return null;
                  })()}
                </>
              ) : (
                <p className="text-[11px] text-[#6f7f9a]/70 font-mono">
                  No configurable presets for this guard.
                </p>
              )}
            </div>
          )}

          {/* Tab selection */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <label className="text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
                Apply to
              </label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={selectAll}
                  className="text-[9px] font-mono text-[#d4a84b] hover:text-[#d4a84b]/80"
                >
                  All
                </button>
                <button
                  type="button"
                  onClick={selectNone}
                  className="text-[9px] font-mono text-[#6f7f9a] hover:text-[#ece7dc]"
                >
                  None
                </button>
              </div>
            </div>

            <div className="flex flex-col gap-1 max-h-[200px] overflow-y-auto">
              {tabs.map((tab) => {
                const p = preview.find((pp) => pp.tabId === tab.id);
                return (
                  <label
                    key={tab.id}
                    className={cn(
                      "flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer transition-colors",
                      selectedTabIds.has(tab.id)
                        ? "bg-[#d4a84b]/5 border border-[#d4a84b]/20"
                        : "border border-transparent hover:bg-[#2d3240]/30",
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={selectedTabIds.has(tab.id)}
                      onChange={() => {
                        toggleTab(tab.id);
                        setApplied(false);
                      }}
                      className="accent-[#d4a84b]"
                    />
                    <span className="flex-1 text-[11px] font-mono truncate">
                      {tab.name}
                      {tab.dirty && <span className="text-[#d4a84b] ml-1">*</span>}
                    </span>
                    {p && (
                      <span
                        className={cn(
                          "text-[9px] font-mono shrink-0",
                          p.willChange ? "text-[#d4a84b]" : "text-[#6f7f9a]/50",
                        )}
                      >
                        {p.willChange ? p.description : "no change"}
                      </span>
                    )}
                  </label>
                );
              })}
            </div>
          </div>
        </div>

        <DialogFooter className="bg-[#0b0d13] border-[#2d3240]">
          {applied ? (
            <div className="flex items-center gap-2 text-[11px] font-mono text-[#3dbf84]">
              <IconCheck size={14} />
              Applied to {changeCount} {changeCount === 1 ? "policy" : "policies"}
            </div>
          ) : changeCount > 0 ? (
            <Button
              onClick={handleApply}
              className="bg-[#d4a84b] text-[#05060a] hover:bg-[#d4a84b]/90 text-[11px] font-mono"
            >
              <IconWand size={13} className="mr-1.5" />
              Apply to {changeCount} {changeCount === 1 ? "policy" : "policies"}
            </Button>
          ) : (
            <div className="flex items-center gap-2 text-[11px] font-mono text-[#6f7f9a]/50">
              <IconAlertTriangle size={14} />
              No changes to apply
            </div>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
