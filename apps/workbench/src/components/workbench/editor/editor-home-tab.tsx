import { useCallback, useMemo, useRef } from "react";
import { useMultiPolicy, useWorkbench } from "@/lib/workbench/multi-policy-store";
import type { PolicyTab } from "@/lib/workbench/multi-policy-store";
import { getRecentFiles } from "@/lib/workbench/policy-store";
import { isDesktop } from "@/lib/tauri-bridge";
import { cn } from "@/lib/utils";
import {
  IconPlus,
  IconFolderOpen,
  IconTemplate,
  IconX,
  IconFileText,
  IconShieldCheck,
  IconArrowRight,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Template definitions
// ---------------------------------------------------------------------------

interface TemplateEntry {
  name: string;
  description: string;
}

const TEMPLATES: TemplateEntry[] = [
  { name: "strict", description: "Maximum security \u2014 blocks most operations by default" },
  { name: "permissive", description: "Minimal restrictions \u2014 allows most operations" },
  { name: "default", description: "Balanced security for general use" },
  { name: "ai-agent", description: "Tailored for AI agent tool boundaries" },
  { name: "cicd", description: "Optimized for CI/CD pipeline security" },
  { name: "ai-agent-posture", description: "Posture-aware AI agent enforcement" },
  { name: "remote-desktop", description: "Controls for remote desktop/CUA sessions" },
  { name: "spider-sense", description: "Hierarchical threat screening with pattern matching" },
];

// ---------------------------------------------------------------------------
// EditorHomeTab
// ---------------------------------------------------------------------------

export function EditorHomeTab({
  onNavigateToTab,
}: {
  onNavigateToTab: () => void;
}) {
  const { tabs, multiDispatch, multiState, canAddTab } = useMultiPolicy();
  const { openFile, openFileByPath } = useWorkbench();
  const templatesRef = useRef<HTMLDivElement>(null);
  const desktop = isDesktop();
  const recentFiles = useMemo(
    () => (desktop ? getRecentFiles() : []),
    [desktop, tabs.length],
  );

  // ---- Handlers ----

  const handleSwitchToTab = useCallback(
    (tabId: string) => {
      multiDispatch({ type: "SWITCH_TAB", tabId });
      onNavigateToTab();
    },
    [multiDispatch, onNavigateToTab],
  );

  const handleCloseTab = useCallback(
    (tabId: string) => {
      const tab = tabs.find((t) => t.id === tabId);
      if (tab?.dirty) {
        const confirmed = window.confirm(
          `"${tab.name}" has unsaved changes. Close anyway?`,
        );
        if (!confirmed) return;
      }
      multiDispatch({ type: "CLOSE_TAB", tabId });
    },
    [tabs, multiDispatch],
  );

  const handleNewPolicy = useCallback(() => {
    multiDispatch({ type: "NEW_TAB" });
    onNavigateToTab();
  }, [multiDispatch, onNavigateToTab]);

  const handleOpenFile = useCallback(async () => {
    await openFile();
    onNavigateToTab();
  }, [openFile, onNavigateToTab]);

  const handleOpenRecentFile = useCallback(
    async (filePath: string) => {
      await openFileByPath(filePath);
      onNavigateToTab();
    },
    [openFileByPath, onNavigateToTab],
  );

  const handleLoadTemplate = useCallback(
    (template: TemplateEntry) => {
      if (!canAddTab) return;
      multiDispatch({
        type: "NEW_TAB",
        policy: {
          version: "1.2.0",
          name: `my-${template.name}-policy`,
          description: "",
          extends: template.name,
          guards: {},
          settings: { fail_fast: false, verbose_logging: false, session_timeout_secs: 3600 },
        },
      });
      onNavigateToTab();
    },
    [canAddTab, multiDispatch, onNavigateToTab],
  );

  const handleScrollToTemplates = useCallback(() => {
    templatesRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  // ---- Guard count helper ----
  function guardCount(tab: PolicyTab): number {
    return Object.keys(tab.policy.guards).filter(
      (k) => (tab.policy.guards as Record<string, { enabled?: boolean }>)[k]?.enabled === true,
    ).length;
  }

  function fileName(path: string): string {
    const parts = path.replace(/\\/g, "/").split("/");
    return parts[parts.length - 1] || path;
  }

  return (
    <div className="h-full overflow-y-auto bg-[#05060a]">
      <div className="max-w-5xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="font-syne font-bold text-lg text-[#ece7dc] mb-1 flex items-center gap-2">
            <IconShieldCheck size={20} stroke={1.5} className="text-[#d4a84b]" />
            Policy Workspace
          </h1>
          <p className="text-xs text-[#6f7f9a] font-mono">
            Manage open policies, browse templates, and open recent files.
          </p>
        </div>

        {/* Three-column grid: Open Tabs, Recent Files, Templates */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-8">
          {/* Open Tabs */}
          <section>
            <h2 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
              Open Tabs
            </h2>
            <div className="space-y-1.5">
              {tabs.map((tab) => {
                const isActive = tab.id === multiState.activeTabId;
                const guards = guardCount(tab);
                const hasErrors = !tab.validation.valid;
                return (
                  <div
                    key={tab.id}
                    onClick={() => handleSwitchToTab(tab.id)}
                    className={cn(
                      "group relative flex items-center gap-2 px-3 py-2 rounded cursor-pointer transition-all",
                      "bg-[#131721] border",
                      isActive
                        ? "border-[#d4a84b] text-[#ece7dc]"
                        : "border-[#2d3240] text-[#ece7dc]/80 hover:border-[#d4a84b]/30",
                    )}
                  >
                    {/* Dirty indicator */}
                    {tab.dirty && (
                      <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b] shrink-0" />
                    )}

                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-mono truncate">
                        {tab.name || "Untitled"}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[9px] text-[#6f7f9a] font-mono">
                          {guards} guard{guards !== 1 ? "s" : ""}
                        </span>
                        {hasErrors && (
                          <span className="text-[9px] text-[#c45c5c] font-mono">
                            errors
                          </span>
                        )}
                        {tab.filePath && (
                          <span className="text-[9px] text-[#6f7f9a]/60 font-mono truncate max-w-[120px]">
                            {fileName(tab.filePath)}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Close button */}
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCloseTab(tab.id);
                      }}
                      className="shrink-0 p-0.5 rounded opacity-0 group-hover:opacity-100 hover:bg-[#c45c5c]/20 hover:text-[#c45c5c] transition-all"
                      title="Close tab"
                    >
                      <IconX size={11} stroke={1.5} />
                    </button>
                  </div>
                );
              })}
              {tabs.length === 0 && (
                <div className="text-[10px] text-[#6f7f9a]/50 font-mono px-3 py-4 text-center">
                  No open tabs
                </div>
              )}
            </div>
          </section>

          {/* Recent Files */}
          {desktop && (
            <section>
              <h2 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                Recent Files
              </h2>
              <div className="space-y-1.5">
                {recentFiles.length > 0 ? (
                  recentFiles.map((filePath) => (
                    <div
                      key={filePath}
                      onClick={() => handleOpenRecentFile(filePath)}
                      className="group flex items-center gap-2 px-3 py-2 rounded cursor-pointer transition-all bg-[#131721] border border-[#2d3240] hover:border-[#d4a84b]/30"
                    >
                      <IconFileText size={13} stroke={1.5} className="text-[#6f7f9a] shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-[11px] font-mono text-[#ece7dc] truncate">
                          {fileName(filePath)}
                        </div>
                        <div className="text-[9px] text-[#6f7f9a]/60 font-mono truncate">
                          {filePath}
                        </div>
                      </div>
                      <IconArrowRight
                        size={11}
                        stroke={1.5}
                        className="text-[#6f7f9a]/0 group-hover:text-[#6f7f9a] transition-colors shrink-0"
                      />
                    </div>
                  ))
                ) : (
                  <div className="text-[10px] text-[#6f7f9a]/50 font-mono px-3 py-4 text-center">
                    No recent files
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Templates */}
          <section ref={templatesRef}>
            <h2 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
              Templates
            </h2>
            <div className="space-y-1.5">
              {TEMPLATES.map((template) => (
                <button
                  key={template.name}
                  type="button"
                  onClick={() => handleLoadTemplate(template)}
                  disabled={!canAddTab}
                  className={cn(
                    "group flex w-full items-center gap-2 px-3 py-2 rounded text-left transition-all bg-[#131721] border border-[#2d3240] hover:border-[#d4a84b]/30",
                    canAddTab ? "cursor-pointer" : "opacity-40 cursor-not-allowed",
                  )}
                >
                  <IconTemplate size={13} stroke={1.5} className="text-[#d4a84b]/60 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-[11px] font-mono text-[#ece7dc]">
                      {template.name}
                    </div>
                    <div className="text-[9px] text-[#6f7f9a] font-mono leading-snug">
                      {template.description}
                    </div>
                  </div>
                  <IconArrowRight
                    size={11}
                    stroke={1.5}
                    className="text-[#6f7f9a]/0 group-hover:text-[#6f7f9a] transition-colors shrink-0"
                  />
                </button>
              ))}
            </div>
          </section>
        </div>

        {/* Quick Actions */}
        <section>
          <h2 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
            Quick Actions
          </h2>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              type="button"
              onClick={handleNewPolicy}
              disabled={!canAddTab}
              className={cn(
                "inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono rounded border transition-colors",
                canAddTab
                  ? "text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]"
                  : "text-[#6f7f9a]/30 border-[#2d3240]/30 bg-[#131721]/50 cursor-not-allowed",
              )}
            >
              <IconPlus size={12} stroke={1.5} />
              New Policy
            </button>

            {desktop && (
              <button
                type="button"
                onClick={handleOpenFile}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono rounded border text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b] transition-colors"
              >
                <IconFolderOpen size={12} stroke={1.5} />
                Open File
              </button>
            )}

            <button
              type="button"
              onClick={handleScrollToTemplates}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-mono rounded border text-[#ece7dc] border-[#2d3240] bg-[#131721] hover:border-[#d4a84b]/40 hover:text-[#d4a84b] transition-colors"
            >
              <IconTemplate size={12} stroke={1.5} />
              From Template
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}
