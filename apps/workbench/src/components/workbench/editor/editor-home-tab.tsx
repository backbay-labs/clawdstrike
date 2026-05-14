import { useCallback, useMemo } from "react";
import { motion } from "motion/react";
import { usePolicyTabsStore, pushRecentFile, type TabMeta } from "@/features/policy/stores/policy-tabs-store";
import { usePolicyEditStore } from "@/features/policy/stores/policy-edit-store";
import { getRecentFiles } from "@/features/policy/stores/policy-store";
import {
  FILE_TYPE_REGISTRY,
  type FileType,
} from "@/lib/workbench/file-type-registry";
import { SIGMA_TEMPLATES } from "@/lib/workbench/sigma-templates";
import type { SigmaTemplate } from "@/lib/workbench/sigma-templates";
import { YARA_TEMPLATES } from "@/lib/workbench/yara-templates";
import type { YaraTemplate } from "@/lib/workbench/yara-templates";
import { isDesktop, openDetectionFile, readDetectionFileByPath } from "@/lib/tauri-bridge";
import { cn } from "@/lib/utils";
import {
  IconArrowRight,
  IconFileText,
  IconFolderOpen,
  IconPlus,
  IconX,
  IconShieldLock,
  IconRadar2,
  IconBug,
  IconSchema,
  IconHexagons,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface TemplateEntry {
  name: string;
  description: string;
  hint: string;
}

const TEMPLATES: TemplateEntry[] = [
  { name: "ai-agent", description: "Tailored for LLM tool boundaries", hint: "Agent tool policies" },
  { name: "strict", description: "Maximum restriction with conservative defaults", hint: "High-security posture" },
  { name: "default", description: "Balanced protection with sensible defaults", hint: "General-purpose baseline" },
  { name: "permissive", description: "Minimal restrictions for development and tests", hint: "Fast iteration" },
  { name: "cicd", description: "Optimized for CI/CD pipeline security", hint: "Build systems" },
  { name: "ai-agent-posture", description: "Posture-aware AI agent enforcement", hint: "Multi-tenant fleets" },
  { name: "remote-desktop", description: "Controls for remote desktop and CUA sessions", hint: "Computer use" },
  { name: "spider-sense", description: "Hierarchical threat screening with pattern matching", hint: "Threat screening" },
];

function fileName(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || path;
}

function guardCount(tab: TabMeta, editStates: Map<string, import("@/features/policy/stores/policy-edit-store").TabEditState>): number {
  if (tab.fileType !== "clawdstrike_policy") return 0;
  const editState = editStates.get(tab.id);
  if (!editState) return 0;
  return Object.keys(editState.policy.guards).filter(
    (key) =>
      (editState.policy.guards as Record<string, { enabled?: boolean }>)[key]?.enabled === true,
  ).length;
}

function tabStatus(tab: TabMeta, editStates: Map<string, import("@/features/policy/stores/policy-edit-store").TabEditState>): string {
  const editState = editStates.get(tab.id);
  if (editState && !editState.validation.valid) {
    const issueCount = editState.validation.errors.length;
    return `${issueCount} issue${issueCount === 1 ? "" : "s"}`;
  }
  switch (tab.fileType) {
    case "clawdstrike_policy": {
      const guards = guardCount(tab, editStates);
      return `${guards} guard${guards === 1 ? "" : "s"}`;
    }
    case "sigma_rule":
      return "replay ready";
    case "yara_rule":
      return "scan ready";
    case "ocsf_event":
      return "schema ready";
    default:
      return "ready";
  }
}

const FORMAT_ICONS: Record<FileType, typeof IconShieldLock> = {
  clawdstrike_policy: IconShieldLock,
  sigma_rule: IconRadar2,
  yara_rule: IconBug,
  ocsf_event: IconSchema,
  swarm_bundle: IconHexagons,
  receipt: IconFileText,
};

// ---------------------------------------------------------------------------
// Open document row
// ---------------------------------------------------------------------------

function DocumentRow({
  tab,
  editStates,
  isActive,
  onSwitch,
  onClose,
  delay,
}: {
  tab: TabMeta;
  editStates: Map<string, import("@/features/policy/stores/policy-edit-store").TabEditState>;
  isActive: boolean;
  onSwitch: () => void;
  onClose: () => void;
  delay: number;
}) {
  const desc = FILE_TYPE_REGISTRY[tab.fileType];
  const Icon = FORMAT_ICONS[tab.fileType] ?? IconFileText;

  return (
    <motion.div
      className={cn(
        "group flex items-center gap-3 px-3 py-2.5 rounded transition-all cursor-pointer",
        isActive
          ? "bg-[#131721] border-l-2"
          : "hover:bg-[#0e1118] border-l-2 border-transparent",
      )}
      style={isActive ? { borderLeftColor: desc.iconColor } : undefined}
      onClick={onSwitch}
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: delay * 0.04, duration: 0.25 }}
    >
      <Icon
        size={14}
        stroke={1.5}
        className="shrink-0"
        style={{ color: desc.iconColor }}
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className={cn(
            "text-[12px] truncate",
            isActive ? "text-[#ece7dc] font-medium" : "text-[#ece7dc]/70",
          )}>
            {tab.name || "Untitled"}
          </span>
          {tab.dirty && (
            <span className="w-1.5 h-1.5 rounded-full bg-[#d4a84b] shrink-0" />
          )}
        </div>
        <div className="text-[9px] font-mono text-[#6f7f9a]/60 mt-0.5 flex items-center gap-1.5">
          <span style={{ color: `${desc.iconColor}80` }}>{desc.shortLabel}</span>
          <span>&middot;</span>
          <span>{tabStatus(tab, editStates)}</span>
          {tab.filePath && (
            <>
              <span>&middot;</span>
              <span className="truncate">{fileName(tab.filePath)}</span>
            </>
          )}
        </div>
      </div>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onClose(); }}
        className="opacity-0 group-hover:opacity-100 rounded p-0.5 text-[#6f7f9a]/40 hover:text-[#c45c5c] transition-all"
        title="Close"
      >
        <IconX size={11} stroke={1.5} />
      </button>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Create format card
// ---------------------------------------------------------------------------

function FormatCard({
  fileType,
  label,
  note,
  disabled,
  onClick,
  delay,
}: {
  fileType: FileType;
  label: string;
  note: string;
  disabled: boolean;
  onClick: () => void;
  delay: number;
}) {
  const desc = FILE_TYPE_REGISTRY[fileType];
  const Icon = FORMAT_ICONS[fileType] ?? IconFileText;

  return (
    <motion.button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "group relative flex items-center gap-3 px-3 py-3 rounded border transition-all text-left overflow-hidden",
        disabled
          ? "cursor-not-allowed opacity-40 border-[#1a1d28] bg-[#0a0c12]"
          : "border-[#1a1d28] bg-[#0a0c12]/60 hover:bg-[#0e1018] hover:border-[#2d3240]",
      )}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: delay * 0.05 + 0.2, duration: 0.25 }}
    >
      {/* Left accent strip */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[2px] transition-all group-hover:w-[3px]"
        style={{ backgroundColor: disabled ? "#1a1d28" : desc.iconColor }}
      />
      <Icon
        size={16}
        stroke={1.5}
        className="shrink-0 ml-1 transition-colors"
        style={{ color: disabled ? "#6f7f9a40" : desc.iconColor }}
      />
      <div className="min-w-0 flex-1">
        <div className="text-[11px] font-medium text-[#ece7dc]">{label}</div>
        <div className="text-[9px] font-mono text-[#6f7f9a]/50 mt-0.5">{note}</div>
      </div>
      <IconPlus
        size={11}
        stroke={1.5}
        className="shrink-0 text-[#6f7f9a]/20 group-hover:text-[#6f7f9a]/60 transition-colors"
      />
    </motion.button>
  );
}

// ---------------------------------------------------------------------------
// Template row
// ---------------------------------------------------------------------------

function TemplateRow({
  name,
  hint,
  color,
  disabled,
  onClick,
}: {
  name: string;
  hint: string;
  color: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "group flex items-center gap-2.5 w-full px-2 py-2 rounded text-left transition-all",
        disabled
          ? "cursor-not-allowed opacity-40"
          : "hover:bg-[#0e1018]",
      )}
    >
      <span
        className="w-1 h-1 rounded-full shrink-0"
        style={{ backgroundColor: color }}
      />
      <div className="min-w-0 flex-1">
        <span className="text-[11px] text-[#ece7dc]/80">{name}</span>
      </div>
      <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-wider shrink-0">
        {hint}
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Editor Home Tab
// ---------------------------------------------------------------------------

export function EditorHomeTab({
  onNavigateToTab,
}: {
  onNavigateToTab: () => void;
}) {
  const tabs = usePolicyTabsStore(s => s.tabs);
  const activeTabId = usePolicyTabsStore(s => s.activeTabId);
  const editStates = usePolicyEditStore(s => s.editStates);
  const canAddTab = tabs.length < 25;
  const desktop = isDesktop();
  const recentFiles = useMemo(
    () => (desktop ? getRecentFiles() : []),
    [desktop, tabs.length],
  );

  const activeTab = useMemo(
    () => tabs.find((tab) => tab.id === activeTabId) ?? tabs[0] ?? null,
    [tabs, activeTabId],
  );

  const visibleRecentFiles = recentFiles.slice(0, 6);

  const handleSwitchToTab = useCallback(
    (tabId: string) => {
      usePolicyTabsStore.getState().switchTab(tabId);
      onNavigateToTab();
    },
    [onNavigateToTab],
  );

  const handleCloseTab = useCallback(
    (tabId: string) => {
      const tab = tabs.find((entry) => entry.id === tabId);
      if (tab?.dirty) {
        const confirmed = window.confirm(`"${tab.name}" has unsaved changes. Close anyway?`);
        if (!confirmed) return;
      }
      usePolicyTabsStore.getState().closeTab(tabId);
    },
    [tabs],
  );

  const handleCreateFile = useCallback(
    (fileType: FileType) => {
      if (!canAddTab) return;
      usePolicyTabsStore.getState().newTab({ fileType });
      onNavigateToTab();
    },
    [canAddTab, onNavigateToTab],
  );

  const handleOpenFile = useCallback(async () => {
    try {
      const result = await openDetectionFile();
      if (!result) return;
      usePolicyTabsStore.getState().openTabOrSwitch(
        result.path,
        result.fileType,
        result.content,
      );
      pushRecentFile(result.path);
      onNavigateToTab();
    } catch (err) {
      console.error("[editor-home-tab] Failed to open file:", err);
    }
  }, [onNavigateToTab]);

  const handleOpenRecentFile = useCallback(
    async (filePath: string) => {
      try {
        const result = await readDetectionFileByPath(filePath);
        if (!result) return;
        usePolicyTabsStore.getState().openTabOrSwitch(
          result.path,
          result.fileType,
          result.content,
        );
        pushRecentFile(result.path);
        onNavigateToTab();
      } catch (err) {
        console.error("[editor-home-tab] Failed to open file by path:", err);
      }
    },
    [onNavigateToTab],
  );

  const handleLoadTemplate = useCallback(
    (template: TemplateEntry) => {
      if (!canAddTab) return;
      usePolicyTabsStore.getState().newTab({
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
    [canAddTab, onNavigateToTab],
  );

  const handleLoadSigmaTemplate = useCallback(
    (template: SigmaTemplate) => {
      if (!canAddTab) return;
      usePolicyTabsStore.getState().newTab({ fileType: "sigma_rule", yaml: template.content });
      onNavigateToTab();
    },
    [canAddTab, onNavigateToTab],
  );

  const handleLoadYaraTemplate = useCallback(
    (template: YaraTemplate) => {
      if (!canAddTab) return;
      usePolicyTabsStore.getState().newTab({ fileType: "yara_rule", yaml: template.content });
      onNavigateToTab();
    },
    [canAddTab, onNavigateToTab],
  );

  const featuredSigmaTemplate = SIGMA_TEMPLATES[0] ?? null;
  const featuredYaraTemplate = YARA_TEMPLATES[0] ?? null;

  // Count open tabs by format
  const formatCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const tab of tabs) {
      counts[tab.fileType] = (counts[tab.fileType] ?? 0) + 1;
    }
    return counts;
  }, [tabs]);

  const dirtyCount = tabs.filter((t) => t.dirty).length;

  return (
    <div className="h-full overflow-auto bg-[#05060a]">
      <div className="w-full px-8 py-6 flex flex-col gap-6 max-w-7xl">

        {/* ================================================================ */}
        {/* Header -- compact workstation briefing                           */}
        {/* ================================================================ */}
        <motion.div
          className="flex items-center justify-between gap-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <div>
            <div className="flex items-center gap-3">
              <h1 className="font-syne text-lg font-bold text-[#ece7dc] tracking-tight">
                Workspace
              </h1>
              {/* Format tally */}
              <div className="flex items-center gap-1.5">
                {Object.entries(formatCounts).map(([ft, count]) => {
                  const desc = FILE_TYPE_REGISTRY[ft as FileType];
                  return (
                    <span
                      key={ft}
                      className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[8px] font-mono"
                      style={{
                        backgroundColor: `${desc.iconColor}10`,
                        color: `${desc.iconColor}aa`,
                      }}
                    >
                      <span
                        className="w-1 h-1 rounded-full"
                        style={{ backgroundColor: desc.iconColor }}
                      />
                      {count}
                    </span>
                  );
                })}
                {dirtyCount > 0 && (
                  <span className="text-[8px] font-mono text-[#d4a84b]/60">
                    {dirtyCount} unsaved
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {desktop && (
              <button
                type="button"
                onClick={handleOpenFile}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-mono text-[#6f7f9a] hover:text-[#ece7dc] border border-[#1a1d28] hover:border-[#2d3240] rounded transition-colors"
              >
                <IconFolderOpen size={12} stroke={1.5} />
                Open
              </button>
            )}
          </div>
        </motion.div>

        {/* ================================================================ */}
        {/* Main grid -- documents left, create/templates right              */}
        {/* ================================================================ */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_300px] gap-4 min-h-0">

          {/* ---- Left: Open documents ---- */}
          <div className="flex flex-col gap-1">
            <div className="flex items-center justify-between px-1 mb-1">
              <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-[0.2em]">
                Open Documents
              </span>
              <span className="text-[8px] font-mono text-[#6f7f9a]/30">
                {tabs.length} / 25
              </span>
            </div>

            {tabs.length === 0 ? (
              <div className="flex items-center justify-center py-12 text-[11px] text-[#6f7f9a]/40 font-mono">
                No open files. Create or open something to get started.
              </div>
            ) : (
              <div className="space-y-0.5">
                {tabs.map((tab, i) => (
                  <DocumentRow
                    key={tab.id}
                    tab={tab}
                    editStates={editStates}
                    isActive={tab.id === activeTab?.id}
                    onSwitch={() => handleSwitchToTab(tab.id)}
                    onClose={() => handleCloseTab(tab.id)}
                    delay={i}
                  />
                ))}
              </div>
            )}

            {/* ---- Recent files ---- */}
            {desktop && visibleRecentFiles.length > 0 && (
              <div className="mt-4">
                <div className="px-1 mb-2">
                  <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-[0.2em]">
                    Recent Files
                  </span>
                </div>
                <div className="space-y-0.5">
                  {visibleRecentFiles.map((filePath, i) => (
                    <motion.button
                      key={filePath}
                      type="button"
                      onClick={() => { void handleOpenRecentFile(filePath); }}
                      className="group flex items-center gap-2.5 w-full px-3 py-2 rounded text-left hover:bg-[#0e1118] transition-colors"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.3 + i * 0.03 }}
                    >
                      <IconFileText size={12} stroke={1.5} className="shrink-0 text-[#6f7f9a]/30" />
                      <div className="min-w-0 flex-1">
                        <div className="text-[11px] text-[#ece7dc]/60 truncate group-hover:text-[#ece7dc]/80 transition-colors">
                          {fileName(filePath)}
                        </div>
                        <div className="text-[8px] font-mono text-[#6f7f9a]/30 truncate mt-0.5">
                          {filePath}
                        </div>
                      </div>
                      <IconArrowRight size={10} stroke={1.5} className="shrink-0 text-[#6f7f9a]/0 group-hover:text-[#6f7f9a]/30 transition-colors" />
                    </motion.button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ---- Right: Create + Templates ---- */}
          <div className="flex flex-col gap-4">
            {/* Create new */}
            <div>
              <div className="px-1 mb-2">
                <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-[0.2em]">
                  New Document
                </span>
              </div>
              <div className="grid grid-cols-1 gap-1.5">
                <FormatCard
                  fileType="clawdstrike_policy"
                  label="Policy"
                  note="Guardrails & runtime controls"
                  disabled={!canAddTab}
                  onClick={() => handleCreateFile("clawdstrike_policy")}
                  delay={0}
                />
                <FormatCard
                  fileType="sigma_rule"
                  label="Sigma Rule"
                  note="Portable detection logic"
                  disabled={!canAddTab}
                  onClick={() => handleCreateFile("sigma_rule")}
                  delay={1}
                />
                <FormatCard
                  fileType="yara_rule"
                  label="YARA Rule"
                  note="Artifact & pattern scanning"
                  disabled={!canAddTab}
                  onClick={() => handleCreateFile("yara_rule")}
                  delay={2}
                />
                <FormatCard
                  fileType="ocsf_event"
                  label="OCSF Event"
                  note="Normalized telemetry"
                  disabled={!canAddTab}
                  onClick={() => handleCreateFile("ocsf_event")}
                  delay={3}
                />
              </div>
            </div>

            {/* Templates */}
            <div>
              <div className="px-1 mb-1.5">
                <span className="text-[8px] font-mono text-[#6f7f9a]/40 uppercase tracking-[0.2em]">
                  Starter Kits
                </span>
              </div>
              <div className="space-y-0">
                {TEMPLATES.slice(0, 5).map((template) => (
                  <TemplateRow
                    key={template.name}
                    name={template.name}
                    hint={template.hint}
                    color="#d4a84b"
                    disabled={!canAddTab}
                    onClick={() => handleLoadTemplate(template)}
                  />
                ))}
                {featuredSigmaTemplate && (
                  <TemplateRow
                    name={featuredSigmaTemplate.name}
                    hint="Sigma starter"
                    color="#7c9aef"
                    disabled={!canAddTab}
                    onClick={() => handleLoadSigmaTemplate(featuredSigmaTemplate)}
                  />
                )}
                {featuredYaraTemplate && (
                  <TemplateRow
                    name={featuredYaraTemplate.name}
                    hint="YARA starter"
                    color="#e0915c"
                    disabled={!canAddTab}
                    onClick={() => handleLoadYaraTemplate(featuredYaraTemplate)}
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
