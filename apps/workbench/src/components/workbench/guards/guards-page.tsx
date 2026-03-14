import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { GUARD_REGISTRY, GUARD_CATEGORIES } from "@/lib/workbench/guard-registry";
import type { GuardMeta, GuardCategory, GuardId } from "@/lib/workbench/types";
import { useToast } from "@/components/ui/toast";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
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
  IconFingerprint,
  IconLayoutGrid,
  IconList,
  IconSearch,
  IconX,
  IconChevronRight,
  IconShield,
  IconSettings,
  IconTestPipe,
  IconArrowRight,
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
  IconFingerprint,
};

function resolveIcon(iconName: string): typeof IconLock {
  return ICON_MAP[iconName] ?? IconShield;
}


const CATEGORY_COLORS: Record<GuardCategory, string> = {
  filesystem: "#8b7355",
  network: "#557b8b",
  content: "#6b7b55",
  tools: "#7b6b8b",
  detection: "#8b5555",
  cua: "#5b7b7b",
};

const CATEGORY_LABELS: Record<GuardCategory, string> = {
  filesystem: "Filesystem",
  network: "Network",
  content: "Content",
  tools: "Tools",
  detection: "Detection",
  cua: "CUA",
};

const CATEGORY_THREAT_MAP: Record<GuardCategory, string[]> = {
  filesystem: [
    "Path traversal",
    "Sensitive data exfiltration",
    "Unauthorized file access",
    "SSH key theft",
    "Credential file access",
  ],
  network: [
    "Data exfiltration via network",
    "C2 callback / reverse shell",
    "DNS tunneling",
    "Unauthorized API calls",
    "DNS rebinding",
  ],
  content: [
    "Secret leakage in outputs",
    "Malicious code injection via patches",
    "API key / token exposure",
    "Credential disclosure",
  ],
  tools: [
    "Arbitrary command execution",
    "Privilege escalation via shell",
    "Malicious MCP tool invocation",
    "Argument injection",
  ],
  detection: [
    "Prompt injection attacks",
    "Jailbreak attempts",
    "Social engineering via prompts",
    "Behavioral anomaly evasion",
    "Instruction hierarchy bypass",
  ],
  cua: [
    "Remote desktop hijacking",
    "Clipboard data theft",
    "Keystroke injection",
    "Side-channel data exfiltration",
    "Unauthorized input automation",
  ],
};


type CategoryFilter = "all" | GuardCategory;

const FILTER_OPTIONS: { id: CategoryFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "filesystem", label: "Filesystem" },
  { id: "network", label: "Network" },
  { id: "content", label: "Content" },
  { id: "tools", label: "Tools" },
  { id: "detection", label: "Detection" },
  { id: "cua", label: "CUA" },
];


function CategoryBadge({ category }: { category: GuardCategory }) {
  const color = CATEGORY_COLORS[category];
  return (
    <span
      className="px-1.5 py-0.5 rounded text-[9px] font-medium uppercase tracking-wider"
      style={{ backgroundColor: `${color}20`, color }}
    >
      {CATEGORY_LABELS[category]}
    </span>
  );
}


function GuardGridCard({
  guard,
  isActive,
  isSelected,
  onSelect,
}: {
  guard: GuardMeta;
  isActive: boolean;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const Icon = resolveIcon(guard.icon);
  const configCount = guard.configFields.filter((f) => f.key !== "enabled").length;

  return (
    <button
      onClick={onSelect}
      className={cn(
        "relative text-left rounded-xl border p-4 transition-all duration-150 group",
        "hover:shadow-[0_0_16px_rgba(212,168,75,0.06)]",
        isSelected
          ? "bg-[#131721] border-[#d4a84b]/40 shadow-[0_0_16px_rgba(212,168,75,0.08)]"
          : "bg-[#131721] border-[#2d3240] hover:border-[#2d3240]/80",
      )}
    >
      {/* Active dot */}
      <span
        className={cn(
          "absolute top-3 right-3 h-2 w-2 rounded-full",
          isActive ? "bg-[#3dbf84]" : "bg-[#2d3240]",
        )}
        title={isActive ? "Active in current policy" : "Inactive in current policy"}
      />

      {/* Header */}
      <div className="flex items-start gap-3 mb-3">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
          style={{ backgroundColor: `${CATEGORY_COLORS[guard.category]}15` }}
        >
          <Icon
            size={18}
            stroke={1.5}
            style={{ color: CATEGORY_COLORS[guard.category] }}
          />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="text-[13px] font-semibold text-[#ece7dc] truncate leading-tight">
            {guard.name}
          </h3>
          <div className="flex items-center gap-1.5 mt-1">
            <CategoryBadge category={guard.category} />
            <VerdictBadge verdict={guard.defaultVerdict} className="text-[9px]" />
          </div>
        </div>
      </div>

      {/* Description */}
      <p className="text-[11px] text-[#6f7f9a] leading-relaxed line-clamp-2 mb-3">
        {guard.description}
      </p>

      {/* Footer */}
      <div className="flex items-center justify-between">
        <span className="text-[10px] text-[#6f7f9a]/60">
          {configCount} configurable field{configCount !== 1 ? "s" : ""}
        </span>
        <IconChevronRight
          size={13}
          stroke={1.5}
          className={cn(
            "text-[#6f7f9a]/40 transition-all duration-150",
            "group-hover:text-[#d4a84b] group-hover:translate-x-0.5",
          )}
        />
      </div>
    </button>
  );
}


function GuardListRow({
  guard,
  isActive,
  isSelected,
  onSelect,
}: {
  guard: GuardMeta;
  isActive: boolean;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const Icon = resolveIcon(guard.icon);

  return (
    <button
      onClick={onSelect}
      className={cn(
        "w-full text-left flex items-center gap-3 px-4 py-2.5 rounded-lg border transition-all duration-150 group",
        isSelected
          ? "bg-[#131721] border-[#d4a84b]/40"
          : "bg-[#131721]/50 border-transparent hover:bg-[#131721] hover:border-[#2d3240]",
      )}
    >
      {/* Active dot */}
      <span
        className={cn(
          "h-2 w-2 rounded-full shrink-0",
          isActive ? "bg-[#3dbf84]" : "bg-[#2d3240]",
        )}
      />

      {/* Icon */}
      <Icon
        size={16}
        stroke={1.5}
        className="shrink-0"
        style={{ color: CATEGORY_COLORS[guard.category] }}
      />

      {/* Name */}
      <span className="text-[12.5px] font-medium text-[#ece7dc] w-44 shrink-0 truncate">
        {guard.name}
      </span>

      {/* Category */}
      <CategoryBadge category={guard.category} />

      {/* Verdict */}
      <VerdictBadge verdict={guard.defaultVerdict} className="text-[9px]" />

      {/* Description */}
      <span className="text-[11px] text-[#6f7f9a] truncate flex-1 min-w-0">
        {guard.description}
      </span>

      <IconChevronRight
        size={13}
        stroke={1.5}
        className="shrink-0 text-[#6f7f9a]/40 group-hover:text-[#d4a84b] transition-colors"
      />
    </button>
  );
}


function GuardDetailPanel({
  guard,
  isActive,
  onClose,
  onToggle,
  onNavigateToEditor,
  onGenerateTests,
  currentConfig,
}: {
  guard: GuardMeta;
  isActive: boolean;
  onClose: () => void;
  onToggle: () => void;
  onNavigateToEditor: () => void;
  onGenerateTests: () => void;
  currentConfig: Record<string, unknown> | undefined;
}) {
  const Icon = resolveIcon(guard.icon);
  const threats = CATEGORY_THREAT_MAP[guard.category];
  const nonEnabledFields = guard.configFields.filter((f) => f.key !== "enabled");

  return (
    <div className="rounded-xl border border-[#2d3240] bg-[#0b0d13] overflow-hidden">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 px-5 pt-5 pb-4 border-b border-[#2d3240]/60">
        <div className="flex items-start gap-3 min-w-0">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
            style={{ backgroundColor: `${CATEGORY_COLORS[guard.category]}15` }}
          >
            <Icon
              size={20}
              stroke={1.5}
              style={{ color: CATEGORY_COLORS[guard.category] }}
            />
          </div>
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-[#ece7dc] leading-tight">
              {guard.name}
            </h2>
            <p className="text-[11px] font-mono text-[#6f7f9a]/60 mt-0.5">
              {guard.technicalName}
            </p>
            <div className="flex items-center gap-2 mt-2">
              <CategoryBadge category={guard.category} />
              <VerdictBadge verdict={guard.defaultVerdict} className="text-[9px]" />
              <span
                className={cn(
                  "flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-medium",
                  isActive
                    ? "bg-[#3dbf84]/15 text-[#3dbf84]"
                    : "bg-[#2d3240]/50 text-[#6f7f9a]",
                )}
              >
                <span className={cn("h-1.5 w-1.5 rounded-full", isActive ? "bg-[#3dbf84]" : "bg-[#6f7f9a]/40")} />
                {isActive ? "Active" : "Inactive"}
              </span>
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="shrink-0 p-1 rounded-md text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721] transition-colors"
        >
          <IconX size={16} stroke={1.5} />
        </button>
      </div>

      {/* Body */}
      <div className="px-5 py-4 space-y-5">
        {/* Description */}
        <p className="text-[12px] text-[#6f7f9a] leading-relaxed">
          {guard.description}
        </p>

        {/* Configuration schema */}
        {nonEnabledFields.length > 0 && (
          <div>
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#ece7dc]/70 mb-2.5 flex items-center gap-1.5">
              <IconSettings size={12} stroke={1.5} className="text-[#d4a84b]" />
              Configuration Schema
            </h3>
            <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 divide-y divide-[#2d3240]/30">
              {nonEnabledFields.map((field) => (
                <div key={field.key} className="px-3 py-2.5 flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[11.5px] font-medium text-[#ece7dc]">
                        {field.label}
                      </span>
                      <span className="text-[9px] font-mono text-[#6f7f9a]/50 px-1 py-0.5 rounded bg-[#0b0d13]/60">
                        {field.type}
                      </span>
                    </div>
                    {field.description && (
                      <p className="text-[10px] text-[#6f7f9a]/70 mt-0.5 leading-relaxed">
                        {field.description}
                      </p>
                    )}
                  </div>
                  {field.defaultValue !== undefined && (
                    <span className="shrink-0 text-[10px] font-mono text-[#d4a84b]/60 mt-0.5">
                      default: {String(field.defaultValue)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Current policy status */}
        <div>
          <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#ece7dc]/70 mb-2.5 flex items-center gap-1.5">
            <IconShield size={12} stroke={1.5} className="text-[#d4a84b]" />
            Current Policy Status
          </h3>
          <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721]/30 px-3 py-3">
            {isActive ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-[#3dbf84]" />
                  <span className="text-[11.5px] text-[#3dbf84] font-medium">
                    Enabled in active policy
                  </span>
                </div>
                {currentConfig && Object.keys(currentConfig).filter((k) => k !== "enabled").length > 0 && (
                  <div className="mt-2 space-y-1">
                    {Object.entries(currentConfig)
                      .filter(([k]) => k !== "enabled")
                      .map(([key, value]) => (
                        <div key={key} className="flex items-center gap-2 text-[10px]">
                          <span className="font-mono text-[#6f7f9a]/70">{key}:</span>
                          <span className="font-mono text-[#d4a84b]/70 truncate">
                            {typeof value === "object" ? JSON.stringify(value) : String(value)}
                          </span>
                        </div>
                      ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[#6f7f9a]/40" />
                <span className="text-[11.5px] text-[#6f7f9a]">
                  Not enabled in active policy
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Threat categories */}
        {threats.length > 0 && (
          <div>
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[#ece7dc]/70 mb-2.5">
              Threat Categories Covered
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {threats.map((t) => (
                <span
                  key={t}
                  className="px-2 py-1 rounded-md text-[10px] text-[#ece7dc]/60 bg-[#131721]/50 border border-[#2d3240]/40"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 pt-1">
          <button
            onClick={onToggle}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors",
              isActive
                ? "bg-[#c45c5c]/15 text-[#c45c5c] hover:bg-[#c45c5c]/25 border border-[#c45c5c]/20"
                : "bg-[#3dbf84]/15 text-[#3dbf84] hover:bg-[#3dbf84]/25 border border-[#3dbf84]/20",
            )}
          >
            <IconShield size={13} stroke={1.5} />
            {isActive ? "Disable in Policy" : "Enable in Policy"}
          </button>

          <button
            onClick={onNavigateToEditor}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-[#131721] text-[#ece7dc] border border-[#2d3240] hover:border-[#d4a84b]/40 hover:text-[#d4a84b] transition-colors"
          >
            <IconArrowRight size={13} stroke={1.5} />
            Configure in Editor
          </button>

          <button
            onClick={onGenerateTests}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium bg-[#131721] text-[#ece7dc] border border-[#2d3240] hover:border-[#7b6b8b]/40 hover:text-[#7b6b8b] transition-colors"
          >
            <IconTestPipe size={13} stroke={1.5} />
            Generate Test Scenarios
          </button>
        </div>
      </div>
    </div>
  );
}


interface GuardsPageProps {
  /** Override the default "navigate to editor" behavior (e.g. when embedded as a panel). */
  onNavigateToEditor?: () => void;
}

export function GuardsPage({ onNavigateToEditor: onNavigateToEditorProp }: GuardsPageProps = {}) {
  const { state, dispatch } = useWorkbench();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>("all");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedGuardId, setSelectedGuardId] = useState<GuardId | null>(null);
  const detailRef = useRef<HTMLDivElement>(null);

  // Compute which guards are active in the current policy
  const activeGuardIds = useMemo(() => {
    const active = new Set<string>();
    for (const [id, config] of Object.entries(state.activePolicy.guards)) {
      if (config && (config as Record<string, unknown>).enabled !== false) {
        active.add(id);
      }
    }
    return active;
  }, [state.activePolicy.guards]);

  const activeCount = activeGuardIds.size;

  // Filter guards
  const filteredGuards = useMemo(() => {
    let guards = GUARD_REGISTRY;

    // Category filter
    if (categoryFilter !== "all") {
      const cat = GUARD_CATEGORIES.find((c) => c.id === categoryFilter);
      if (cat) {
        const guardIdSet = new Set(cat.guards);
        guards = guards.filter((g) => guardIdSet.has(g.id));
      }
    }

    // Search filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      guards = guards.filter(
        (g) =>
          g.name.toLowerCase().includes(q) ||
          g.technicalName.toLowerCase().includes(q) ||
          g.description.toLowerCase().includes(q) ||
          g.category.toLowerCase().includes(q),
      );
    }

    return guards;
  }, [categoryFilter, searchQuery]);

  // Clear selection when filters hide the selected guard
  useEffect(() => {
    if (selectedGuardId) {
      const stillVisible = filteredGuards.some((g) => g.id === selectedGuardId);
      if (!stillVisible) setSelectedGuardId(null);
    }
  }, [filteredGuards, selectedGuardId]);

  const selectedGuard = useMemo(
    () => (selectedGuardId ? GUARD_REGISTRY.find((g) => g.id === selectedGuardId) : undefined),
    [selectedGuardId],
  );

  // Scroll detail panel into view when a guard is selected
  useEffect(() => {
    if (selectedGuard && detailRef.current) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [selectedGuard]);

  const handleToggleGuard = useCallback(
    (guardId: string) => {
      const isCurrentlyActive = activeGuardIds.has(guardId);
      dispatch({
        type: "TOGGLE_GUARD",
        guardId: guardId as GuardId,
        enabled: !isCurrentlyActive,
      });
      toast({
        type: "success",
        title: isCurrentlyActive ? "Guard disabled" : "Guard enabled",
        description: `${GUARD_REGISTRY.find((g) => g.id === guardId)?.name ?? guardId} has been ${isCurrentlyActive ? "disabled" : "enabled"} in the active policy.`,
      });
    },
    [activeGuardIds, dispatch, toast],
  );

  const handleNavigateToEditor = useCallback(() => {
    if (onNavigateToEditorProp) {
      onNavigateToEditorProp();
    } else {
      navigate("/editor");
    }
  }, [navigate, onNavigateToEditorProp]);

  const handleGenerateTests = useCallback(
    (guard: GuardMeta) => {
      toast({
        type: "info",
        title: "Test scenario generation",
        description: `Scenario generation for ${guard.name} will be available in the Threat Lab. Navigate there to create and run guard-specific test scenarios.`,
        duration: 4000,
      });
    },
    [toast],
  );

  return (
    <div className="flex flex-col h-full bg-[#05060a]">
      {/* Header bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 bg-[#0b0d13]/50">
        <div className="flex items-center justify-between gap-4 px-6 py-4">
          {/* Left: title */}
          <div className="shrink-0">
            <h1 className="font-syne font-bold text-xl text-[#ece7dc] flex items-center gap-2">
              <IconShield size={20} stroke={1.5} className="text-[#d4a84b]" />
              Guards
            </h1>
            <p className="text-[11.5px] text-[#6f7f9a] mt-0.5">
              {activeCount} active / {GUARD_REGISTRY.length} total
            </p>
          </div>

          {/* Center: category pills */}
          <div className="flex items-center gap-1 flex-wrap justify-center">
            {FILTER_OPTIONS.map((opt) => (
              <button
                key={opt.id}
                onClick={() => setCategoryFilter(opt.id)}
                className={cn(
                  "px-2.5 py-1 rounded-full text-[10.5px] font-medium transition-all duration-150",
                  categoryFilter === opt.id
                    ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/30"
                    : "text-[#6f7f9a] border border-transparent hover:text-[#ece7dc] hover:bg-[#131721]/60",
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {/* Right: view toggle + search */}
          <div className="flex items-center gap-2 shrink-0">
            {/* View toggle */}
            <div className="flex items-center rounded-lg border border-[#2d3240] bg-[#131721]/50 p-0.5">
              <button
                onClick={() => setViewMode("grid")}
                className={cn(
                  "p-1.5 rounded-md transition-colors",
                  viewMode === "grid"
                    ? "bg-[#d4a84b]/15 text-[#d4a84b]"
                    : "text-[#6f7f9a] hover:text-[#ece7dc]",
                )}
                title="Grid view"
              >
                <IconLayoutGrid size={14} stroke={1.5} />
              </button>
              <button
                onClick={() => setViewMode("list")}
                className={cn(
                  "p-1.5 rounded-md transition-colors",
                  viewMode === "list"
                    ? "bg-[#d4a84b]/15 text-[#d4a84b]"
                    : "text-[#6f7f9a] hover:text-[#ece7dc]",
                )}
                title="List view"
              >
                <IconList size={14} stroke={1.5} />
              </button>
            </div>

            {/* Search */}
            <div className="relative">
              <IconSearch
                size={13}
                stroke={1.5}
                className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6f7f9a]/50 pointer-events-none"
              />
              <input
                type="text"
                placeholder="Search guards..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={cn(
                  "w-48 pl-8 pr-7 py-1.5 rounded-lg text-[11.5px] font-medium",
                  "bg-[#131721]/50 border border-[#2d3240] text-[#ece7dc] placeholder-[#6f7f9a]/40",
                  "focus:outline-none focus:border-[#d4a84b]/40 transition-colors",
                )}
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
                >
                  <IconX size={12} stroke={1.5} />
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main area */}
      <ScrollArea className="flex-1">
        <div className="p-6 max-w-7xl mx-auto">
          {filteredGuards.length === 0 ? (
            /* Empty state */
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <div className="w-14 h-14 rounded-2xl bg-[#131721] border border-[#2d3240]/50 flex items-center justify-center mb-4">
                <IconSearch size={22} className="text-[#6f7f9a]/40" />
              </div>
              <p className="text-[13px] font-medium text-[#6f7f9a] mb-1">
                No guards match your filter criteria
              </p>
              <p className="text-[11px] text-[#6f7f9a]/50 max-w-[300px]">
                Try broadening your search or selecting a different category.
              </p>
              <button
                onClick={() => {
                  setCategoryFilter("all");
                  setSearchQuery("");
                }}
                className="mt-4 px-3 py-1.5 rounded-lg text-[11px] font-medium text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 hover:bg-[#d4a84b]/15 transition-colors"
              >
                Clear filters
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Grid / List */}
              {viewMode === "grid" ? (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  {filteredGuards.map((guard) => (
                    <GuardGridCard
                      key={guard.id}
                      guard={guard}
                      isActive={activeGuardIds.has(guard.id)}
                      isSelected={selectedGuardId === guard.id}
                      onSelect={() =>
                        setSelectedGuardId(
                          selectedGuardId === guard.id ? null : guard.id,
                        )
                      }
                    />
                  ))}
                </div>
              ) : (
                <div className="space-y-1">
                  {filteredGuards.map((guard) => (
                    <GuardListRow
                      key={guard.id}
                      guard={guard}
                      isActive={activeGuardIds.has(guard.id)}
                      isSelected={selectedGuardId === guard.id}
                      onSelect={() =>
                        setSelectedGuardId(
                          selectedGuardId === guard.id ? null : guard.id,
                        )
                      }
                    />
                  ))}
                </div>
              )}

              {/* Detail panel (inline below grid/list) */}
              {selectedGuard && (
                <div ref={detailRef}>
                  <GuardDetailPanel
                    guard={selectedGuard}
                    isActive={activeGuardIds.has(selectedGuard.id)}
                    onClose={() => setSelectedGuardId(null)}
                    onToggle={() => handleToggleGuard(selectedGuard.id)}
                    onNavigateToEditor={handleNavigateToEditor}
                    onGenerateTests={() => handleGenerateTests(selectedGuard)}
                    currentConfig={
                      state.activePolicy.guards[selectedGuard.id as GuardId] as
                        | Record<string, unknown>
                        | undefined
                    }
                  />
                </div>
              )}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
