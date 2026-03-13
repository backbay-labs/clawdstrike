import { useState, useCallback, useMemo, useRef, type DragEvent } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { Button as MovingBorderButton } from "@/components/ui/moving-border";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";
import {
  parseEventLog,
  synthesizePolicy,
  mergeSynthIntoPolicy,
  type ParsedEvent,
  type SynthResult,
  type EventRiskLevel,
} from "@/lib/workbench/observe-synth-engine";
import {
  IconUpload,
  IconSparkles,
  IconArrowRight,
  IconFile,
  IconFileText,
  IconNetwork,
  IconTerminal,
  IconTool,
  IconPencil,
  IconMessage,
  IconFilter,
  IconX,
  IconShieldCheck,
  IconAlertTriangle,
  IconBan,
  IconTerminal2,
  IconChevronDown,
  IconChevronRight,
  IconCircleCheck,
  IconCircleX,
  IconInfoCircle,
} from "@tabler/icons-react";
import type { TestActionType } from "@/lib/workbench/types";
import { ClaudeCodeHint } from "@/components/workbench/shared/claude-code-hint";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ACTION_ICONS: Record<string, typeof IconFile> = {
  file_access: IconFile,
  file_write: IconFileText,
  network_egress: IconNetwork,
  shell_command: IconTerminal,
  mcp_tool_call: IconTool,
  patch_apply: IconPencil,
  user_input: IconMessage,
};

const RISK_STYLES: Record<EventRiskLevel, { bg: string; border: string; text: string; label: string }> = {
  safe: { bg: "bg-[#3dbf84]/10", border: "border-[#3dbf84]/20", text: "text-[#3dbf84]", label: "SAFE" },
  suspicious: { bg: "bg-[#d4a84b]/10", border: "border-[#d4a84b]/20", text: "text-[#d4a84b]", label: "SUSPICIOUS" },
  blocked: { bg: "bg-[#c45c5c]/10", border: "border-[#c45c5c]/20", text: "text-[#c45c5c]", label: "BLOCKED" },
};

type FilterActionType = TestActionType | "all";
type FilterRiskLevel = EventRiskLevel | "all";

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function RiskBadge({ level }: { level: EventRiskLevel }) {
  const style = RISK_STYLES[level];
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0 text-[9px] font-mono uppercase border rounded select-none tracking-wide",
        style.bg,
        style.border,
        style.text,
      )}
    >
      {style.label}
    </span>
  );
}

function EventRow({ event, coverageVerdict }: { event: ParsedEvent; coverageVerdict?: string }) {
  const Icon = ACTION_ICONS[event.normalizedAction ?? ""] ?? IconFile;
  const timestamp = event.parsedTimestamp;
  const timeStr = timestamp.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div
      className={cn(
        "flex items-center gap-2.5 px-3 py-2 border-b border-[#2d3240]/40 hover:bg-[#131721]/40 transition-colors group",
      )}
    >
      {/* Timestamp */}
      <span className="text-[10px] font-mono text-[#6f7f9a]/60 w-[60px] shrink-0">
        {timeStr}
      </span>

      {/* Action icon */}
      <div className="w-5 h-5 rounded bg-[#131721] border border-[#2d3240]/40 flex items-center justify-center shrink-0">
        <Icon size={11} stroke={1.5} className="text-[#6f7f9a]" />
      </div>

      {/* Action type */}
      <span className="text-[10px] font-mono text-[#6f7f9a] w-[80px] shrink-0 truncate">
        {event.action_type}
      </span>

      {/* Target */}
      <span className="text-[11px] font-mono text-[#ece7dc] flex-1 min-w-0 truncate">
        {event.target}
      </span>

      {/* Risk badge */}
      <RiskBadge level={event.riskLevel} />

      {/* Coverage verdict (post-synth) */}
      {coverageVerdict && (
        <VerdictBadge verdict={coverageVerdict as "allow" | "deny" | "warn"} />
      )}
    </div>
  );
}

function SynthStatsPanel({ stats }: { stats: SynthResult["stats"] }) {
  const items = [
    { label: "Events", value: stats.totalEvents, color: "#ece7dc" },
    { label: "Paths", value: stats.uniquePaths, color: "#6f7f9a" },
    { label: "Domains", value: stats.uniqueDomains, color: "#6f7f9a" },
    { label: "Commands", value: stats.uniqueCommands, color: "#6f7f9a" },
    { label: "Tools", value: stats.uniqueTools, color: "#6f7f9a" },
  ];

  return (
    <div className="grid grid-cols-5 gap-2 mb-4">
      {items.map((item) => (
        <div
          key={item.label}
          className="flex flex-col items-center px-2 py-2 rounded-lg border border-[#2d3240] bg-[#0b0d13]"
        >
          <span className="text-lg font-mono font-bold" style={{ color: item.color }}>
            {item.value}
          </span>
          <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mt-0.5">
            {item.label}
          </span>
        </div>
      ))}
    </div>
  );
}

function CoverageHeatmap({ coverage }: { coverage: SynthResult["coverage"] }) {
  const allowed = coverage.filter((c) => c.synthVerdict === "allow").length;
  const denied = coverage.filter((c) => c.synthVerdict === "deny").length;
  const warned = coverage.filter((c) => c.synthVerdict === "warn").length;
  const total = coverage.length;

  const pctAllow = total > 0 ? Math.round((allowed / total) * 100) : 0;
  const pctDeny = total > 0 ? Math.round((denied / total) * 100) : 0;
  const pctWarn = total > 0 ? Math.round((warned / total) * 100) : 0;

  return (
    <div className="border border-[#2d3240] rounded-lg p-4 bg-[#0b0d13]/50">
      <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-3 flex items-center gap-1.5">
        <IconShieldCheck size={12} stroke={1.5} className="text-[#d4a84b]" />
        Coverage Analysis
      </h4>

      {/* Stacked bar */}
      <div className="h-3 rounded-full overflow-hidden flex bg-[#131721] border border-[#2d3240] mb-3">
        {pctAllow > 0 && (
          <div
            className="h-full bg-[#3dbf84] transition-all duration-500"
            style={{ width: `${pctAllow}%` }}
          />
        )}
        {pctWarn > 0 && (
          <div
            className="h-full bg-[#d4a84b] transition-all duration-500"
            style={{ width: `${pctWarn}%` }}
          />
        )}
        {pctDeny > 0 && (
          <div
            className="h-full bg-[#c45c5c] transition-all duration-500"
            style={{ width: `${pctDeny}%` }}
          />
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-[10px] font-mono">
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#3dbf84]" />
          <span className="text-[#3dbf84]">{allowed} allowed</span>
          <span className="text-[#6f7f9a]/50">({pctAllow}%)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#d4a84b]" />
          <span className="text-[#d4a84b]">{warned} warned</span>
          <span className="text-[#6f7f9a]/50">({pctWarn}%)</span>
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-[#c45c5c]" />
          <span className="text-[#c45c5c]">{denied} denied</span>
          <span className="text-[#6f7f9a]/50">({pctDeny}%)</span>
        </span>
      </div>
    </div>
  );
}

function SynthGuardConfig({ synth }: { synth: SynthResult }) {
  const [expandedGuard, setExpandedGuard] = useState<string | null>(null);
  const guards = synth.guards;

  const guardEntries = Object.entries(guards).filter(
    ([, config]) => config && Object.keys(config).length > 0,
  );

  return (
    <div className="border border-[#2d3240] rounded-lg bg-[#0b0d13]/50 overflow-hidden">
      <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] px-4 py-3 border-b border-[#2d3240] flex items-center gap-1.5">
        <IconSparkles size={12} stroke={1.5} className="text-[#d4a84b]" />
        Synthesized Guard Configuration
      </h4>

      {guardEntries.map(([guardId, config]) => {
        const isExpanded = expandedGuard === guardId;
        return (
          <div key={guardId} className="border-b border-[#2d3240]/40 last:border-b-0">
            <button
              onClick={() => setExpandedGuard(isExpanded ? null : guardId)}
              className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-[#131721]/40 transition-colors"
            >
              {isExpanded ? (
                <IconChevronDown size={12} stroke={2} className="text-[#6f7f9a] shrink-0" />
              ) : (
                <IconChevronRight size={12} stroke={2} className="text-[#6f7f9a] shrink-0" />
              )}
              <span className="text-xs font-mono text-[#ece7dc]">{guardId}</span>
              <span
                className={cn(
                  "ml-auto text-[9px] font-mono uppercase px-1.5 py-0 border rounded",
                  (config as { enabled?: boolean }).enabled !== false
                    ? "text-[#3dbf84] border-[#3dbf84]/20 bg-[#3dbf84]/10"
                    : "text-[#6f7f9a] border-[#2d3240] bg-[#131721]",
                )}
              >
                {(config as { enabled?: boolean }).enabled !== false ? "enabled" : "disabled"}
              </span>
            </button>
            {isExpanded && (
              <div className="px-4 pb-3">
                <pre className="text-[10px] font-mono bg-[#131721] border border-[#2d3240] rounded p-2.5 overflow-x-auto text-[#6f7f9a] max-h-40 overflow-y-auto">
                  {JSON.stringify(config, null, 2)}
                </pre>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Panel
// ---------------------------------------------------------------------------

export function ObserveSynthPanel() {
  const { state, dispatch } = useWorkbench();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [rawInput, setRawInput] = useState("");
  const [events, setEvents] = useState<ParsedEvent[]>([]);
  const [parseErrors, setParseErrors] = useState<string[]>([]);
  const [synthResult, setSynthResult] = useState<SynthResult | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [filterAction, setFilterAction] = useState<FilterActionType>("all");
  const [filterRisk, setFilterRisk] = useState<FilterRiskLevel>("all");
  const [showFilters, setShowFilters] = useState(false);

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (filterAction !== "all" && e.normalizedAction !== filterAction) return false;
      if (filterRisk !== "all" && e.riskLevel !== filterRisk) return false;
      return true;
    });
  }, [events, filterAction, filterRisk]);

  // Import handler
  const handleImport = useCallback(
    (text: string) => {
      const [parsed, errors] = parseEventLog(text);
      setEvents(parsed);
      setParseErrors(errors);
      setSynthResult(null);

      if (parsed.length > 0) {
        toast({
          type: "success",
          title: `Imported ${parsed.length} event(s)`,
          description: errors.length > 0 ? `${errors.length} line(s) skipped` : "All lines parsed successfully",
        });
      } else if (errors.length > 0) {
        toast({
          type: "error",
          title: "Import failed",
          description: `${errors.length} parsing error(s) — check the format`,
        });
      }
    },
    [toast],
  );

  const handlePasteImport = useCallback(() => {
    if (rawInput.trim()) {
      handleImport(rawInput);
    }
  }, [rawInput, handleImport]);

  // File drag & drop
  const handleDragOver = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        const file = files[0];
        const reader = new FileReader();
        reader.onload = (evt) => {
          const text = evt.target?.result;
          if (typeof text === "string") {
            setRawInput(text);
            handleImport(text);
          }
        };
        reader.readAsText(file);
      }
    },
    [handleImport],
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (evt) => {
        const text = evt.target?.result;
        if (typeof text === "string") {
          setRawInput(text);
          handleImport(text);
        }
      };
      reader.readAsText(file);
    },
    [handleImport],
  );

  // Synth handler
  const handleSynthesize = useCallback(() => {
    if (events.length === 0) return;
    const result = synthesizePolicy(events);
    setSynthResult(result);
    toast({
      type: "success",
      title: "Policy synthesized",
      description: `Generated config from ${result.stats.totalEvents} events`,
    });
  }, [events, toast]);

  // Apply synth to active policy
  const handleApplyToPolicy = useCallback(() => {
    if (!synthResult) return;
    const merged = mergeSynthIntoPolicy(state.activePolicy, synthResult.guards);
    dispatch({ type: "SET_POLICY", policy: merged });
    toast({
      type: "success",
      title: "Policy updated",
      description: "Synthesized configuration merged into active policy",
    });
  }, [synthResult, state.activePolicy, dispatch, toast]);

  // Clear all
  const handleClear = useCallback(() => {
    setRawInput("");
    setEvents([]);
    setParseErrors([]);
    setSynthResult(null);
  }, []);

  // Risk stats
  const riskStats = useMemo(() => {
    const safe = events.filter((e) => e.riskLevel === "safe").length;
    const suspicious = events.filter((e) => e.riskLevel === "suspicious").length;
    const blocked = events.filter((e) => e.riskLevel === "blocked").length;
    return { safe, suspicious, blocked };
  }, [events]);

  // ---------------------------------------------------------------------------
  // Render: Empty state
  // ---------------------------------------------------------------------------
  if (events.length === 0) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex flex-col items-center justify-center p-8">
          {/* Hero section */}
          <div className="max-w-xl w-full">
            {/* Methodology banner */}
            <div className="flex items-center gap-3 mb-8 justify-center">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-[#d4a84b]/20 bg-[#d4a84b]/5">
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#d4a84b] font-semibold">
                  Observe
                </span>
                <IconArrowRight size={10} stroke={2} className="text-[#d4a84b]/50" />
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                  Synth
                </span>
                <IconArrowRight size={10} stroke={2} className="text-[#6f7f9a]/50" />
                <span className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a]">
                  Tighten
                </span>
              </div>
            </div>

            {/* Drag & drop zone */}
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={cn(
                "relative border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 mb-6",
                isDragOver
                  ? "border-[#d4a84b] bg-[#d4a84b]/5 scale-[1.01]"
                  : "border-[#2d3240] bg-[#0b0d13]/50 hover:border-[#d4a84b]/40",
              )}
            >
              <div className="w-12 h-12 rounded-xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mx-auto mb-4">
                <IconUpload size={20} stroke={1.2} className="text-[#d4a84b]" />
              </div>
              <h3 className="font-syne font-bold text-sm text-[#ece7dc] mb-1.5">
                Import Agent Activity
              </h3>
              <p className="text-[12px] text-[#6f7f9a] leading-relaxed mb-4 max-w-sm mx-auto">
                Drop a JSONL event log here or paste events below to auto-generate
                a security policy from real agent behavior.
              </p>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-[#131721] border border-[#2d3240] text-[#ece7dc] text-xs font-medium hover:bg-[#131721]/80 hover:border-[#d4a84b]/30 transition-all duration-150"
              >
                <IconUpload size={13} stroke={1.5} />
                Browse files
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".jsonl,.json,.txt,.log"
                onChange={handleFileSelect}
                className="hidden"
              />
            </div>

            {/* Paste area */}
            <div className="mb-4">
              <Textarea
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                placeholder={'{"action_type":"file_access","target":"~/.ssh/id_rsa"}\n{"action_type":"network","target":"api.github.com","verdict":"allow"}\n{"action_type":"shell","target":"git status"}'}
                rows={6}
                className="bg-[#0b0d13] border-[#2d3240] text-[#ece7dc] font-mono text-xs placeholder:text-[#6f7f9a]/30 resize-none"
              />
            </div>

            {rawInput.trim() && (
              <button
                onClick={handlePasteImport}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-xs font-medium hover:bg-[#d4a84b]/20 transition-colors"
              >
                <IconArrowRight size={14} stroke={1.5} />
                Parse & Import Events
              </button>
            )}

            {/* Parse errors */}
            {parseErrors.length > 0 && (
              <div className="mt-4 p-3 rounded-lg border border-[#c45c5c]/20 bg-[#c45c5c]/5">
                <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#c45c5c] mb-2 flex items-center gap-1.5">
                  <IconAlertTriangle size={11} stroke={1.5} />
                  Parse Errors
                </h4>
                <div className="space-y-1 max-h-24 overflow-y-auto">
                  {parseErrors.map((err, i) => (
                    <p key={i} className="text-[11px] text-[#c45c5c]/80 font-mono">{err}</p>
                  ))}
                </div>
              </div>
            )}

            {/* CLI hint */}
            <div className="mt-6 p-4 rounded-lg border border-[#2d3240] bg-[#0b0d13]">
              <div className="flex items-start gap-3">
                <IconTerminal2 size={16} stroke={1.5} className="text-[#d4a84b] shrink-0 mt-0.5" />
                <div>
                  <p className="text-[11px] text-[#6f7f9a] leading-relaxed mb-2">
                    Capture agent activity with the ClawdStrike CLI:
                  </p>
                  <code className="block text-[11px] font-mono text-[#d4a84b] bg-[#131721] px-3 py-2 rounded border border-[#2d3240]">
                    clawdstrike policy observe --out events.jsonl -- your-agent-command
                  </code>
                </div>
              </div>
            </div>

            {/* Claude Code hint */}
            <ClaudeCodeHint
              hintId="observe.synth"
              className="mt-4"
            />
          </div>
        </div>
      </div>
    );
  }

  // ---------------------------------------------------------------------------
  // Render: Events loaded
  // ---------------------------------------------------------------------------
  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        {/* Event count + risk summary */}
        <div className="flex items-center gap-3">
          <span className="text-xs font-mono text-[#ece7dc]">
            {events.length} event{events.length !== 1 ? "s" : ""}
          </span>
          <div className="flex items-center gap-2 text-[10px] font-mono">
            <span className="flex items-center gap-1 text-[#3dbf84]">
              <IconCircleCheck size={10} stroke={2} />
              {riskStats.safe}
            </span>
            <span className="flex items-center gap-1 text-[#d4a84b]">
              <IconAlertTriangle size={10} stroke={2} />
              {riskStats.suspicious}
            </span>
            <span className="flex items-center gap-1 text-[#c45c5c]">
              <IconBan size={10} stroke={2} />
              {riskStats.blocked}
            </span>
          </div>
        </div>

        <div className="flex-1" />

        {/* Filter toggle */}
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={cn(
            "flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-mono transition-colors",
            showFilters || filterAction !== "all" || filterRisk !== "all"
              ? "bg-[#d4a84b]/10 text-[#d4a84b]"
              : "text-[#6f7f9a] hover:text-[#ece7dc]",
          )}
        >
          <IconFilter size={12} stroke={1.5} />
          Filter
        </button>

        {/* Synth button */}
        {!synthResult && (
          <button
            onClick={handleSynthesize}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
          >
            <IconSparkles size={13} stroke={1.5} />
            Synthesize Policy
          </button>
        )}

        {/* Clear */}
        <button
          onClick={handleClear}
          className="flex items-center gap-1 px-2 py-1 rounded-md text-[#6f7f9a] text-[11px] font-mono hover:text-[#ece7dc] transition-colors"
        >
          <IconX size={12} stroke={1.5} />
          Clear
        </button>
      </div>

      {/* Filters bar */}
      {showFilters && (
        <div className="flex items-center gap-3 px-4 py-2 border-b border-[#2d3240]/60 bg-[#0b0d13]/80 shrink-0">
          <span className="text-[10px] font-mono text-[#6f7f9a] uppercase tracking-wider">Action:</span>
          <div className="flex items-center gap-1">
            {(["all", "file_access", "file_write", "network_egress", "shell_command", "mcp_tool_call", "patch_apply", "user_input"] as FilterActionType[]).map(
              (val) => (
                <button
                  key={val}
                  onClick={() => setFilterAction(val)}
                  className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-mono transition-colors",
                    filterAction === val
                      ? "bg-[#d4a84b]/15 text-[#d4a84b]"
                      : "text-[#6f7f9a] hover:text-[#ece7dc]",
                  )}
                >
                  {val === "all" ? "All" : val.replace(/_/g, " ")}
                </button>
              ),
            )}
          </div>
          <div className="w-px h-4 bg-[#2d3240]" />
          <span className="text-[10px] font-mono text-[#6f7f9a] uppercase tracking-wider">Risk:</span>
          <div className="flex items-center gap-1">
            {(["all", "safe", "suspicious", "blocked"] as FilterRiskLevel[]).map((val) => (
              <button
                key={val}
                onClick={() => setFilterRisk(val)}
                className={cn(
                  "px-2 py-0.5 rounded text-[10px] font-mono transition-colors",
                  filterRisk === val
                    ? "bg-[#d4a84b]/15 text-[#d4a84b]"
                    : "text-[#6f7f9a] hover:text-[#ece7dc]",
                )}
              >
                {val === "all" ? "All" : val}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Content area */}
      <div className="flex-1 min-h-0 flex">
        {/* Left: Event timeline */}
        <div className={cn("flex-1 min-w-0 flex flex-col", synthResult ? "max-w-[55%]" : "")}>
          <ScrollArea className="flex-1 overflow-y-auto">
            <div>
              {filteredEvents.map((event, i) => {
                const coverage = synthResult?.coverage.find((c) => c.eventIndex === event.lineIndex);
                return (
                  <EventRow
                    key={`${event.lineIndex}-${i}`}
                    event={event}
                    coverageVerdict={coverage?.synthVerdict}
                  />
                );
              })}
              {filteredEvents.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12 text-[#6f7f9a]">
                  <IconInfoCircle size={20} stroke={1.2} className="mb-2 opacity-50" />
                  <span className="text-[12px]">No events match the current filters</span>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Right: Synth results */}
        {synthResult && (
          <div className="w-[45%] shrink-0 border-l border-[#2d3240] bg-[#05060a] flex flex-col">
            <div className="px-4 py-3 border-b border-[#2d3240] shrink-0">
              <div className="flex items-center gap-2">
                <IconSparkles size={14} stroke={1.5} className="text-[#d4a84b]" />
                <h3 className="font-syne font-bold text-sm text-[#ece7dc]">
                  Synthesized Policy
                </h3>
              </div>
              <p className="text-[10px] text-[#6f7f9a] mt-1">
                Generated from {synthResult.stats.totalEvents} observed events
              </p>
            </div>

            <ScrollArea className="flex-1 overflow-y-auto">
              <div className="p-4 space-y-4">
                <SynthStatsPanel stats={synthResult.stats} />
                <CoverageHeatmap coverage={synthResult.coverage} />
                <SynthGuardConfig synth={synthResult} />

                {/* Apply button */}
                <div className="pt-2">
                  <MovingBorderButton
                    onClick={handleApplyToPolicy}
                    containerClassName="h-10 w-full"
                    borderClassName="bg-[radial-gradient(#d4a84b_40%,transparent_60%)]"
                    className="bg-[#0b0d13] border-[#2d3240] text-[#d4a84b] font-syne font-bold text-sm"
                    borderRadius="0.5rem"
                  >
                    Apply to Active Policy
                  </MovingBorderButton>
                </div>

                <p className="text-[10px] text-[#6f7f9a]/60 text-center leading-relaxed">
                  Merges synthesized config into your active policy.
                  Review the result in the editor before saving.
                </p>
              </div>
            </ScrollArea>
          </div>
        )}
      </div>
    </div>
  );
}
