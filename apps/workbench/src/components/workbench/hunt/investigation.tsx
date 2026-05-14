import { useState, useMemo, useCallback } from "react";
import { motion } from "motion/react";
import {
  IconPlus,
  IconFileAnalytics,
  IconShieldCheck,
  IconShieldX,
  IconShieldPlus,
  IconNetwork,
  IconTerminal,
  IconFile,
  IconFileText,
  IconBrain,
  IconTool,
  IconChevronLeft,
  IconChevronRight,
  IconChevronDown,
  IconChevronUp,
  IconAlertTriangle,
  IconCircleCheck,
  IconCircleDot,
  IconCircleHalf2,
  IconCircleX,
  IconUser,
  IconNote,
  IconCheck,
  IconTarget,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import type {
  Investigation,
  InvestigationStatus,
  InvestigationVerdict,
  InvestigationAction,
  Severity,
  Annotation,
  AgentEvent,
} from "@/lib/workbench/hunt-types";
import type { Verdict, TestActionType } from "@/lib/workbench/types";
import { useCoverageGaps } from "@/lib/workbench/detection-workflow/use-coverage-gaps";
import type { CoverageGapInput, DocumentCoverageEntry } from "@/lib/workbench/detection-workflow/coverage-gap-engine";
import type { CoverageGapCandidate } from "@/lib/workbench/detection-workflow/shared-types";
import { CoverageGapCard } from "@/components/workbench/coverage/coverage-gap-card";


interface InvestigationWorkbenchProps {
  investigations: Investigation[];
  events: AgentEvent[];
  onCreateInvestigation: (investigation: Investigation) => void;
  onUpdateInvestigation: (id: string, updates: Partial<Investigation>) => void;
  onAddAnnotation: (investigationId: string, text: string) => void;
  onDraftDetection?: (
    investigation: Investigation,
    scopeEvents?: AgentEvent[],
    selectedGap?: CoverageGapCandidate,
  ) => void;
  openDocumentCoverage?: DocumentCoverageEntry[];
  publishedCoverage?: DocumentCoverageEntry[];
}


const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#c45c5c",
  high: "#d4784b",
  medium: "#d4a84b",
  low: "#6b9b8b",
  info: "#6f7f9a",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
  info: "INFO",
};

const VERDICT_OPTIONS: { value: InvestigationVerdict; label: string }[] = [
  { value: "threat-confirmed", label: "Threat Confirmed" },
  { value: "false-positive", label: "False Positive" },
  { value: "policy-gap", label: "Policy Gap" },
  { value: "inconclusive", label: "Inconclusive" },
];

const ACTION_OPTIONS: { value: InvestigationAction; label: string }[] = [
  { value: "policy-updated", label: "Policy Updated" },
  { value: "pattern-added", label: "Pattern Added" },
  { value: "agent-revoked", label: "Agent Revoked" },
  { value: "escalated", label: "Escalated" },
];

const ACTION_TYPE_ICONS: Record<TestActionType, typeof IconFile> = {
  file_access: IconFile,
  file_write: IconFileText,
  network_egress: IconNetwork,
  shell_command: IconTerminal,
  mcp_tool_call: IconTool,
  patch_apply: IconFileText,
  user_input: IconBrain,
};

const VERDICT_STYLES: Record<Verdict, { color: string; label: string }> = {
  allow: { color: "#3dbf84", label: "ALLOW" },
  deny: { color: "#c45c5c", label: "DENY" },
  warn: { color: "#d4a84b", label: "WARN" },
};

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];


function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

function caseDisplayId(index: number): string {
  return `#INV-${String(index + 1).padStart(3, "0")}`;
}

function statusIcon(status: InvestigationStatus) {
  switch (status) {
    case "open":
      return <IconCircleDot size={10} className="text-[#d4a84b]" stroke={2} />;
    case "in-progress":
      return <IconCircleHalf2 size={10} className="text-[#d4a84b]" stroke={2} />;
    case "resolved":
      return <IconCircleCheck size={10} className="text-[#3dbf84]" stroke={2} />;
    case "false-positive":
      return <IconCircleX size={10} className="text-[#6f7f9a]" stroke={2} />;
  }
}

function isActiveCaseStatus(status: InvestigationStatus): boolean {
  return status === "open" || status === "in-progress";
}

function anomalyScoreDot(score: number | undefined): string {
  if (score === undefined || score < 0.3) return "bg-[#6f7f9a]/30";
  if (score < 0.6) return "bg-[#d4a84b]";
  return "bg-[#c45c5c]";
}

function eventHasFlags(event: AgentEvent): boolean {
  return event.flags.length > 0;
}

function eventHaloColor(event: AgentEvent): string | null {
  if (event.flags.some((f) => f.type === "anomaly" && f.score >= 0.7)) return "#c45c5c";
  if (event.flags.some((f) => f.type === "anomaly" && f.score >= 0.4)) return "#d4a84b";
  if (event.flags.some((f) => f.type === "escalated")) return "#c45c5c";
  if (event.flags.some((f) => f.type === "pattern-match")) return "#d4a84b";
  return null;
}


export function InvestigationWorkbench({
  investigations,
  events,
  onCreateInvestigation,
  onUpdateInvestigation,
  onAddAnnotation,
  onDraftDetection,
  openDocumentCoverage,
  publishedCoverage,
}: InvestigationWorkbenchProps) {
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [showNewCaseForm, setShowNewCaseForm] = useState(false);
  const [sessionIndex, setSessionIndex] = useState(0);
  const [annotationsExpanded, setAnnotationsExpanded] = useState(true);
  const [showAnnotationInput, setShowAnnotationInput] = useState(false);
  const [annotationText, setAnnotationText] = useState("");

  // New investigation form state
  const [newTitle, setNewTitle] = useState("");
  const [newSeverity, setNewSeverity] = useState<Severity>("medium");

  const selectedCase = useMemo(
    () => investigations.find((inv) => inv.id === selectedCaseId) ?? null,
    [investigations, selectedCaseId],
  );

  // Partition cases into active and closed
  const activeCases = useMemo(
    () => investigations.filter((inv) => isActiveCaseStatus(inv.status)),
    [investigations],
  );
  const closedCases = useMemo(
    () => investigations.filter((inv) => !isActiveCaseStatus(inv.status)),
    [investigations],
  );

  // Events in the selected investigation's scope
  const scopedEvents = useMemo(() => {
    if (!selectedCase) return [];
    const eventIdSet = new Set(selectedCase.eventIds);
    const sessionIdSet = new Set(selectedCase.sessionIds);
    return events
      .filter(
        (e) => eventIdSet.has(e.id) || sessionIdSet.has(e.sessionId),
      )
      .sort(
        (a, b) =>
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
      );
  }, [selectedCase, events]);

  // Unique sessions in the scoped events
  const sessionIds = useMemo(() => {
    const ids: string[] = [];
    const seen = new Set<string>();
    for (const e of scopedEvents) {
      if (!seen.has(e.sessionId)) {
        seen.add(e.sessionId);
        ids.push(e.sessionId);
      }
    }
    return ids;
  }, [scopedEvents]);

  const currentSessionId = sessionIds[sessionIndex] ?? null;

  // Events filtered to current session
  const sessionEvents = useMemo(() => {
    if (!currentSessionId) return scopedEvents;
    return scopedEvents.filter((e) => e.sessionId === currentSessionId);
  }, [scopedEvents, currentSessionId]);

  // Current agent name from session events
  const currentAgentName = sessionEvents[0]?.agentName ?? "Unknown Agent";

  // Selected event
  const selectedEvent = useMemo(
    () => events.find((e) => e.id === selectedEventId) ?? null,
    [events, selectedEventId],
  );

  // Case index map for display IDs
  const caseIndexMap = useMemo(() => {
    const map = new Map<string, number>();
    investigations.forEach((inv, i) => map.set(inv.id, i));
    return map;
  }, [investigations]);

  // Handlers
  const handleCreateInvestigation = useCallback(() => {
    if (!newTitle.trim()) return;
    const now = new Date().toISOString();
    const investigation: Investigation = {
      id: crypto.randomUUID(),
      title: newTitle.trim(),
      status: "open",
      severity: newSeverity,
      createdAt: now,
      updatedAt: now,
      createdBy: "analyst",
      agentIds: [],
      sessionIds: [],
      timeRange: { start: now, end: now },
      eventIds: [],
      annotations: [],
    };
    onCreateInvestigation(investigation);
    setSelectedCaseId(investigation.id);
    setNewTitle("");
    setNewSeverity("medium");
    setShowNewCaseForm(false);
  }, [newTitle, newSeverity, onCreateInvestigation]);

  const handleAddAnnotation = useCallback(() => {
    if (!selectedCaseId || !annotationText.trim()) return;
    onAddAnnotation(selectedCaseId, annotationText.trim());
    setAnnotationText("");
    setShowAnnotationInput(false);
  }, [selectedCaseId, annotationText, onAddAnnotation]);

  const handleVerdictChange = useCallback(
    (verdict: InvestigationVerdict) => {
      if (!selectedCaseId) return;
      onUpdateInvestigation(selectedCaseId, {
        verdict,
        status: verdict === "false-positive" ? "false-positive" : "resolved",
        updatedAt: new Date().toISOString(),
      });
    },
    [selectedCaseId, onUpdateInvestigation],
  );

  const handleActionToggle = useCallback(
    (action: InvestigationAction) => {
      if (!selectedCase) return;
      const current = selectedCase.actions ?? [];
      const next = current.includes(action)
        ? current.filter((a) => a !== action)
        : [...current, action];
      onUpdateInvestigation(selectedCase.id, {
        actions: next,
        updatedAt: new Date().toISOString(),
      });
    },
    [selectedCase, onUpdateInvestigation],
  );

  const handlePrevSession = useCallback(() => {
    setSessionIndex((i) => Math.max(0, i - 1));
    setSelectedEventId(null);
  }, []);

  const handleNextSession = useCallback(() => {
    setSessionIndex((i) => Math.min(sessionIds.length - 1, i + 1));
    setSelectedEventId(null);
  }, [sessionIds.length]);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Main 3-column layout */}
      <div className="flex flex-1 min-h-0">
        {/* ----------------------------------------------------------------- */}
        {/* LEFT COLUMN: Case List */}
        {/* ----------------------------------------------------------------- */}
        <div className="w-56 shrink-0 border-r border-[#2d3240]/60 flex flex-col bg-[#0b0d13]">
          {/* Header */}
          <div className="shrink-0 px-3 py-3 border-b border-[#2d3240]/60">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50">
                Cases
              </span>
              <button
                onClick={() => setShowNewCaseForm((v) => !v)}
                className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/10 transition-colors"
              >
                <IconPlus size={11} stroke={2} />
                New Investigation
              </button>
            </div>
          </div>

          {/* New case form */}
          {showNewCaseForm && (
            <div className="shrink-0 px-3 py-3 border-b border-[#2d3240]/60 bg-[#131721]">
              <input
                type="text"
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleCreateInvestigation();
                  if (e.key === "Escape") setShowNewCaseForm(false);
                }}
                placeholder="e.g., Suspicious egress to unknown domain"
                autoFocus
                className="w-full rounded-md border border-[#2d3240] bg-[#05060a] px-2 py-1.5 text-[11px] text-[#ece7dc] placeholder:text-[#6f7f9a]/40 outline-none focus:border-[#d4a84b]/50 transition-colors"
              />
              <div className="mt-2 flex items-center gap-2">
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as Severity)}
                  className="flex-1 rounded-md border border-[#2d3240] bg-[#05060a] px-2 py-1 text-[10px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/50 transition-colors"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {SEVERITY_LABELS[s]}
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleCreateInvestigation}
                  disabled={!newTitle.trim()}
                  className={cn(
                    "rounded-md px-3 py-1 text-[10px] font-medium transition-colors",
                    newTitle.trim()
                      ? "bg-[#d4a84b]/10 text-[#d4a84b] hover:bg-[#d4a84b]/20 border border-[#d4a84b]/20"
                      : "text-[#6f7f9a]/30 cursor-not-allowed border border-[#2d3240]/50",
                  )}
                >
                  Create
                </button>
              </div>
            </div>
          )}

          {/* Case list */}
          <div className="flex-1 overflow-y-auto">
            {investigations.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <IconFileAnalytics
                  size={20}
                  className="mx-auto mb-2 text-[#6f7f9a]/50"
                />
                <p className="text-[10px] text-[#6f7f9a]/40 leading-relaxed">
                  No investigations yet. Escalate suspicious activity from the
                  Activity Stream to begin.
                </p>
              </div>
            ) : (
              <>
                {/* Active cases */}
                {activeCases.map((inv) => (
                  <CaseCard
                    key={inv.id}
                    investigation={inv}
                    displayId={caseDisplayId(caseIndexMap.get(inv.id) ?? 0)}
                    isSelected={selectedCaseId === inv.id}
                    agentCount={
                      new Set(
                        events
                          .filter(
                            (e) =>
                              inv.eventIds.includes(e.id) ||
                              inv.sessionIds.includes(e.sessionId),
                          )
                          .map((e) => e.agentId),
                      ).size
                    }
                    onClick={() => {
                      setSelectedCaseId(inv.id);
                      setSessionIndex(0);
                      setSelectedEventId(null);
                    }}
                  />
                ))}

                {/* Separator */}
                {activeCases.length > 0 && closedCases.length > 0 && (
                  <div className="mx-3 my-1 border-t border-[#2d3240]/40" />
                )}

                {/* Closed cases */}
                {closedCases.map((inv) => (
                  <CaseCard
                    key={inv.id}
                    investigation={inv}
                    displayId={caseDisplayId(caseIndexMap.get(inv.id) ?? 0)}
                    isSelected={selectedCaseId === inv.id}
                    agentCount={
                      new Set(
                        events
                          .filter(
                            (e) =>
                              inv.eventIds.includes(e.id) ||
                              inv.sessionIds.includes(e.sessionId),
                          )
                          .map((e) => e.agentId),
                      ).size
                    }
                    onClick={() => {
                      setSelectedCaseId(inv.id);
                      setSessionIndex(0);
                      setSelectedEventId(null);
                    }}
                  />
                ))}
              </>
            )}
          </div>
        </div>

        {/* ----------------------------------------------------------------- */}
        {/* CENTER + RIGHT columns wrapper */}
        {/* ----------------------------------------------------------------- */}
        <div className="flex flex-1 min-w-0 flex-col">
          {/* Top area: center + right columns */}
          <div className="flex flex-1 min-h-0">
            {/* ------------------------------------------------------------- */}
            {/* CENTER COLUMN: Session Timeline */}
            {/* ------------------------------------------------------------- */}
            <div className="flex-1 flex flex-col min-w-0">
              {selectedCase ? (
                <>
                  {/* Timeline header */}
                  <div className="shrink-0 px-5 py-3 border-b border-[#2d3240]/60 bg-[#0b0d13]">
                    <div className="flex items-center justify-between">
                      <div>
                        <h2 className="font-syne text-[11px] font-semibold text-[#ece7dc] tracking-[-0.01em]">
                          Session Timeline
                        </h2>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-[10px] text-[#6f7f9a]">
                            {currentAgentName}
                          </span>
                          {currentSessionId && (
                            <span className="font-mono text-[9px] text-[#6f7f9a]/50">
                              {currentSessionId.slice(0, 8)}...
                            </span>
                          )}
                        </div>
                      </div>
                      {/* Session navigation */}
                      {sessionIds.length > 1 && (
                        <div className="flex items-center gap-1">
                          <button
                            onClick={handlePrevSession}
                            disabled={sessionIndex === 0}
                            className={cn(
                              "flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-medium transition-colors",
                              sessionIndex === 0
                                ? "text-[#6f7f9a]/50 cursor-not-allowed"
                                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]",
                            )}
                          >
                            <IconChevronLeft size={12} stroke={1.5} />
                            prev
                          </button>
                          <span className="text-[9px] font-mono text-[#6f7f9a]/50 px-1">
                            {sessionIndex + 1}/{sessionIds.length}
                          </span>
                          <button
                            onClick={handleNextSession}
                            disabled={sessionIndex >= sessionIds.length - 1}
                            className={cn(
                              "flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-medium transition-colors",
                              sessionIndex >= sessionIds.length - 1
                                ? "text-[#6f7f9a]/50 cursor-not-allowed"
                                : "text-[#6f7f9a] hover:text-[#ece7dc] hover:bg-[#131721]",
                            )}
                          >
                            next
                            <IconChevronRight size={12} stroke={1.5} />
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Timeline content */}
                  <div className="flex-1 overflow-y-auto px-5 py-4">
                    {sessionEvents.length === 0 ? (
                      <div className="flex h-full items-center justify-center">
                        <div className="flex flex-col items-center gap-3">
                          <IconAlertTriangle
                            size={20}
                            className="text-[#6f7f9a]/50"
                          />
                          <p className="text-[11px] text-[#6f7f9a]/40 max-w-[260px] text-center">
                            No events in scope. Add events from the Activity
                            Stream.
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="relative pl-6">
                        {/* Vertical connector line */}
                        <div className="absolute left-[7px] top-2 bottom-2 w-px bg-[#2d3240]/60" />

                        {sessionEvents.map((event, idx) => {
                          const ActionIcon =
                            ACTION_TYPE_ICONS[event.actionType] ?? IconFile;
                          const verdictStyle = VERDICT_STYLES[event.verdict];
                          const isSelected = selectedEventId === event.id;
                          const hasFlags = eventHasFlags(event);
                          const haloColor = eventHaloColor(event);

                          return (
                            <div
                              key={event.id}
                              className={cn(
                                "relative mb-1 cursor-pointer rounded-lg px-3 py-2.5 transition-colors",
                                isSelected
                                  ? "bg-[#131721] border border-[#d4a84b]/30"
                                  : "hover:bg-[#0b0d13]/80 border border-transparent",
                              )}
                              onClick={() => setSelectedEventId(event.id)}
                            >
                              {/* Timeline dot */}
                              <div
                                className={cn(
                                  "absolute -left-6 top-3.5 h-3.5 w-3.5 rounded-full border-2 bg-[#0b0d13] flex items-center justify-center",
                                  haloColor
                                    ? "border-current"
                                    : "border-[#2d3240]",
                                )}
                                style={
                                  haloColor
                                    ? {
                                        borderColor: haloColor,
                                        boxShadow: `0 0 6px ${haloColor}40`,
                                      }
                                    : undefined
                                }
                              >
                                <div
                                  className={cn(
                                    "h-1.5 w-1.5 rounded-full",
                                    anomalyScoreDot(event.anomalyScore),
                                  )}
                                />
                              </div>

                              <div className="flex items-start gap-3">
                                {/* Time */}
                                <span className="shrink-0 w-14 font-mono text-[10px] text-[#6f7f9a]/60 pt-0.5">
                                  {formatTime(event.timestamp)}
                                </span>

                                {/* Action icon */}
                                <div className="shrink-0 mt-0.5">
                                  <ActionIcon
                                    size={13}
                                    stroke={1.5}
                                    className="text-[#6f7f9a]/50"
                                  />
                                </div>

                                {/* Content */}
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono text-[10px] text-[#ece7dc]/60 truncate max-w-[200px]">
                                      {event.target}
                                    </span>
                                    <span
                                      className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
                                      style={{
                                        backgroundColor:
                                          verdictStyle.color + "15",
                                        color: verdictStyle.color,
                                      }}
                                    >
                                      {verdictStyle.label}
                                    </span>
                                    {hasFlags && (
                                      <IconAlertTriangle
                                        size={10}
                                        stroke={2}
                                        className="text-[#d4a84b] shrink-0"
                                      />
                                    )}
                                  </div>
                                  {event.content && (
                                    <p className="mt-0.5 text-[9px] text-[#6f7f9a]/40 truncate max-w-[300px]">
                                      {event.content}
                                    </p>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="flex h-full items-center justify-center">
                  <div className="flex flex-col items-center gap-3">
                    <IconFileAnalytics
                      size={24}
                      className="text-[#6f7f9a]/15"
                    />
                    <p className="text-[11px] text-[#6f7f9a]/30">
                      Select a case to view the session timeline
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* ------------------------------------------------------------- */}
            {/* RIGHT COLUMN: Receipt Inspector */}
            {/* ------------------------------------------------------------- */}
            <div className="w-72 shrink-0 border-l border-[#2d3240]/60 flex flex-col bg-[#0b0d13] max-lg:hidden">
              {/* Header */}
              <div className="shrink-0 px-4 py-3 border-b border-[#2d3240]/60">
                <span className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50">
                  Receipt Inspector
                </span>
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto px-4 py-3">
                {selectedEvent ? (
                  <motion.div
                    key={selectedEvent.id}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.15 }}
                    className="space-y-4"
                  >
                    {/* Event metadata */}
                    <section>
                      <SectionHeading>Event Metadata</SectionHeading>
                      <div className="space-y-1.5 mt-2">
                        <DetailRow
                          label="Action"
                          value={selectedEvent.actionType}
                          mono
                        />
                        <DetailRow
                          label="Target"
                          value={selectedEvent.target}
                          mono
                        />
                        {selectedEvent.content && (
                          <div className="mt-1">
                            <span className="text-[9px] text-[#6f7f9a]/50">
                              Content
                            </span>
                            <pre className="mt-0.5 rounded border border-[#2d3240]/60 bg-[#05060a] p-2 text-[9px] font-mono text-[#ece7dc]/50 overflow-auto max-h-[80px] whitespace-pre-wrap break-all">
                              {selectedEvent.content}
                            </pre>
                          </div>
                        )}
                        <DetailRow
                          label="Timestamp"
                          value={formatTimestamp(selectedEvent.timestamp)}
                        />
                        <DetailRow
                          label="Agent"
                          value={selectedEvent.agentName}
                        />
                        <DetailRow
                          label="Session"
                          value={selectedEvent.sessionId.slice(0, 12) + "..."}
                          mono
                        />
                        {selectedEvent.anomalyScore !== undefined && (
                          <div className="flex items-center gap-2 text-[10px]">
                            <span className="text-[#6f7f9a]/50 shrink-0 w-[70px]">
                              Anomaly
                            </span>
                            <div className="flex items-center gap-1.5">
                              <div className="w-16 h-1.5 rounded-full bg-[#2d3240] overflow-hidden">
                                <div
                                  className={cn(
                                    "h-full rounded-full transition-all",
                                    selectedEvent.anomalyScore >= 0.7
                                      ? "bg-[#c45c5c]"
                                      : selectedEvent.anomalyScore >= 0.4
                                        ? "bg-[#d4a84b]"
                                        : "bg-[#3dbf84]",
                                  )}
                                  style={{
                                    width: `${Math.round(selectedEvent.anomalyScore * 100)}%`,
                                  }}
                                />
                              </div>
                              <span className="font-mono text-[9px] text-[#ece7dc]/50">
                                {selectedEvent.anomalyScore.toFixed(2)}
                              </span>
                            </div>
                          </div>
                        )}
                      </div>
                    </section>

                    {/* Receipt card */}
                    <section>
                      <SectionHeading>Receipt</SectionHeading>
                      <div className="mt-2 rounded-lg border border-[#2d3240]/60 bg-[#05060a] p-3">
                        {selectedEvent.receiptId ? (
                          <div className="space-y-1.5">
                            <DetailRow
                              label="Receipt ID"
                              value={
                                selectedEvent.receiptId.slice(0, 12) + "..."
                              }
                              mono
                            />
                            <div className="flex items-center gap-2 text-[10px]">
                              <span className="text-[#6f7f9a]/50 shrink-0 w-[70px]">
                                Signature
                              </span>
                              <span className="flex items-center gap-1 text-[#3dbf84] font-mono text-[9px]">
                                <IconShieldCheck size={10} stroke={2} />
                                Ed25519
                              </span>
                            </div>
                            <DetailRow
                              label="Policy Hash"
                              value={
                                selectedEvent.policyVersion.slice(0, 16) + "..."
                              }
                              mono
                            />
                          </div>
                        ) : (
                          <div className="flex items-center gap-2">
                            <IconShieldX
                              size={12}
                              stroke={1.5}
                              className="text-[#6f7f9a]/40"
                            />
                            <span className="text-[10px] text-[#6f7f9a]/40">
                              No receipt
                            </span>
                          </div>
                        )}
                      </div>
                    </section>

                    {/* Guard evaluations */}
                    <section>
                      <SectionHeading>Guard Evaluations</SectionHeading>
                      <div className="mt-2 space-y-1">
                        {selectedEvent.guardResults.length > 0 ? (
                          selectedEvent.guardResults.map((gr, i) => (
                            <div
                              key={`${gr.guardId}-${i}`}
                              className="flex items-start gap-2 rounded-md border border-[#2d3240]/40 bg-[#05060a] px-2.5 py-2"
                            >
                              {gr.verdict === "allow" ? (
                                <IconCircleCheck
                                  size={11}
                                  stroke={2}
                                  className="text-[#3dbf84] shrink-0 mt-0.5"
                                />
                              ) : (
                                <IconCircleX
                                  size={11}
                                  stroke={2}
                                  className="text-[#c45c5c] shrink-0 mt-0.5"
                                />
                              )}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between">
                                  <span className="font-mono text-[9px] text-[#ece7dc]/70">
                                    {gr.guardName}
                                  </span>
                                  <span
                                    className="rounded px-1 py-0.5 text-[7px] font-semibold uppercase"
                                    style={{
                                      backgroundColor:
                                        VERDICT_STYLES[gr.verdict].color + "15",
                                      color: VERDICT_STYLES[gr.verdict].color,
                                    }}
                                  >
                                    {gr.verdict}
                                  </span>
                                </div>
                                <p className="text-[9px] text-[#6f7f9a]/50 mt-0.5 leading-relaxed">
                                  {gr.message}
                                </p>
                                {gr.evidence?.evaluation_ms !== undefined && (
                                  <span className="text-[8px] font-mono text-[#6f7f9a]/30 mt-0.5 block">
                                    {String(gr.evidence.evaluation_ms)}ms
                                  </span>
                                )}
                              </div>
                            </div>
                          ))
                        ) : (
                          <p className="text-[10px] text-[#6f7f9a]/30">
                            No guard evaluations available
                          </p>
                        )}
                      </div>
                    </section>

                    {/* Flags */}
                    {selectedEvent.flags.length > 0 && (
                      <section>
                        <SectionHeading>Flags</SectionHeading>
                        <div className="mt-2 space-y-1">
                          {selectedEvent.flags.map((flag, i) => (
                            <div
                              key={i}
                              className="flex items-center gap-2 rounded-md border border-[#2d3240]/40 bg-[#05060a] px-2.5 py-1.5"
                            >
                              {flag.type === "anomaly" && (
                                <>
                                  <IconAlertTriangle
                                    size={10}
                                    stroke={2}
                                    className="text-[#d4a84b] shrink-0"
                                  />
                                  <span className="text-[9px] text-[#ece7dc]/60 truncate">
                                    {flag.reason}
                                  </span>
                                  <span className="ml-auto text-[8px] font-mono text-[#d4a84b]">
                                    {flag.score.toFixed(2)}
                                  </span>
                                </>
                              )}
                              {flag.type === "escalated" && (
                                <>
                                  <IconCircleDot
                                    size={10}
                                    stroke={2}
                                    className="text-[#c45c5c] shrink-0"
                                  />
                                  <span className="text-[9px] text-[#ece7dc]/60 truncate">
                                    Escalated by {flag.by}
                                  </span>
                                </>
                              )}
                              {flag.type === "tag" && (
                                <>
                                  <span
                                    className="h-2 w-2 rounded-full shrink-0"
                                    style={{
                                      backgroundColor:
                                        flag.color ?? "#6f7f9a",
                                    }}
                                  />
                                  <span className="text-[9px] text-[#ece7dc]/60">
                                    {flag.label}
                                  </span>
                                </>
                              )}
                              {flag.type === "pattern-match" && (
                                <>
                                  <IconBrain
                                    size={10}
                                    stroke={2}
                                    className="text-[#d4a84b] shrink-0"
                                  />
                                  <span className="text-[9px] text-[#ece7dc]/60 truncate">
                                    {flag.patternName}
                                  </span>
                                </>
                              )}
                            </div>
                          ))}
                        </div>
                      </section>
                    )}
                  </motion.div>
                ) : (
                  <div className="flex h-full items-center justify-center">
                    <div className="flex flex-col items-center gap-2">
                      <IconShieldCheck
                        size={20}
                        className="text-[#6f7f9a]/15"
                      />
                      <p className="text-[10px] text-[#6f7f9a]/30 text-center max-w-[180px]">
                        Select an event from the timeline to inspect its receipt
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ----------------------------------------------------------------- */}
          {/* BOTTOM PANEL: Annotations */}
          {/* ----------------------------------------------------------------- */}
          {selectedCase && (
            <div
              className={cn(
                "shrink-0 border-t border-[#2d3240]/60 bg-[#0b0d13] flex flex-col transition-all",
                annotationsExpanded ? "h-40" : "h-8",
              )}
            >
              {/* Annotations header */}
              <div className="shrink-0 px-4 py-1.5 flex items-center justify-between border-b border-[#2d3240]/40">
                <button
                  onClick={() => setAnnotationsExpanded((v) => !v)}
                  className="flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors"
                >
                  {annotationsExpanded ? (
                    <IconChevronDown size={10} stroke={2} />
                  ) : (
                    <IconChevronUp size={10} stroke={2} />
                  )}
                  Annotations
                  <span className="text-[#6f7f9a]/30 font-mono">
                    ({selectedCase.annotations.length})
                  </span>
                </button>
                <div className="flex items-center gap-2">
                  {annotationsExpanded && (
                    <button
                      onClick={() => setShowAnnotationInput((v) => !v)}
                      className="flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/10 transition-colors"
                    >
                      <IconPlus size={10} stroke={2} />
                      Add
                    </button>
                  )}
                </div>
              </div>

              {/* Annotations body (only when expanded) */}
              {annotationsExpanded && (
                <div className="flex flex-1 min-h-0 flex-col">
                  {/* Annotation list */}
                  <div className="flex-1 overflow-y-auto px-4 py-2 space-y-1.5">
                    {selectedCase.annotations.length === 0 &&
                      !showAnnotationInput && (
                        <p className="text-[10px] text-[#6f7f9a]/30 text-center py-2">
                          No annotations yet
                        </p>
                      )}
                    {selectedCase.annotations.map((ann) => (
                      <AnnotationRow key={ann.id} annotation={ann} />
                    ))}

                    {/* Add annotation form */}
                    {showAnnotationInput && (
                      <div className="flex items-start gap-2 mt-1">
                        <input
                          type="text"
                          value={annotationText}
                          onChange={(e) => setAnnotationText(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleAddAnnotation();
                            if (e.key === "Escape") {
                              setShowAnnotationInput(false);
                              setAnnotationText("");
                            }
                          }}
                          placeholder="Add a note..."
                          autoFocus
                          className="flex-1 rounded-md border border-[#2d3240] bg-[#05060a] px-2 py-1.5 text-[10px] text-[#ece7dc] placeholder:text-[#6f7f9a]/40 outline-none focus:border-[#d4a84b]/50 transition-colors"
                        />
                        <button
                          onClick={handleAddAnnotation}
                          disabled={!annotationText.trim()}
                          className={cn(
                            "rounded-md px-2.5 py-1.5 text-[10px] font-medium transition-colors",
                            annotationText.trim()
                              ? "bg-[#d4a84b]/10 text-[#d4a84b] hover:bg-[#d4a84b]/20 border border-[#d4a84b]/20"
                              : "text-[#6f7f9a]/30 cursor-not-allowed border border-[#2d3240]/50",
                          )}
                        >
                          <IconCheck size={12} stroke={2} />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Case resolution bar */}
                  <div className="shrink-0 px-4 py-2 border-t border-[#2d3240]/40 flex items-center gap-3">
                    {/* Verdict dropdown */}
                    <div className="flex items-center gap-1.5">
                      <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40">
                        Verdict
                      </span>
                      <select
                        value={selectedCase.verdict ?? ""}
                        onChange={(e) => {
                          if (e.target.value) {
                            handleVerdictChange(
                              e.target.value as InvestigationVerdict,
                            );
                          }
                        }}
                        className="rounded-md border border-[#2d3240] bg-[#05060a] px-2 py-1 text-[10px] text-[#ece7dc] outline-none focus:border-[#d4a84b]/50 transition-colors"
                      >
                        <option value="">-- Select --</option>
                        {VERDICT_OPTIONS.map((v) => (
                          <option key={v.value} value={v.value}>
                            {v.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Separator */}
                    <div className="h-4 w-px bg-[#2d3240]/60" />

                    {/* Action checkboxes */}
                    <div className="flex items-center gap-3">
                      {ACTION_OPTIONS.map((ao) => {
                        const isChecked =
                          selectedCase.actions?.includes(ao.value) ?? false;
                        return (
                          <label
                            key={ao.value}
                            className="flex items-center gap-1 cursor-pointer"
                          >
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => handleActionToggle(ao.value)}
                              className="h-3 w-3 rounded border-[#2d3240] bg-[#05060a] accent-[#d4a84b]"
                            />
                            <span
                              className={cn(
                                "text-[9px]",
                                isChecked
                                  ? "text-[#ece7dc]/70"
                                  : "text-[#6f7f9a]/40",
                              )}
                            >
                              {ao.label}
                            </span>
                          </label>
                        );
                      })}
                    </div>

                    {/* Draft Detection button */}
                    {onDraftDetection && selectedCase && (
                      <>
                        <div className="h-4 w-px bg-[#2d3240]/60" />
                        <button
                          data-testid="investigation-draft-detection"
                          onClick={() =>
                            onDraftDetection(
                              selectedCase,
                              events.filter(
                                (event) =>
                                  selectedCase.eventIds.includes(event.id) ||
                                  selectedCase.sessionIds.includes(event.sessionId),
                              ),
                            )
                          }
                          className="flex items-center gap-1.5 rounded-md border border-[#7c9aef]/25 bg-[#7c9aef]/10 px-2.5 py-1 text-[10px] font-medium text-[#7c9aef] hover:bg-[#7c9aef]/20 transition-colors"
                        >
                          <IconShieldPlus size={12} stroke={1.5} />
                          Draft Detection
                        </button>
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ----------------------------------------------------------------- */}
          {/* COVERAGE GAPS PANEL */}
          {/* ----------------------------------------------------------------- */}
          {selectedCase && (
            <InvestigationCoverageGaps
              investigation={selectedCase}
              events={events}
              onDraftDetection={onDraftDetection}
              openDocumentCoverage={openDocumentCoverage}
              publishedCoverage={publishedCoverage}
            />
          )}
        </div>
      </div>
    </div>
  );
}


function InvestigationCoverageGaps({
  investigation,
  events,
  onDraftDetection,
  openDocumentCoverage,
  publishedCoverage,
}: {
  investigation: Investigation;
  events: AgentEvent[];
  onDraftDetection?: (
    investigation: Investigation,
    scopeEvents?: AgentEvent[],
    selectedGap?: CoverageGapCandidate,
  ) => void;
  openDocumentCoverage?: DocumentCoverageEntry[];
  publishedCoverage?: DocumentCoverageEntry[];
}) {
  const [expanded, setExpanded] = useState(false);

  // Gather events in scope for this investigation
  const scopeEvents = useMemo(
    () =>
      events.filter(
        (e) =>
          investigation.eventIds.includes(e.id) ||
          investigation.sessionIds.includes(e.sessionId),
      ),
    [events, investigation.eventIds, investigation.sessionIds],
  );

  const gapInput = useMemo<CoverageGapInput>(
    () => ({
      events: scopeEvents,
      investigations: [investigation],
      openDocumentCoverage,
      publishedCoverage,
    }),
    [investigation, openDocumentCoverage, publishedCoverage, scopeEvents],
  );

  const { gaps, dismiss, draftFromGap } = useCoverageGaps(gapInput, {
    onDraftFromGap: onDraftDetection
      ? (gap) => onDraftDetection(investigation, scopeEvents, gap)
      : undefined,
    persistenceKey: `clawdstrike_gap_dismissals_investigation_${investigation.id}`,
  });

  if (gaps.length === 0) return null;

  return (
    <div
      className={cn(
        "shrink-0 border-t border-[#2d3240]/60 bg-[#0b0d13] flex flex-col transition-all",
        expanded ? "max-h-48" : "h-8",
      )}
    >
      <div className="shrink-0 px-4 py-1.5 flex items-center justify-between border-b border-[#2d3240]/40">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-1.5 text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 hover:text-[#ece7dc] transition-colors"
        >
          {expanded ? (
            <IconChevronDown size={10} stroke={2} />
          ) : (
            <IconChevronUp size={10} stroke={2} />
          )}
          <IconTarget size={10} stroke={1.5} className="text-[#d4a84b]/60" />
          Coverage Gaps
          <span className="text-[#6f7f9a]/30 font-mono">
            ({gaps.length})
          </span>
        </button>
      </div>

      {expanded && (
        <div className="flex-1 overflow-y-auto px-4 py-2 space-y-2">
          {gaps.map((gap) => (
            <CoverageGapCard
              key={gap.id}
              gap={gap}
              compact
              onDraft={() => draftFromGap(gap)}
              onDismiss={() => dismiss(gap.id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}


function CaseCard({
  investigation,
  displayId,
  isSelected,
  agentCount,
  onClick,
}: {
  investigation: Investigation;
  displayId: string;
  isSelected: boolean;
  agentCount: number;
  onClick: () => void;
}) {
  const sevColor = SEVERITY_COLORS[investigation.severity];

  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full text-left px-3 py-2.5 border-b border-[#2d3240]/30 transition-colors",
        isSelected
          ? "bg-[#131721] border-l-2 border-l-[#d4a84b]"
          : "hover:bg-[#131721]/50 border-l-2 border-l-transparent",
      )}
    >
      <div className="flex items-center gap-1.5 mb-1">
        <span className="font-mono text-[9px] text-[#6f7f9a]/50">
          {displayId}
        </span>
        <span
          className="shrink-0 rounded px-1.5 py-0.5 text-[7px] font-bold uppercase"
          style={{
            backgroundColor: sevColor + "15",
            color: sevColor,
          }}
        >
          {SEVERITY_LABELS[investigation.severity]}
        </span>
        <span className="ml-auto">
          {statusIcon(investigation.status)}
        </span>
      </div>
      <p className="text-[10px] text-[#ece7dc]/70 truncate leading-snug">
        {investigation.title}
      </p>
      <div className="flex items-center gap-2 mt-1">
        <span className="flex items-center gap-0.5 text-[8px] text-[#6f7f9a]/40">
          <IconUser size={8} stroke={1.5} />
          {agentCount}
        </span>
        <span className="text-[8px] text-[#6f7f9a]/30 font-mono">
          {formatDate(investigation.createdAt)}
        </span>
      </div>
    </button>
  );
}

function AnnotationRow({ annotation }: { annotation: Annotation }) {
  return (
    <div className="flex items-start gap-2 rounded-md bg-[#05060a] border border-[#2d3240]/40 px-2.5 py-2">
      <IconNote
        size={11}
        stroke={1.5}
        className="text-[#6f7f9a]/30 shrink-0 mt-0.5"
      />
      <div className="flex-1 min-w-0">
        <p className="text-[10px] text-[#ece7dc]/60 leading-relaxed break-words">
          {annotation.text}
        </p>
        <div className="flex items-center gap-2 mt-1">
          <span className="text-[8px] text-[#6f7f9a]/30">
            {annotation.createdBy}
          </span>
          <span className="text-[8px] text-[#6f7f9a]/50 font-mono">
            {formatTimestamp(annotation.createdAt)}
          </span>
        </div>
      </div>
    </div>
  );
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="font-syne text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50">
      {children}
    </h3>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline gap-2 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[70px]">{label}</span>
      <span
        className={cn("text-[#ece7dc]/70 truncate", mono && "font-mono text-[9px]")}
      >
        {value}
      </span>
    </div>
  );
}
