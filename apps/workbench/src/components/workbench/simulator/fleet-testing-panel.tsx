import { useState, useCallback, useMemo } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { VerdictBadge } from "@/components/workbench/shared/verdict-badge";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";
import { simulatePolicy } from "@/lib/workbench/simulation-engine";
import {
  fetchAuditEvents,
  type AuditEvent,
} from "@/lib/workbench/fleet-client";
import {
  auditEventsToScenarios,
  summarizeTraffic,
  identifyCoverageGaps,
  type TrafficSummary,
  type CoverageGap,
} from "@/lib/workbench/traffic-replay";
import type { TestScenario, SimulationResult, Verdict } from "@/lib/workbench/types";
import {
  IconCloudDownload,
  IconPlayerPlay,
  IconRadar,
  IconArrowsExchange,
  IconAlertTriangle,
  IconCircleCheck,
  IconCircleX,
  IconCircle,
  IconShieldCheck,
  IconPlugConnectedX,
  IconSettings,
  IconChevronDown,
  IconChevronRight,
  IconClock,
} from "@tabler/icons-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type TimeRange = "1h" | "24h" | "7d";

interface WhatIfResult {
  totalScenarios: number;
  productionAllow: number;
  productionDeny: number;
  productionWarn: number;
  draftAllow: number;
  draftDeny: number;
  draftWarn: number;
  changedCount: number;
  deltas: Array<{
    scenarioId: string;
    scenarioName: string;
    target: string;
    productionDecision: Verdict;
    draftDecision: Verdict;
    changed: boolean;
  }>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sinceForRange(range: TimeRange): string {
  const now = new Date();
  switch (range) {
    case "1h":
      return new Date(now.getTime() - 60 * 60 * 1000).toISOString();
    case "24h":
      return new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    case "7d":
      return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();
  }
}

function countVerdict(
  scenarios: TestScenario[],
  verdict: Verdict,
): number {
  return scenarios.filter((s) => s.expectedVerdict === verdict).length;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ConnectionBadge({ connected }: { connected: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0 text-[9px] font-mono uppercase border rounded select-none tracking-wide",
        connected
          ? "text-[#3dbf84] border-[#3dbf84]/20 bg-[#3dbf84]/10"
          : "text-[#6f7f9a] border-[#2d3240] bg-[#131721]",
      )}
    >
      <IconCircle
        size={5}
        stroke={0}
        fill={connected ? "#3dbf84" : "#6f7f9a"}
      />
      {connected ? "connected" : "offline"}
    </span>
  );
}

function HorizontalBar({
  items,
}: {
  items: Array<{ label: string; value: number; color: string }>;
}) {
  const total = items.reduce((sum, item) => sum + item.value, 0);
  if (total === 0) return null;

  return (
    <div className="space-y-1.5">
      {items.map((item) => {
        const pct = Math.round((item.value / total) * 100);
        return (
          <div key={item.label} className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-[#6f7f9a] w-[100px] truncate text-right shrink-0">
              {item.label}
            </span>
            <div className="flex-1 h-3 rounded-full bg-[#131721] border border-[#2d3240]/50 overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${Math.max(pct, 1)}%`,
                  backgroundColor: item.color,
                }}
              />
            </div>
            <span className="text-[10px] font-mono text-[#6f7f9a] w-[36px] text-right shrink-0">
              {pct}%
            </span>
            <span className="text-[10px] font-mono text-[#6f7f9a]/50 w-[30px] text-right shrink-0">
              {item.value}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function DecisionSegments({
  allow,
  deny,
  warn,
  label,
}: {
  allow: number;
  deny: number;
  warn: number;
  label: string;
}) {
  const total = allow + deny + warn;
  if (total === 0) return null;

  const pctAllow = Math.round((allow / total) * 100);
  const pctDeny = Math.round((deny / total) * 100);
  const pctWarn = Math.round((warn / total) * 100);

  return (
    <div>
      <div className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-1.5">
        {label}
      </div>
      <div className="h-3 rounded-full overflow-hidden flex bg-[#131721] border border-[#2d3240]">
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
      <div className="flex items-center gap-3 mt-1.5 text-[10px] font-mono">
        <span className="text-[#3dbf84]">{allow} allow</span>
        <span className="text-[#d4a84b]">{warn} warn</span>
        <span className="text-[#c45c5c]">{deny} deny</span>
      </div>
    </div>
  );
}

function GapCard({ gap }: { gap: CoverageGap }) {
  const severityColor =
    gap.severity === "high"
      ? "#c45c5c"
      : gap.severity === "medium"
        ? "#d4a84b"
        : "#6f7f9a";

  return (
    <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg border border-[#2d3240] bg-[#0b0d13]">
      <IconAlertTriangle
        size={14}
        stroke={1.5}
        style={{ color: severityColor }}
        className="shrink-0 mt-0.5"
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[11px] font-medium text-[#ece7dc]">
            Enable {gap.guardName}
          </span>
          <span
            className="text-[9px] font-mono uppercase px-1.5 py-0 border rounded"
            style={{
              color: severityColor,
              borderColor: `${severityColor}33`,
              backgroundColor: `${severityColor}15`,
            }}
          >
            {gap.severity}
          </span>
        </div>
        <p className="text-[10px] text-[#6f7f9a] leading-relaxed">
          {gap.message}
        </p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Disconnected State
// ---------------------------------------------------------------------------

function DisconnectedState() {
  return (
    <div className="flex flex-col items-center justify-center h-full px-8">
      <div className="w-16 h-16 rounded-2xl bg-[#131721] border border-[#2d3240]/60 flex items-center justify-center mb-5">
        <IconPlugConnectedX
          size={24}
          stroke={1.2}
          className="text-[#6f7f9a]"
        />
      </div>
      <span className="text-[14px] font-medium text-[#6f7f9a] mb-1.5">
        Fleet not connected
      </span>
      <span className="text-[12px] text-[#6f7f9a]/60 text-center leading-relaxed max-w-[320px] mb-4">
        Connect to a running hushd instance to import production audit events
        and run what-if analysis against your draft policy.
      </span>
      <div className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-[#2d3240] bg-[#131721] text-[#6f7f9a] text-[11px]">
        <IconSettings size={13} stroke={1.5} />
        Configure connection in Fleet Settings
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Panel
// ---------------------------------------------------------------------------

export function FleetTestingPanel() {
  const { connection } = useFleetConnection();
  const { state } = useWorkbench();
  const { toast } = useToast();

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [scenarios, setScenarios] = useState<TestScenario[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedRange, setSelectedRange] = useState<TimeRange>("24h");
  const [whatIfResult, setWhatIfResult] = useState<WhatIfResult | null>(null);
  const [runningWhatIf, setRunningWhatIf] = useState(false);
  const [expandedSection, setExpandedSection] = useState<string | null>(
    "import",
  );

  // Derived data
  const trafficSummary: TrafficSummary | null = useMemo(
    () => (auditEvents.length > 0 ? summarizeTraffic(auditEvents) : null),
    [auditEvents],
  );

  const coverageGaps: CoverageGap[] = useMemo(
    () =>
      auditEvents.length > 0
        ? identifyCoverageGaps(auditEvents, state.activePolicy)
        : [],
    [auditEvents, state.activePolicy],
  );

  // Action type chart items
  const actionTypeItems = useMemo(() => {
    if (!trafficSummary) return [];
    const colors: Record<string, string> = {
      file_access: "#3dbf84",
      file_write: "#3dbf84",
      file_read: "#3dbf84",
      network_egress: "#6f7f9a",
      network: "#6f7f9a",
      shell_command: "#d4a84b",
      shell: "#d4a84b",
      mcp_tool_call: "#c45c5c",
      mcp_tool: "#c45c5c",
      patch_apply: "#6f7f9a",
      user_input: "#d4a84b",
    };
    return Object.entries(trafficSummary.byActionType)
      .sort(([, a], [, b]) => b - a)
      .map(([label, value]) => ({
        label,
        value,
        color: colors[label] ?? "#6f7f9a",
      }));
  }, [trafficSummary]);

  // Guard frequency chart items
  const guardItems = useMemo(() => {
    if (!trafficSummary) return [];
    return Object.entries(trafficSummary.byGuard)
      .sort(([, a], [, b]) => b - a)
      .map(([label, value]) => ({
        label,
        value,
        color: "#d4a84b",
      }));
  }, [trafficSummary]);

  // ---------- Handlers ----------

  const handleFetchEvents = useCallback(async () => {
    if (!connection.connected) return;
    setLoading(true);
    try {
      const since = sinceForRange(selectedRange);
      const events = await fetchAuditEvents(connection, {
        since,
        limit: 500,
      });
      setAuditEvents(events);
      setScenarios([]);
      setWhatIfResult(null);
      toast({
        type: events.length > 0 ? "success" : "info",
        title:
          events.length > 0
            ? `Fetched ${events.length} audit event(s)`
            : "No events found",
        description:
          events.length > 0
            ? `Last ${selectedRange} from ${connection.hushdUrl}`
            : `No audit events in the last ${selectedRange}`,
      });
    } catch (err) {
      toast({
        type: "error",
        title: "Failed to fetch audit events",
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setLoading(false);
    }
  }, [connection, selectedRange, toast]);

  const handleConvertToScenarios = useCallback(() => {
    const converted = auditEventsToScenarios(auditEvents);
    setScenarios(converted);
    setWhatIfResult(null);
    toast({
      type: "success",
      title: `Converted ${converted.length} scenario(s)`,
      description: "Ready for what-if analysis",
    });
  }, [auditEvents, toast]);

  const handleRunWhatIf = useCallback(() => {
    if (scenarios.length === 0) return;
    setRunningWhatIf(true);

    // Use setTimeout to avoid blocking the UI on large scenario sets
    setTimeout(() => {
      try {
        const results: SimulationResult[] = [];
        for (const s of scenarios) {
          results.push(simulatePolicy(state.activePolicy, s));
        }

        // Build deltas
        const deltas = scenarios.map((s, i) => {
          const draftVerdict = results[i].overallVerdict;
          const prodVerdict = s.expectedVerdict ?? "allow";
          return {
            scenarioId: s.id,
            scenarioName: s.name,
            target:
              (s.payload.path as string) ??
              (s.payload.host as string) ??
              (s.payload.command as string) ??
              (s.payload.tool as string) ??
              "unknown",
            productionDecision: prodVerdict,
            draftDecision: draftVerdict,
            changed: prodVerdict !== draftVerdict,
          };
        });

        const whatIf: WhatIfResult = {
          totalScenarios: scenarios.length,
          productionAllow: countVerdict(scenarios, "allow"),
          productionDeny: countVerdict(scenarios, "deny"),
          productionWarn: countVerdict(scenarios, "warn"),
          draftAllow: results.filter((r) => r.overallVerdict === "allow").length,
          draftDeny: results.filter((r) => r.overallVerdict === "deny").length,
          draftWarn: results.filter((r) => r.overallVerdict === "warn").length,
          changedCount: deltas.filter((d) => d.changed).length,
          deltas,
        };

        setWhatIfResult(whatIf);
        toast({
          type: "info",
          title: `What-if complete -- ${whatIf.changedCount} verdict(s) changed`,
          description: `${whatIf.totalScenarios} production scenarios replayed against draft policy`,
        });
      } finally {
        setRunningWhatIf(false);
      }
    }, 10);
  }, [scenarios, state.activePolicy, toast]);

  const toggleSection = useCallback(
    (section: string) => {
      setExpandedSection((prev) => (prev === section ? null : section));
    },
    [],
  );

  // ---------- Disconnected state ----------

  if (!connection.connected) {
    return <DisconnectedState />;
  }

  // ---------- Connected state ----------

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <IconRadar size={14} stroke={1.5} className="text-[#d4a84b]" />
        <span className="text-xs font-syne font-bold text-[#ece7dc]">
          Fleet Testing
        </span>
        <ConnectionBadge connected={connection.connected} />
        <span className="text-[10px] font-mono text-[#6f7f9a]">
          {connection.hushdUrl}
        </span>
        <div className="flex-1" />
        {auditEvents.length > 0 && (
          <span className="text-[10px] font-mono text-[#6f7f9a]">
            {auditEvents.length} event{auditEvents.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      <ScrollArea className="flex-1 overflow-y-auto">
        <div className="p-4 space-y-3">
          {/* ---- Section: Import from Production ---- */}
          <div className="rounded-lg border border-[#2d3240] bg-[#0b0d13]/50 overflow-hidden">
            <button
              onClick={() => toggleSection("import")}
              className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-[#131721]/40 transition-colors"
            >
              {expandedSection === "import" ? (
                <IconChevronDown
                  size={12}
                  stroke={2}
                  className="text-[#6f7f9a] shrink-0"
                />
              ) : (
                <IconChevronRight
                  size={12}
                  stroke={2}
                  className="text-[#6f7f9a] shrink-0"
                />
              )}
              <IconCloudDownload
                size={14}
                stroke={1.5}
                className="text-[#d4a84b]"
              />
              <span className="text-[11px] font-syne font-bold text-[#ece7dc]">
                Import from Production
              </span>
            </button>

            {expandedSection === "import" && (
              <div className="px-4 pb-4 space-y-4">
                {/* Time range + fetch */}
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-[#6f7f9a] uppercase tracking-wider">
                    Range:
                  </span>
                  {(["1h", "24h", "7d"] as TimeRange[]).map((range) => (
                    <button
                      key={range}
                      onClick={() => setSelectedRange(range)}
                      className={cn(
                        "flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-mono transition-colors",
                        selectedRange === range
                          ? "bg-[#d4a84b]/15 text-[#d4a84b] border border-[#d4a84b]/20"
                          : "text-[#6f7f9a] border border-[#2d3240] hover:text-[#ece7dc] hover:border-[#2d3240]",
                      )}
                    >
                      <IconClock size={10} stroke={1.5} />
                      {range}
                    </button>
                  ))}
                  <div className="flex-1" />
                  <button
                    onClick={handleFetchEvents}
                    disabled={loading}
                    className={cn(
                      "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-medium transition-colors",
                      loading
                        ? "bg-[#131721] text-[#6f7f9a] cursor-wait"
                        : "bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] hover:bg-[#d4a84b]/20",
                    )}
                  >
                    <IconCloudDownload
                      size={13}
                      stroke={1.5}
                      className={loading ? "animate-pulse" : ""}
                    />
                    {loading ? "Fetching..." : "Fetch Events"}
                  </button>
                </div>

                {/* Traffic Summary */}
                {trafficSummary && (
                  <div className="space-y-4">
                    {/* Stats row */}
                    <div className="grid grid-cols-3 gap-2">
                      <div className="flex flex-col items-center px-2 py-2 rounded-lg border border-[#2d3240] bg-[#131721]">
                        <span className="text-lg font-mono font-bold text-[#ece7dc]">
                          {trafficSummary.totalEvents}
                        </span>
                        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mt-0.5">
                          Total Events
                        </span>
                      </div>
                      <div className="flex flex-col items-center px-2 py-2 rounded-lg border border-[#2d3240] bg-[#131721]">
                        <span className="text-lg font-mono font-bold text-[#ece7dc]">
                          {Object.keys(trafficSummary.byActionType).length}
                        </span>
                        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mt-0.5">
                          Action Types
                        </span>
                      </div>
                      <div className="flex flex-col items-center px-2 py-2 rounded-lg border border-[#2d3240] bg-[#131721]">
                        <span className="text-lg font-mono font-bold text-[#ece7dc]">
                          {Object.keys(trafficSummary.byGuard).length}
                        </span>
                        <span className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mt-0.5">
                          Guards Hit
                        </span>
                      </div>
                    </div>

                    {/* Action type breakdown */}
                    {actionTypeItems.length > 0 && (
                      <div>
                        <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                          Traffic by Action Type
                        </h4>
                        <HorizontalBar items={actionTypeItems} />
                      </div>
                    )}

                    {/* Decision breakdown */}
                    <DecisionSegments
                      allow={trafficSummary.byDecision["allow"] ?? trafficSummary.byDecision["allowed"] ?? 0}
                      deny={trafficSummary.byDecision["deny"] ?? trafficSummary.byDecision["denied"] ?? trafficSummary.byDecision["blocked"] ?? 0}
                      warn={trafficSummary.byDecision["warn"] ?? trafficSummary.byDecision["warning"] ?? 0}
                      label="Decision Breakdown"
                    />

                    {/* Guard hit frequency */}
                    {guardItems.length > 0 && (
                      <div>
                        <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                          Guard Hit Frequency
                        </h4>
                        <HorizontalBar items={guardItems} />
                      </div>
                    )}

                    {/* Convert button */}
                    <button
                      onClick={handleConvertToScenarios}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#d4a84b]/10 border border-[#d4a84b]/20 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
                    >
                      <IconArrowsExchange size={14} stroke={1.5} />
                      Convert to {auditEvents.length} Scenario
                      {auditEvents.length !== 1 ? "s" : ""}
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ---- Section: What-If Analysis ---- */}
          {scenarios.length > 0 && (
            <div className="rounded-lg border border-[#2d3240] bg-[#0b0d13]/50 overflow-hidden">
              <button
                onClick={() => toggleSection("whatif")}
                className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-[#131721]/40 transition-colors"
              >
                {expandedSection === "whatif" ? (
                  <IconChevronDown
                    size={12}
                    stroke={2}
                    className="text-[#6f7f9a] shrink-0"
                  />
                ) : (
                  <IconChevronRight
                    size={12}
                    stroke={2}
                    className="text-[#6f7f9a] shrink-0"
                  />
                )}
                <IconPlayerPlay
                  size={14}
                  stroke={1.5}
                  className="text-[#3dbf84]"
                />
                <span className="text-[11px] font-syne font-bold text-[#ece7dc]">
                  What-If Analysis
                </span>
                <span className="text-[10px] font-mono text-[#6f7f9a]">
                  {scenarios.length} scenario
                  {scenarios.length !== 1 ? "s" : ""}
                </span>
              </button>

              {expandedSection === "whatif" && (
                <div className="px-4 pb-4 space-y-4">
                  {/* Run button */}
                  <button
                    onClick={handleRunWhatIf}
                    disabled={runningWhatIf}
                    className={cn(
                      "w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-[11px] font-medium transition-colors",
                      runningWhatIf
                        ? "bg-[#131721] text-[#6f7f9a] cursor-wait"
                        : "bg-[#3dbf84]/10 border border-[#3dbf84]/20 text-[#3dbf84] hover:bg-[#3dbf84]/20",
                    )}
                  >
                    <IconPlayerPlay
                      size={14}
                      stroke={1.5}
                      className={runningWhatIf ? "animate-pulse" : ""}
                    />
                    {runningWhatIf
                      ? "Running..."
                      : `Run What-If (${scenarios.length} scenarios)`}
                  </button>

                  {/* Results comparison */}
                  {whatIfResult && (
                    <div className="space-y-4">
                      {/* Summary comparison */}
                      <div className="grid grid-cols-2 gap-3">
                        <div className="rounded-lg border border-[#2d3240] bg-[#131721] p-3">
                          <div className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                            Production
                          </div>
                          <div className="flex items-center gap-2 text-[11px] font-mono">
                            <span className="text-[#3dbf84]">
                              {whatIfResult.productionAllow} allow
                            </span>
                            <span className="text-[#d4a84b]">
                              {whatIfResult.productionWarn} warn
                            </span>
                            <span className="text-[#c45c5c]">
                              {whatIfResult.productionDeny} deny
                            </span>
                          </div>
                        </div>
                        <div className="rounded-lg border border-[#2d3240] bg-[#131721] p-3">
                          <div className="text-[9px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                            Draft Policy
                          </div>
                          <div className="flex items-center gap-2 text-[11px] font-mono">
                            <span className="text-[#3dbf84]">
                              {whatIfResult.draftAllow} allow
                            </span>
                            <span className="text-[#d4a84b]">
                              {whatIfResult.draftWarn} warn
                            </span>
                            <span className="text-[#c45c5c]">
                              {whatIfResult.draftDeny} deny
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Change count badge */}
                      <div
                        className={cn(
                          "flex items-center justify-center gap-2 py-2.5 rounded-lg border",
                          whatIfResult.changedCount > 0
                            ? "border-[#d4a84b]/20 bg-[#d4a84b]/5"
                            : "border-[#3dbf84]/20 bg-[#3dbf84]/5",
                        )}
                      >
                        {whatIfResult.changedCount > 0 ? (
                          <>
                            <IconAlertTriangle
                              size={14}
                              stroke={1.5}
                              className="text-[#d4a84b]"
                            />
                            <span className="text-[11px] font-medium text-[#d4a84b]">
                              {whatIfResult.changedCount} verdict
                              {whatIfResult.changedCount !== 1 ? "s" : ""}{" "}
                              changed
                            </span>
                          </>
                        ) : (
                          <>
                            <IconCircleCheck
                              size={14}
                              stroke={1.5}
                              className="text-[#3dbf84]"
                            />
                            <span className="text-[11px] font-medium text-[#3dbf84]">
                              No verdict changes -- draft matches production
                            </span>
                          </>
                        )}
                      </div>

                      {/* Delta list (changed only, or all if none changed) */}
                      {whatIfResult.changedCount > 0 && (
                        <div>
                          <h4 className="text-[10px] font-mono uppercase tracking-wider text-[#6f7f9a] mb-2">
                            Changed Verdicts
                          </h4>
                          <div className="space-y-1 max-h-60 overflow-y-auto rounded-lg border border-[#2d3240] bg-[#131721]">
                            {whatIfResult.deltas
                              .filter((d) => d.changed)
                              .map((delta) => (
                                <div
                                  key={delta.scenarioId}
                                  className="flex items-center gap-2 px-3 py-2 border-b border-[#2d3240]/40 last:border-b-0"
                                >
                                  <span className="text-[10px] font-mono text-[#ece7dc] flex-1 min-w-0 truncate">
                                    {delta.target}
                                  </span>
                                  <VerdictBadge
                                    verdict={delta.productionDecision}
                                  />
                                  <IconArrowsExchange
                                    size={10}
                                    stroke={1.5}
                                    className="text-[#6f7f9a] shrink-0"
                                  />
                                  <VerdictBadge
                                    verdict={delta.draftDecision}
                                  />
                                  {delta.draftDecision === "deny" &&
                                  delta.productionDecision !== "deny" ? (
                                    <IconCircleX
                                      size={12}
                                      stroke={1.5}
                                      className="text-[#c45c5c] shrink-0"
                                    />
                                  ) : (
                                    <IconShieldCheck
                                      size={12}
                                      stroke={1.5}
                                      className="text-[#3dbf84] shrink-0"
                                    />
                                  )}
                                </div>
                              ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ---- Section: Coverage Gap Report ---- */}
          {auditEvents.length > 0 && (
            <div className="rounded-lg border border-[#2d3240] bg-[#0b0d13]/50 overflow-hidden">
              <button
                onClick={() => toggleSection("gaps")}
                className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-[#131721]/40 transition-colors"
              >
                {expandedSection === "gaps" ? (
                  <IconChevronDown
                    size={12}
                    stroke={2}
                    className="text-[#6f7f9a] shrink-0"
                  />
                ) : (
                  <IconChevronRight
                    size={12}
                    stroke={2}
                    className="text-[#6f7f9a] shrink-0"
                  />
                )}
                <IconShieldCheck
                  size={14}
                  stroke={1.5}
                  className={
                    coverageGaps.length > 0
                      ? "text-[#c45c5c]"
                      : "text-[#3dbf84]"
                  }
                />
                <span className="text-[11px] font-syne font-bold text-[#ece7dc]">
                  Coverage Gap Report
                </span>
                {coverageGaps.length > 0 && (
                  <span className="text-[9px] font-mono uppercase px-1.5 py-0 border rounded text-[#c45c5c] border-[#c45c5c]/20 bg-[#c45c5c]/10">
                    {coverageGaps.length} gap
                    {coverageGaps.length !== 1 ? "s" : ""}
                  </span>
                )}
              </button>

              {expandedSection === "gaps" && (
                <div className="px-4 pb-4 space-y-2">
                  {coverageGaps.length === 0 ? (
                    <div className="flex items-center gap-2 px-3 py-3 rounded-lg border border-[#3dbf84]/20 bg-[#3dbf84]/5">
                      <IconCircleCheck
                        size={14}
                        stroke={1.5}
                        className="text-[#3dbf84]"
                      />
                      <span className="text-[11px] text-[#3dbf84]">
                        All production action types have corresponding guards
                        enabled
                      </span>
                    </div>
                  ) : (
                    coverageGaps.map((gap, i) => (
                      <GapCard key={`${gap.guardId}-${i}`} gap={gap} />
                    ))
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
