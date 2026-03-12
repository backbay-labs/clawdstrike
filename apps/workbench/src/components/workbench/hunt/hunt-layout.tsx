import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import type { AgentEvent, AgentBaseline, Investigation, HuntPattern, StreamFilters, StreamStats } from "@/lib/workbench/hunt-types";
import {
  auditEventToAgentEvent,
  enrichEvents,
  computeBaseline,
  computeStreamStats,
  timeRangeToSince,
} from "@/lib/workbench/hunt-engine";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { fetchAuditEvents } from "@/lib/workbench/fleet-client";
import {
  IconActivity,
  IconChartBar,
  IconSearch,
  IconBrain,
  IconCircle,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { ActivityStream } from "./activity-stream";
import { Baselines } from "./baselines";
import { InvestigationWorkbench } from "./investigation";
import { PatternMining } from "./pattern-mining";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type HuntTab = "stream" | "baselines" | "investigate" | "patterns";

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

function HuntHeader({
  activeTab,
  onTabChange,
  connected,
  openInvestigations,
  anomalyCount,
}: {
  activeTab: HuntTab;
  onTabChange: (tab: HuntTab) => void;
  connected: boolean;
  openInvestigations: number;
  anomalyCount: number;
}) {
  const tabs: { id: HuntTab; label: string; icon: typeof IconActivity }[] = [
    { id: "stream", label: "Stream", icon: IconActivity },
    { id: "baselines", label: "Baselines", icon: IconChartBar },
    { id: "investigate", label: "Investigate", icon: IconSearch },
    { id: "patterns", label: "Patterns", icon: IconBrain },
  ];

  return (
    <div className="flex items-center justify-between px-1 py-0 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
      {/* Tabs */}
      <div className="flex items-center">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-3 text-xs font-medium transition-all duration-150 border-b-2 -mb-px",
                isActive
                  ? "text-[#d4a84b] border-[#d4a84b]"
                  : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:border-[#2d3240]",
              )}
            >
              <Icon size={14} stroke={1.5} />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Right side: status indicators */}
      <div className="flex items-center gap-3 pr-3">
        {/* Fleet connection status */}
        <div
          className="flex items-center gap-1.5"
          title={connected ? "Fleet connected — live data" : "Fleet offline — no live data"}
        >
          <IconCircle
            size={6}
            stroke={0}
            fill={connected ? "#3dbf84" : "#6f7f9a"}
            className={connected ? "animate-pulse" : ""}
          />
          <span
            className={cn(
              "text-[9px] font-mono uppercase tracking-wider",
              connected ? "text-[#3dbf84]/70" : "text-[#6f7f9a]/50",
            )}
          >
            {connected ? "Live" : "Offline"}
          </span>
        </div>

        {/* Open investigations badge */}
        {openInvestigations > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#2d3240] bg-[#131721]">
            <IconSearch size={12} stroke={1.5} className="text-[#d4a84b]" />
            <span className="text-[10px] font-mono font-semibold text-[#d4a84b] tracking-wider">
              {openInvestigations}
            </span>
          </div>
        )}

        {/* Anomaly count (last hour) */}
        {anomalyCount > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#2d3240] bg-[#131721]">
            <IconAlertTriangle size={12} stroke={1.5} className="text-[#c45c5c]" />
            <span className="text-[10px] font-mono font-semibold text-[#c45c5c] tracking-wider">
              {anomalyCount}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Layout
// ---------------------------------------------------------------------------

export function HuntLayout() {
  const [activeTab, setActiveTab] = useState<HuntTab>("stream");
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [baselines, setBaselines] = useState<Map<string, AgentBaseline>>(new Map());
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [patterns, setPatterns] = useState<HuntPattern[]>([]);
  const [streamFilters, setStreamFilters] = useState<StreamFilters>({ timeRange: "24h" });
  const [streamLive, setStreamLive] = useState(true);
  const [sensitivity, setSensitivity] = useState<"low" | "medium" | "high">("medium");

  const { connection } = useFleetConnection();
  const connected = connection.connected;
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch events from fleet and convert + enrich
  const fetchEvents = useCallback(async () => {
    if (!connected) return;

    try {
      const since = timeRangeToSince("24h");
      const auditEvents = await fetchAuditEvents(connection, { since, limit: 500 });
      const converted = auditEvents.map(auditEventToAgentEvent);

      // Compute baselines from all events by agent
      const agentIds = new Set(converted.map((e) => e.agentId));
      const newBaselines = new Map<string, AgentBaseline>();
      for (const agentId of agentIds) {
        const agentEvents = converted.filter((e) => e.agentId === agentId);
        const agentName = agentEvents[0]?.agentName ?? agentId;
        const teamId = agentEvents[0]?.teamId;
        newBaselines.set(agentId, computeBaseline(agentId, agentName, converted, teamId));
      }
      setBaselines(newBaselines);

      // Enrich events with anomaly scores
      const enriched = enrichEvents(converted, newBaselines);
      setEvents(enriched);
    } catch (err) {
      console.warn("[hunt-layout] Failed to fetch events:", err);
    }
  }, [connected, connection]);

  // Initial fetch + auto-poll every 30 seconds while the stream is live
  useEffect(() => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = null;

    if (!connected || !streamLive) {
      return;
    }

    fetchEvents();
    pollRef.current = setInterval(fetchEvents, 30_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [connected, fetchEvents, streamLive]);

  // Derived: open investigations count
  const openInvestigations = useMemo(
    () => investigations.filter((i) => i.status === "open" || i.status === "in-progress").length,
    [investigations],
  );

  // Derived: anomaly count in last hour
  const anomalyCount = useMemo(() => {
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    return events.filter(
      (e) => (e.anomalyScore ?? 0) > 0.7 && new Date(e.timestamp).getTime() > oneHourAgo,
    ).length;
  }, [events]);

  // Derived: stream stats
  const streamStats = useMemo<StreamStats>(
    () => computeStreamStats(events),
    [events],
  );

  // Derived: baselines as array for Baselines component
  const baselinesArray = useMemo(
    () => Array.from(baselines.values()),
    [baselines],
  );

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Header with tabs + status indicators */}
      <HuntHeader
        activeTab={activeTab}
        onTabChange={setActiveTab}
        connected={connected}
        openInvestigations={openInvestigations}
        anomalyCount={anomalyCount}
      />

      {/* Tab content */}
      <div className="flex-1 min-h-0">
        {activeTab === "stream" && (
          <ActivityStream
            events={events}
            filters={streamFilters}
            onFilterChange={setStreamFilters}
            stats={streamStats}
            live={streamLive}
            onToggleLive={() => setStreamLive((prev) => !prev)}
            onEscalate={(eventIds, note) => {
              const inv: Investigation = {
                id: crypto.randomUUID(),
                title: note || `Investigation from ${eventIds.length} event(s)`,
                status: "open",
                severity: "medium",
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString(),
                createdBy: "analyst",
                agentIds: [...new Set(events.filter((e) => eventIds.includes(e.id)).map((e) => e.agentId))],
                sessionIds: [...new Set(events.filter((e) => eventIds.includes(e.id)).map((e) => e.sessionId))],
                timeRange: {
                  start: events
                    .filter((e) => eventIds.includes(e.id))
                    .map((e) => e.timestamp)
                    .sort()[0] ?? new Date().toISOString(),
                  end: events
                    .filter((e) => eventIds.includes(e.id))
                    .map((e) => e.timestamp)
                    .sort()
                    .reverse()[0] ?? new Date().toISOString(),
                },
                eventIds,
                annotations: [],
              };
              setInvestigations((prev) => [inv, ...prev]);
              setActiveTab("investigate");
            }}
          />
        )}

        {activeTab === "baselines" && (
          <Baselines
            baselines={baselinesArray}
            events={events}
            sensitivity={sensitivity}
            onSensitivityChange={setSensitivity}
          />
        )}

        {activeTab === "investigate" && (
          <InvestigationWorkbench
            investigations={investigations}
            events={events}
            onCreateInvestigation={(inv) => {
              setInvestigations((prev) => [inv, ...prev]);
            }}
            onUpdateInvestigation={(id, updates) => {
              setInvestigations((prev) =>
                prev.map((i) => (i.id === id ? { ...i, ...updates, updatedAt: new Date().toISOString() } : i)),
              );
            }}
            onAddAnnotation={(investigationId, text) => {
              setInvestigations((prev) =>
                prev.map((i) =>
                  i.id === investigationId
                    ? {
                        ...i,
                        updatedAt: new Date().toISOString(),
                        annotations: [
                          ...i.annotations,
                          {
                            id: crypto.randomUUID(),
                            text,
                            createdAt: new Date().toISOString(),
                            createdBy: "analyst",
                          },
                        ],
                      }
                    : i,
                ),
              );
            }}
          />
        )}

        {activeTab === "patterns" && (
          <PatternMining patterns={patterns} events={events} onPatternsChange={setPatterns} />
        )}
      </div>
    </div>
  );
}
