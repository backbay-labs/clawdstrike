import { useState, useCallback, useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import type { Investigation, StreamFilters, StreamStats } from "@/lib/workbench/hunt-types";
import {
  computeStreamStats,
} from "@/lib/workbench/hunt-engine";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { fetchAuditEvents } from "@/features/fleet/fleet-client";
import { usePolicyTabs } from "@/features/policy/hooks/use-policy-actions";
import { usePolicyTabsStore } from "@/features/policy/stores/policy-tabs-store";
import { useDraftDetection } from "@/lib/workbench/detection-workflow/use-draft-detection";
import { buildOpenDocumentCoverage } from "@/lib/workbench/detection-workflow/coverage-projection";
import { usePublishedCoverage } from "@/lib/workbench/detection-workflow/use-published-coverage";
import { useHuntStore } from "@/features/hunt/stores/hunt-store";
import {
  IconActivity,
  IconChartBar,
  IconSearch,
  IconBrain,
  IconCircle,
  IconAlertTriangle,
} from "@tabler/icons-react";
import { usePaneStore } from "@/features/panes/pane-store";
import { cn } from "@/lib/utils";
import { SubTabBar, type SubTab } from "../shared/sub-tab-bar";
import { ActivityStream } from "./activity-stream";
import { Baselines } from "./baselines";
import { InvestigationWorkbench } from "./investigation";
import { PatternMining } from "./pattern-mining";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type HuntTab = "stream" | "baselines" | "investigate" | "patterns";

// ---------------------------------------------------------------------------
// Tab definitions
// ---------------------------------------------------------------------------

const HUNT_TABS: SubTab[] = [
  { id: "stream", label: "Stream", icon: IconActivity },
  { id: "baselines", label: "Baselines", icon: IconChartBar },
  { id: "investigate", label: "Investigate", icon: IconSearch },
  { id: "patterns", label: "Patterns", icon: IconBrain },
];

function parseHuntTab(search: string): HuntTab {
  const tab = new URLSearchParams(search).get("tab");
  if (tab === "baselines" || tab === "investigate" || tab === "patterns") {
    return tab;
  }
  return "stream";
}

// ---------------------------------------------------------------------------
// Status indicators (right-side slot for SubTabBar)
// ---------------------------------------------------------------------------

function HuntStatusIndicators({
  connected,
  openInvestigations,
  anomalyCount,
}: {
  connected: boolean;
  openInvestigations: number;
  anomalyCount: number;
}) {
  return (
    <>
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
    </>
  );
}

// ---------------------------------------------------------------------------
// Main Layout
// ---------------------------------------------------------------------------

export function HuntLayout() {
  const [streamFilters, setStreamFilters] = useState<StreamFilters>({ timeRange: "24h" });
  const [sensitivity, setSensitivity] = useState<"low" | "medium" | "high">("medium");
  const { search } = useLocation();
  const navigate = useNavigate();
  const activeTab = parseHuntTab(search);

  const { connection } = useFleetConnection();
  const connected = connection.connected;
  const publishedCoverage = usePublishedCoverage();
  const events = useHuntStore.use.events();
  const baselines = useHuntStore.use.baselines();
  const investigations = useHuntStore.use.investigations();
  const patterns = useHuntStore.use.patterns();
  const streamLive = useHuntStore.use.isLive();
  const huntActions = useHuntStore.use.actions();

  // Draft detection hook — bridges Hunt -> Editor
  const { multiDispatch, tabs } = usePolicyTabs();
  const {
    draftFromEvents,
    draftFromInvestigation,
    draftFromPattern,
  } = useDraftDetection({
    dispatch: multiDispatch,
    onNavigateToEditor: () => {
      // After drafting a detection, the active tab in policy-tabs-store has the new policy
      const activeTab = usePolicyTabsStore.getState().getActiveTab();
      if (activeTab?.filePath) {
        usePaneStore.getState().openFile(activeTab.filePath, activeTab.name);
      } else if (activeTab) {
        // Untitled file -- use __new__ route
        usePaneStore.getState().openApp(`/file/__new__/${activeTab.id}`, activeTab.name);
      }
    },
  });

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
  const baselinesArray = baselines;

  const openDocumentCoverage = useMemo(
    () => buildOpenDocumentCoverage(tabs),
    [tabs],
  );

  const handleTabChange = useCallback(
    (tab: HuntTab) => {
      const params = new URLSearchParams(search);
      if (tab === "stream") {
        params.delete("tab");
      } else {
        params.set("tab", tab);
      }
      const nextSearch = params.toString();
      navigate(
        {
          pathname: "/hunt",
          search: nextSearch ? `?${nextSearch}` : "",
        },
        { replace: false },
      );
    },
    [navigate, search],
  );

  return (
    <div
      className="flex flex-col h-full min-h-0 border border-transparent transition-colors duration-[400ms] ease-out"
      style={{ borderColor: "var(--spirit-accent)" }}
    >
      {/* Sub-tab bar with status indicators */}
      <SubTabBar
        tabs={HUNT_TABS}
        activeTab={activeTab}
        onTabChange={(id) => handleTabChange(id as HuntTab)}
      >
        <HuntStatusIndicators
          connected={connected}
          openInvestigations={openInvestigations}
          anomalyCount={anomalyCount}
        />
      </SubTabBar>

      {/* Tab content */}
      <div className="flex-1 min-h-0">
        {activeTab === "stream" && (
          <ActivityStream
            events={events}
            filters={streamFilters}
            onFilterChange={setStreamFilters}
            onDraftDetection={draftFromEvents}
            stats={streamStats}
            live={streamLive}
            onToggleLive={() => huntActions.setLive(!streamLive)}
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
              huntActions.createInvestigation(inv);
              handleTabChange("investigate");
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
            onDraftDetection={draftFromInvestigation}
            onCreateInvestigation={huntActions.createInvestigation}
            onUpdateInvestigation={huntActions.updateInvestigation}
            onAddAnnotation={(investigationId, text) => {
              huntActions.addAnnotation(investigationId, {
                createdAt: new Date().toISOString(),
                createdBy: "analyst",
                text,
              });
            }}
            openDocumentCoverage={openDocumentCoverage}
            publishedCoverage={publishedCoverage}
          />
        )}

        {activeTab === "patterns" && (
          <PatternMining
            patterns={patterns}
            events={events}
            onPatternsChange={huntActions.setPatterns}
            onDraftDetection={draftFromPattern}
            openDocumentCoverage={openDocumentCoverage}
            publishedCoverage={publishedCoverage}
          />
        )}
      </div>
    </div>
  );
}
