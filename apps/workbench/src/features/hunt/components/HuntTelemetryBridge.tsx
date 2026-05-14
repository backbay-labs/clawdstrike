import { useCallback, useEffect, useRef } from "react";
import { fetchAuditEvents } from "@/features/fleet/fleet-client";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import {
  auditEventToAgentEvent,
  computeBaseline,
  computeStreamStats,
  enrichEvents,
} from "@/lib/workbench/hunt-engine";
import type { AgentBaseline, AgentEvent } from "@/lib/workbench/hunt-types";
import { useHuntStore } from "../stores/hunt-store";

const HUNT_POLL_MS = 30_000;

function buildTelemetry(events: AgentEvent[]): {
  baselines: AgentBaseline[];
  events: AgentEvent[];
} {
  const baselines = Array.from(new Set(events.map((event) => event.agentId)))
    .map((agentId) => {
      const sample = events.find((event) => event.agentId === agentId);
      return computeBaseline(
        agentId,
        sample?.agentName ?? agentId,
        events,
        sample?.teamId,
      );
    });
  const baselineMap = new Map(baselines.map((baseline) => [baseline.agentId, baseline]));
  return {
    baselines,
    events: enrichEvents(events, baselineMap),
  };
}

export function HuntTelemetryBridge() {
  const { connection, getAuthenticatedConnection } = useFleetConnection();
  const connected = connection.connected;
  const isLive = useHuntStore.use.isLive();
  const huntActions = useHuntStore.use.actions();
  const fetchRef = useRef<(() => Promise<void>) | null>(null);

  const fetchTelemetry = useCallback(async () => {
    if (!connected || !isLive) {
      return;
    }

    huntActions.setLoading(true);
    try {
      const auditEvents = await fetchAuditEvents(getAuthenticatedConnection(), {
        since: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        limit: 500,
      });
      const converted = auditEvents.map(auditEventToAgentEvent);
      const telemetry = buildTelemetry(converted);
      huntActions.replaceTelemetry({
        baselines: telemetry.baselines,
        events: telemetry.events,
        lastUpdatedAt: new Date().toISOString(),
        stats: computeStreamStats(telemetry.events),
      });
    } catch (error) {
      console.warn("[hunt-telemetry-bridge] Failed to refresh hunt telemetry:", error);
    } finally {
      huntActions.setLoading(false);
    }
  }, [connected, getAuthenticatedConnection, huntActions, isLive]);

  fetchRef.current = fetchTelemetry;

  useEffect(() => {
    huntActions.setConnected(connected);
  }, [connected, huntActions]);

  useEffect(() => {
    if (!connected || !isLive) {
      huntActions.setLoading(false);
      return;
    }

    void fetchRef.current?.();
    const timer = window.setInterval(() => {
      void fetchRef.current?.();
    }, HUNT_POLL_MS);
    return () => window.clearInterval(timer);
  }, [connected, huntActions, isLive]);

  return null;
}
