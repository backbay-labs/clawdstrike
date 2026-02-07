/**
 * NetworkMapView - Hubble network flow data table
 *
 * Shows recent network flows from Hubble in a sortable table.
 * Subscribes to spine events filtered to network_flow and dns_query categories.
 */
import { useMemo, useCallback } from "react";
import { GlassPanel, GlassHeader } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import { GlowButton } from "@backbay/glia/primitives";
import { useSpineEvents } from "@/hooks/useSpineEvents";
import type { SDREvent, SpineConnectionStatus } from "@/types/spine";

// ---------------------------------------------------------------------------
// Flow row type for the table
// ---------------------------------------------------------------------------

interface FlowRow {
  id: string;
  timestamp: string;
  srcPod: string;
  srcIp: string;
  dstIp: string;
  protocol: string;
  dstPort: number | undefined;
  verdict: string;
  severity: string;
  l7Summary: string;
  direction: string;
}

// ---------------------------------------------------------------------------
// Verdict / severity badge variants
// ---------------------------------------------------------------------------

const VERDICT_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  forwarded: "default",
  dropped: "destructive",
  error: "destructive",
  audit: "secondary",
};

const SEVERITY_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  info: "outline",
  low: "outline",
  medium: "secondary",
  high: "destructive",
  critical: "destructive",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function eventToFlowRow(event: SDREvent): FlowRow | null {
  if (event.category !== "network_flow" && event.category !== "dns_query") {
    return null;
  }

  const net = event.network;
  const raw = event.raw as Record<string, unknown> | undefined;
  const l7 = raw?.l7 as Record<string, unknown> | undefined;

  let l7Summary = "";
  if (l7) {
    const record = l7.record as Record<string, unknown> | undefined;
    if (record) {
      const recordType = record.type as string | undefined;
      if (recordType === "http") {
        l7Summary = `HTTP ${record.method ?? ""} ${record.url ?? ""} [${record.code ?? ""}]`;
      } else if (recordType === "dns") {
        l7Summary = `DNS ${record.query ?? ""}`;
      } else if (recordType === "kafka") {
        l7Summary = `Kafka ${record.topic ?? ""}`;
      }
    }
  }

  if (!l7Summary && event.category === "dns_query" && net?.dnsName) {
    l7Summary = `DNS ${net.dnsName}`;
  }

  return {
    id: event.id,
    timestamp: event.timestamp,
    srcPod: event.origin?.pod ?? "",
    srcIp: net?.srcIp ?? "",
    dstIp: net?.dstIp ?? "",
    protocol: net?.protocol?.toUpperCase() ?? "",
    dstPort: net?.dstPort,
    verdict: net?.verdict ?? "",
    severity: event.severityLabel,
    l7Summary,
    direction: net?.direction ?? "",
  };
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString(undefined, { hour12: false });
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Status indicator
// ---------------------------------------------------------------------------

function StatusIndicator({ status }: { status: SpineConnectionStatus }) {
  const config = {
    connected: { color: "bg-sdr-accent-green", label: "Live" },
    demo: { color: "bg-sdr-accent-amber", label: "Demo" },
    connecting: { color: "bg-sdr-accent-blue animate-pulse", label: "Connecting" },
    disconnected: { color: "bg-sdr-accent-red", label: "Offline" },
  };
  const { color, label } = config[status];

  return (
    <span className="flex items-center gap-1.5 text-xs text-sdr-text-muted">
      <span className={`w-1.5 h-1.5 rounded-full ${color}`} />
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function NetworkMapView() {
  const { events, status, clearEvents } = useSpineEvents({ enabled: true });

  const flowRows = useMemo(() => {
    const rows: FlowRow[] = [];
    for (const event of events) {
      const row = eventToFlowRow(event);
      if (row) rows.push(row);
    }
    return rows;
  }, [events]);

  const stats = useMemo(() => {
    const dropped = flowRows.filter((r) => r.verdict === "dropped").length;
    const dns = flowRows.filter((r) => r.l7Summary.startsWith("DNS")).length;
    return { total: flowRows.length, dropped, dns };
  }, [flowRows]);

  const handleClear = useCallback(() => {
    clearEvents();
  }, [clearEvents]);

  return (
    <GlassPanel className="flex flex-col h-full">
      <GlassHeader className="flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-sdr-text-primary">Network Map</h1>
          <StatusIndicator status={status} />
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-sdr-text-muted">
            {stats.total} flows
            {stats.dropped > 0 && (
              <span className="text-sdr-accent-red ml-1">({stats.dropped} dropped)</span>
            )}
            {stats.dns > 0 && <span className="ml-1">/ {stats.dns} DNS</span>}
          </span>
          <GlowButton onClick={handleClear} variant="secondary">
            Clear
          </GlowButton>
        </div>
      </GlassHeader>

      <div className="flex-1 overflow-y-auto">
        {flowRows.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-sdr-text-muted">
            <p className="text-sm">Waiting for Hubble network flows...</p>
            <p className="text-xs mt-1">Flows appear when the spine connection is active</p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-sdr-bg-secondary border-b border-sdr-border">
              <tr>
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium">
                  Time
                </th>
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium">
                  Source
                </th>
                <th className="px-1 py-2 w-6" />
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium">
                  Destination
                </th>
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium w-16">
                  Proto
                </th>
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium w-24">
                  Verdict
                </th>
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium w-20">
                  Severity
                </th>
                <th className="px-3 py-2 text-left text-[10px] uppercase tracking-wider text-sdr-text-muted font-medium">
                  L7 Info
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-sdr-border-subtle">
              {flowRows.map((row) => (
                <tr key={row.id} className="hover:bg-sdr-bg-hover transition-colors">
                  <td className="px-3 py-1.5 font-mono text-[11px] text-sdr-text-muted whitespace-nowrap">
                    {formatTime(row.timestamp)}
                  </td>
                  <td className="px-3 py-1.5 truncate max-w-[180px]">
                    <span className="text-sdr-text-primary">{row.srcPod || row.srcIp || "-"}</span>
                    {row.srcPod && row.srcIp && (
                      <span className="text-[10px] text-sdr-text-muted ml-1 font-mono">
                        {row.srcIp}
                      </span>
                    )}
                  </td>
                  <td className="px-1 py-1.5 text-sdr-text-muted text-center">
                    &rarr;
                  </td>
                  <td className="px-3 py-1.5 truncate max-w-[180px]">
                    <span className="text-sdr-text-primary">{row.dstIp || "-"}</span>
                    {row.dstPort !== undefined && (
                      <span className="text-[10px] text-sdr-text-muted ml-1 font-mono">
                        :{row.dstPort}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5 text-sdr-text-secondary">
                    {row.protocol || "-"}
                  </td>
                  <td className="px-3 py-1.5">
                    {row.verdict ? (
                      <Badge variant={VERDICT_VARIANT[row.verdict] ?? "outline"}>
                        {row.verdict}
                      </Badge>
                    ) : (
                      <span className="text-sdr-text-muted">-</span>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    <Badge variant={SEVERITY_VARIANT[row.severity] ?? "outline"}>
                      {row.severity}
                    </Badge>
                  </td>
                  <td className="px-3 py-1.5 text-[11px] text-sdr-text-secondary font-mono truncate max-w-[250px]">
                    {row.l7Summary || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </GlassPanel>
  );
}
