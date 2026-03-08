import { clsx } from "clsx";
import * as React from "react";

import { useOpenClaw } from "@/context/OpenClawContext";
import { PolicyWorkbenchPanel } from "./PolicyWorkbenchPanel";

type ChronicleWorkbenchShelfProps = {
  daemonUrl: string;
  connected: boolean;
  policyWorkbenchEnabled: boolean;
  className?: string;
};

function formatLastSeen(lastSeenMs: number | null): string {
  if (!lastSeenMs) return "No telemetry";
  const delta = Date.now() - lastSeenMs;
  if (delta < 5_000) return "Live now";
  const sec = Math.floor(delta / 1_000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h ago`;
}

export function ChronicleWorkbenchShelf({
  daemonUrl,
  connected,
  policyWorkbenchEnabled,
  className,
}: ChronicleWorkbenchShelfProps) {
  const oc = useOpenClaw();
  const runtime = oc.runtimeByGatewayId[oc.activeGatewayId];

  const openClawConnected = runtime?.status === "connected";
  const nodes = (runtime?.nodes ?? []).filter((node) => node.connected !== false).length;
  const presence = Array.isArray(runtime?.presence) ? runtime.presence.length : 0;
  const approvals = runtime?.execApprovalQueue?.length ?? 0;
  const lastSeen = formatLastSeen(runtime?.lastMessageAtMs ?? runtime?.connectedAtMs ?? null);
  const runtimeSummary = {
    connected: openClawConnected,
    statusLabel: openClawConnected ? "LIVE" : "OFFLINE",
    statusDetail: openClawConnected
      ? `OpenClaw telemetry ${lastSeen}`
      : "OpenClaw telemetry offline",
    nodes,
    presence,
    approvals,
  };

  return (
    <div
      className={clsx(
        "workbench-shelf-shell flex h-full min-h-0 flex-col overflow-hidden",
        className,
      )}
    >
      {policyWorkbenchEnabled ? (
        <PolicyWorkbenchPanel
          daemonUrl={daemonUrl}
          connected={connected}
          variant="shelf"
          runtimeSummary={runtimeSummary}
          className="h-full min-h-0"
        />
      ) : (
        <div className="flex min-h-[140px] items-center justify-center rounded-xl border border-dashed border-[rgba(213,173,87,0.18)] bg-[rgba(6,9,15,0.72)] text-sm text-sdr-text-muted">
          Policy Workbench is disabled.
        </div>
      )}
    </div>
  );
}

export default ChronicleWorkbenchShelf;
