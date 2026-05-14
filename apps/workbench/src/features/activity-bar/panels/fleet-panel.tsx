import { useMemo } from "react";
import { IconServer, IconNetwork } from "@tabler/icons-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useFleetConnectionStore } from "@/features/fleet/use-fleet-connection";
import { usePaneStore } from "@/features/panes/pane-store";
import type { AgentInfo } from "@/features/fleet/fleet-client";

// ---------------------------------------------------------------------------
// FleetPanel -- connection status, agent list, and topology link.
//
// Shows hushd connection state, connected agents with health dots,
// and a link to the topology map. When disconnected, shows a CTA
// to open Settings.
// ---------------------------------------------------------------------------

function formatRelativeTime(seconds: number | undefined): string {
  if (seconds === undefined || seconds === null) return "offline";
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function getAgentHealthColor(agent: AgentInfo): string {
  if (!agent.online) return "#6f7f9a";
  const secs = agent.seconds_since_heartbeat ?? 0;
  if (secs < 300) return "#4ade80"; // ready
  return "#d4a84b"; // degraded
}

function getConnectionDotColor(connected: boolean, error: string | null): string {
  if (error) return "#c45c5c";
  if (connected) return "#4ade80";
  return "#6f7f9a";
}

// ---------------------------------------------------------------------------
// FleetPanel
// ---------------------------------------------------------------------------

export function FleetPanel() {
  const connection = useFleetConnectionStore.use.connection();
  const agents = useFleetConnectionStore.use.agents();
  const error = useFleetConnectionStore.use.error();

  const onlineCount = useMemo(
    () => agents.filter((a) => a.online).length,
    [agents],
  );

  const handleOpenTopology = () => {
    usePaneStore.getState().openApp("/topology", "Topology");
  };

  const handleOpenSettings = () => {
    usePaneStore.getState().openApp("/settings", "Settings");
  };

  // Disconnected state
  if (!connection.connected) {
    return (
      <div className="flex flex-col h-full">
        {/* Panel header */}
        <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
          <span className="font-display font-semibold text-sm text-[#ece7dc]">
            Fleet &amp; Topology
          </span>
        </div>

        {/* Disconnected CTA */}
        <div className="flex-1 flex flex-col items-center justify-center py-8 text-center gap-1">
          <IconNetwork size={28} stroke={1} className="text-[#6f7f9a]/30" />
          <span className="text-[11px] font-mono font-semibold text-[#6f7f9a]/70">
            Not Connected
          </span>
          <p className="text-[11px] font-mono text-[#6f7f9a]/70 leading-relaxed max-w-[80%]">
            Configure a hushd connection in Settings to manage your fleet.
          </p>
          <button
            type="button"
            onClick={handleOpenSettings}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 mt-2 text-[10px] font-mono rounded border border-[#d4a84b]/20 text-[#d4a84b] bg-[#d4a84b]/5 hover:bg-[#d4a84b]/10 transition-colors"
          >
            Open Settings
          </button>
        </div>

        {/* Footer */}
        <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240]">
          <span className="text-[9px] font-mono text-[#6f7f9a]/40">
            0 agents online
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Panel header */}
      <div className="h-8 shrink-0 flex items-center px-4 border-b border-[#2d3240]/40">
        <span className="font-display font-semibold text-sm text-[#ece7dc]">
          Fleet &amp; Topology
        </span>
      </div>

      {/* Connection section */}
      <div className="shrink-0 px-3 py-2 border-b border-[#2d3240]/40">
        <div className="flex items-center gap-1 w-full px-0 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider">
          CONNECTION
        </div>
        <div className="flex items-start gap-2 px-0 py-1">
          {/* Status dot */}
          <span
            className="w-1.5 h-1.5 rounded-full shrink-0 mt-1"
            style={{
              backgroundColor: getConnectionDotColor(
                connection.connected,
                error,
              ),
            }}
            aria-hidden="true"
          />
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-[#ece7dc]/70">
                Connected to hushd
              </span>
              {connection.hushdHealth?.version && (
                <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
                  v{connection.hushdHealth.version}
                </span>
              )}
            </div>
            {connection.hushdUrl && (
              <span className="text-[9px] font-mono text-[#6f7f9a] truncate block">
                {connection.hushdUrl}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Agent list */}
      <ScrollArea className="flex-1">
        <div className="px-3 py-1">
          <div className="flex items-center gap-1 w-full px-0 py-1.5 text-[10px] font-mono font-semibold text-[#6f7f9a] uppercase tracking-wider">
            AGENTS
            <span className="text-[#6f7f9a]/50 ml-0.5">({agents.length})</span>
          </div>

          {agents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-4 text-center">
              <p className="text-[10px] font-mono text-[#6f7f9a]/50">
                No agents registered with this hushd instance.
              </p>
            </div>
          ) : (
            agents.map((agent) => (
              <button
                key={agent.endpoint_agent_id}
                type="button"
                role="option"
                onClick={() =>
                  usePaneStore
                    .getState()
                    .openApp(
                      `/fleet/${agent.endpoint_agent_id}`,
                      agent.endpoint_agent_id,
                    )
                }
                className="flex items-center gap-1.5 w-full h-8 px-0 text-left hover:bg-[#131721]/40 transition-colors"
              >
                {/* Server icon */}
                <IconServer
                  size={14}
                  stroke={1.5}
                  className="text-[#6f7f9a] shrink-0"
                />
                {/* Agent name */}
                <span className="text-[11px] font-mono text-[#ece7dc]/70 truncate flex-1">
                  {agent.endpoint_agent_id}
                </span>
                {/* Health dot */}
                <span
                  className="w-1.5 h-1.5 rounded-full shrink-0"
                  style={{ backgroundColor: getAgentHealthColor(agent) }}
                  aria-hidden="true"
                />
                {/* Relative time */}
                <span className="text-[9px] font-mono text-[#6f7f9a] shrink-0">
                  {agent.online
                    ? formatRelativeTime(agent.seconds_since_heartbeat)
                    : "offline"}
                </span>
              </button>
            ))
          )}
        </div>

        {/* Topology link */}
        <div className="px-3 py-1 border-t border-[#2d3240]/40">
          <button
            type="button"
            onClick={handleOpenTopology}
            className="flex items-center gap-1.5 w-full h-8 text-left hover:bg-[#131721]/40 transition-colors"
          >
            <span className="text-[11px] font-mono text-[#d4a84b]">
              &gt; Open Topology Map
            </span>
          </button>
        </div>
      </ScrollArea>

      {/* Footer */}
      <div className="shrink-0 px-3 py-1.5 border-t border-[#2d3240]">
        <span className="text-[9px] font-mono text-[#6f7f9a]/40">
          {onlineCount} agents online
        </span>
      </div>
    </div>
  );
}
