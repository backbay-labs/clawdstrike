/**
 * SwarmContext - Agent swarm state management
 */
import { createContext, useContext, useCallback, useState, useEffect, useRef, type ReactNode } from "react";
import type { AgentNode, DelegationEdge, TrustLevel } from "@/types/agents";
import { useConnection } from "./ConnectionContext";
import { getHushdClient } from "@/services/hushdClient";

interface SwarmContextState {
  agents: AgentNode[];
  delegations: DelegationEdge[];
  selectedAgentId?: string;
  isLoading: boolean;
  error?: string;
  lastFetched?: number;
}

interface SwarmContextValue extends SwarmContextState {
  fetchSwarm: () => Promise<void>;
  selectAgent: (agentId: string | undefined) => void;
  getAgent: (agentId: string) => AgentNode | undefined;
  getAgentDelegations: (agentId: string) => DelegationEdge[];
}

const SwarmContext = createContext<SwarmContextValue | null>(null);

const TRUST_RADIUS: Record<TrustLevel, number> = {
  System: 0,
  High: 3,
  Medium: 6,
  Low: 9,
  Untrusted: 12,
};

function derivePositions(agents: AgentNode[]): void {
  const byLevel = new Map<TrustLevel, AgentNode[]>();
  for (const agent of agents) {
    const group = byLevel.get(agent.trust_level);
    if (group) {
      group.push(agent);
    } else {
      byLevel.set(agent.trust_level, [agent]);
    }
  }

  for (const [level, group] of byLevel) {
    const radius = TRUST_RADIUS[level];
    const count = group.length;
    for (let i = 0; i < count; i++) {
      const angle = (i * 2 * Math.PI) / count;
      group[i].position = [
        radius * Math.cos(angle),
        0,
        radius * Math.sin(angle),
      ];
    }
  }
}

export function SwarmProvider({ children }: { children: ReactNode }) {
  const { status } = useConnection();
  const abortRef = useRef<AbortController | null>(null);

  const [state, setState] = useState<SwarmContextState>({
    agents: [],
    delegations: [],
    isLoading: false,
  });

  const fetchSwarm = useCallback(async () => {
    if (status !== "connected") return;

    setState((s) => ({ ...s, isLoading: true, error: undefined }));
    try {
      const client = getHushdClient();
      const [agentsRes, delegationsRes] = await Promise.all([
        client.getAgents(),
        client.getDelegations(),
      ]);

      const agentNodes: AgentNode[] = agentsRes.agents.map((identity) => ({
        ...identity,
        position: [0, 0, 0] as [number, number, number],
        threat_score: 0,
      }));

      // Derive threat_score: blocked_count / (event_count || 1)
      for (const agent of agentNodes) {
        const blocked = agent.blocked_count ?? 0;
        const events = agent.event_count ?? 1;
        agent.threat_score = events > 0 ? blocked / events : 0;
      }

      // Derive 3D positions by trust level
      derivePositions(agentNodes);

      setState((s) => ({
        ...s,
        agents: agentNodes,
        delegations: delegationsRes.delegations,
        isLoading: false,
        lastFetched: Date.now(),
      }));
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to fetch swarm data";
      setState((s) => ({ ...s, isLoading: false, error: message }));
    }
  }, [status]);

  const selectAgent = useCallback((agentId: string | undefined) => {
    setState((s) => ({ ...s, selectedAgentId: agentId }));
  }, []);

  const getAgent = useCallback(
    (agentId: string): AgentNode | undefined => {
      return state.agents.find((a) => a.id === agentId);
    },
    [state.agents]
  );

  const getAgentDelegations = useCallback(
    (agentId: string): DelegationEdge[] => {
      return state.delegations.filter((d) => d.from === agentId || d.to === agentId);
    },
    [state.delegations]
  );

  // Fetch swarm when connected + poll every 15s
  useEffect(() => {
    if (status === "connected") {
      const controller = new AbortController();
      abortRef.current = controller;

      void fetchSwarm();

      const timer = setInterval(() => {
        if (!controller.signal.aborted) {
          void fetchSwarm();
        }
      }, 15000);

      return () => {
        controller.abort();
        clearInterval(timer);
      };
    } else {
      setState((s) => ({ ...s, agents: [], delegations: [] }));
    }
  }, [status, fetchSwarm]);

  const value: SwarmContextValue = {
    ...state,
    fetchSwarm,
    selectAgent,
    getAgent,
    getAgentDelegations,
  };

  return <SwarmContext.Provider value={value}>{children}</SwarmContext.Provider>;
}

export function useSwarm(): SwarmContextValue {
  const context = useContext(SwarmContext);
  if (!context) {
    throw new Error("useSwarm must be used within SwarmProvider");
  }
  return context;
}

export function useAgents(): AgentNode[] {
  return useSwarm().agents;
}

export function useSelectedAgent(): AgentNode | undefined {
  const { agents, selectedAgentId } = useSwarm();
  return agents.find((a) => a.id === selectedAgentId);
}
