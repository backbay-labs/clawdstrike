/**
 * SwarmContext - Agent swarm state management
 */
import { createContext, useContext, useCallback, useState, useEffect, type ReactNode } from "react";
import type { AgentNode, DelegationEdge } from "@/types/agents";
import { useConnection } from "./ConnectionContext";

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

export function SwarmProvider({ children }: { children: ReactNode }) {
  const { status } = useConnection();

  const [state, setState] = useState<SwarmContextState>({
    agents: [],
    delegations: [],
    isLoading: false,
  });

  const fetchSwarm = useCallback(async () => {
    if (status !== "connected") return;

    setState((s) => ({ ...s, isLoading: true, error: undefined }));
    try {
      setState((s) => ({
        ...s,
        agents: [],
        delegations: [],
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

  // Fetch swarm when connected
  useEffect(() => {
    if (status === "connected") {
      fetchSwarm();
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
