import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../api/client";

interface Agent {
  id: string;
  agent_id: string;
  name: string;
  status: string;
  last_heartbeat_at: string | null;
  public_key: string;
  role: string;
  trust_level: string;
}

export function useAgents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiFetch<Agent[]>("/agents");
      setAgents(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { agents, loading, error, refresh };
}
