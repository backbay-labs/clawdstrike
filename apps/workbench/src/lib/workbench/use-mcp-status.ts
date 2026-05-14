import { useState, useEffect, useCallback } from "react";
import {
  getMcpStatus,
  stopMcpServer,
  restartMcpServer,
  type TauriMcpStatusResponse,
} from "@/lib/tauri-commands";

/** Hook to poll the embedded MCP sidecar status from the Tauri backend. */
export function useMcpStatus() {
  const [status, setStatus] = useState<TauriMcpStatusResponse | null>(null);
  const [isRestarting, setIsRestarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);

  const refresh = useCallback(async () => {
    const s = await getMcpStatus();
    setStatus(s);
  }, []);

  useEffect(() => {
    // Initial fetch + periodic poll every 5s
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  const handleRestart = useCallback(async () => {
    setIsRestarting(true);
    try {
      const s = await restartMcpServer();
      if (s) {
        setStatus(s);
      } else {
        setStatus(await getMcpStatus());
      }
    } finally {
      setIsRestarting(false);
    }
  }, []);

  const handleStop = useCallback(async () => {
    setIsStopping(true);
    try {
      const s = await stopMcpServer();
      if (s) {
        setStatus(s);
      } else {
        setStatus(await getMcpStatus());
      }
    } finally {
      setIsStopping(false);
    }
  }, []);

  return { status, isRestarting, isStopping, refresh, handleRestart, handleStop };
}
