import { createContext, type ReactNode, useContext } from "react";
import { type SSEConnectionStatus, type SSEEvent, useSSE } from "../hooks/useSSE";

interface SharedSSEValue {
  events: SSEEvent[];
  connected: boolean;
  status: SSEConnectionStatus;
  error: string | null;
  reconnect: () => void;
}

const SharedSSEContext = createContext<SharedSSEValue | null>(null);

export function SharedSSEProvider({ children }: { children: ReactNode }) {
  const value = useSSE("/api/v1/events");
  return <SharedSSEContext.Provider value={value}>{children}</SharedSSEContext.Provider>;
}

export function useSharedSSE(): SharedSSEValue {
  const value = useContext(SharedSSEContext);
  if (!value) {
    throw new Error("useSharedSSE must be used within SharedSSEProvider");
  }
  return value;
}
