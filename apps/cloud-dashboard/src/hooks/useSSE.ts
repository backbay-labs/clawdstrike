import { useEffect, useRef, useState } from "react";

export interface SSEEvent {
  event_type: string;
  action_type?: string;
  target?: string;
  allowed?: boolean;
  guard?: string;
  policy_hash?: string;
  session_id?: string;
  agent_id?: string;
  timestamp: string;
}

export function useSSE(url: string) {
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const apiBase = localStorage.getItem("hushd_url") || "";
    const apiKey = localStorage.getItem("hushd_api_key");
    const fullUrl = apiKey
      ? `${apiBase}${url}?token=${encodeURIComponent(apiKey)}`
      : `${apiBase}${url}`;

    const source = new EventSource(fullUrl);
    sourceRef.current = source;

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);

    function handleEvent(eventType: string) {
      return (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          const event: SSEEvent = {
            event_type: eventType,
            timestamp: new Date().toISOString(),
            ...data,
          };
          setEvents((prev) => [event, ...prev].slice(0, 500));
        } catch {
          // skip malformed
        }
      };
    }

    source.addEventListener("check", handleEvent("check"));
    source.addEventListener("violation", handleEvent("violation"));
    source.addEventListener("policy_updated", handleEvent("policy_updated"));
    source.addEventListener("session_posture_transition", handleEvent("session_posture_transition"));

    // Also handle unnamed messages
    source.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data === "ping" || e.data === "ping") return;
        const event: SSEEvent = {
          event_type: "message",
          timestamp: new Date().toISOString(),
          ...data,
        };
        setEvents((prev) => [event, ...prev].slice(0, 500));
      } catch {
        // skip
      }
    };

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [url]);

  return { events, connected };
}
