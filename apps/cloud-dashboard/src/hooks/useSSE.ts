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
    const fullUrl = `${apiBase}${url}`;

    // EventSource doesn't support custom headers, so for authenticated
    // hushd deployments we use a fetch-based approach.
    const apiKey = localStorage.getItem("hushd_api_key");
    let source: EventSource;
    if (apiKey) {
      // Use fetch + ReadableStream to send Authorization header
      const ctrl = new AbortController();
      fetch(fullUrl, {
        headers: { Authorization: `Bearer ${apiKey}` },
        signal: ctrl.signal,
      })
        .then((res) => {
          if (!res.ok || !res.body) {
            setConnected(false);
            return;
          }
          setConnected(true);
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          let currentEvent = "";

          function pump(): Promise<void> {
            return reader.read().then(({ done, value }) => {
              if (done) { setConnected(false); return; }
              buffer += decoder.decode(value, { stream: true });
              const lines = buffer.split("\n");
              buffer = lines.pop() ?? "";
              for (const line of lines) {
                if (line.startsWith("event:")) {
                  currentEvent = line.slice(6).trim();
                } else if (line.startsWith("data:")) {
                  const raw = line.slice(5).trim();
                  try {
                    const data = JSON.parse(raw);
                    if (data === "ping" || raw === "ping") continue;
                    const eventType = currentEvent || "message";
                    const event: SSEEvent = {
                      ...data,
                      event_type: eventType,
                      timestamp: data.timestamp ?? new Date().toISOString(),
                    };
                    setEvents((prev) => [event, ...prev].slice(0, 500));
                  } catch { /* skip malformed */ }
                  currentEvent = "";
                } else if (line.trim() === "") {
                  currentEvent = "";
                }
              }
              return pump();
            });
          }
          pump();
        })
        .catch(() => setConnected(false));

      return () => { ctrl.abort(); };
    }

    source = new EventSource(fullUrl);
    sourceRef.current = source;

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);

    function handleEvent(eventType: string) {
      return (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          const event: SSEEvent = {
            ...data,
            event_type: eventType,
            timestamp: data.timestamp ?? new Date().toISOString(),
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
          ...data,
          event_type: "message",
          timestamp: data.timestamp ?? new Date().toISOString(),
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
