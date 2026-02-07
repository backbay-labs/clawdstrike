import { useEffect, useRef, useState } from "react";

export function useSSE<T>(url: string) {
  const [events, setEvents] = useState<T[]>([]);
  const [connected, setConnected] = useState(false);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    const fullUrl = token ? `${url}?token=${encodeURIComponent(token)}` : url;
    const source = new EventSource(fullUrl);
    sourceRef.current = source;

    source.onopen = () => setConnected(true);

    source.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data) as T;
        setEvents((prev) => [parsed, ...prev].slice(0, 500));
      } catch {
        // skip malformed events
      }
    };

    source.onerror = () => setConnected(false);

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [url]);

  return { events, connected };
}
