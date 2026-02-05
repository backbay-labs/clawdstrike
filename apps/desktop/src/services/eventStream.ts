/**
 * EventStream - SSE subscription for real-time daemon events
 */
import type { DaemonEvent } from "@/types/events";

export type EventCallback = (event: DaemonEvent) => void;
export type ErrorCallback = (error: Error) => void;

export interface EventStreamOptions {
  onEvent: EventCallback;
  onError?: ErrorCallback;
  onConnect?: () => void;
  onDisconnect?: () => void;
  reconnectDelay?: number;
  maxReconnectAttempts?: number;
}

export class EventStream {
  private eventSource: EventSource | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: number | null = null;
  private isManualClose = false;

  constructor(
    private baseUrl: string,
    private options: EventStreamOptions
  ) {}

  connect(): void {
    if (this.eventSource) {
      return;
    }

    this.isManualClose = false;
    this.reconnectAttempts = 0;
    this.createConnection();
  }

  private createConnection(): void {
    try {
      this.eventSource = new EventSource(`${this.baseUrl}/api/v1/events`);

      this.eventSource.onopen = () => {
        this.reconnectAttempts = 0;
        this.options.onConnect?.();
      };

      this.eventSource.onmessage = (event) => {
        this.emitIncomingEvent("message", event.data);
      };

      this.eventSource.onerror = () => {
        this.handleError();
      };

      // hushd emits named events such as `check`, `violation`, and `eval`.
      const namedEventTypes = [
        "check",
        "violation",
        "eval",
        "policy_reload",
        "policy_updated",
        "error",
      ];

      namedEventTypes.forEach((eventType) => {
        this.eventSource?.addEventListener(eventType, (event) => {
          const messageEvent = event as MessageEvent;
          this.emitIncomingEvent(eventType, messageEvent.data);
        });
      });
    } catch {
      this.handleError();
    }
  }

  private emitIncomingEvent(eventType: string, payload: string): void {
    try {
      const parsed = JSON.parse(payload) as unknown;
      if (
        parsed &&
        typeof parsed === "object" &&
        "type" in parsed &&
        "timestamp" in parsed &&
        "data" in parsed
      ) {
        this.options.onEvent(parsed as DaemonEvent);
        return;
      }

      this.options.onEvent({
        type: eventType,
        timestamp: new Date().toISOString(),
        data: (parsed ?? {}) as DaemonEvent["data"],
      });
    } catch (e) {
      console.error(`[EventStream] Failed to parse ${eventType}:`, e);
    }
  }

  private handleError(): void {
    this.cleanup();
    this.options.onDisconnect?.();

    if (this.isManualClose) {
      return;
    }

    const maxAttempts = this.options.maxReconnectAttempts ?? 10;
    if (this.reconnectAttempts >= maxAttempts) {
      this.options.onError?.(new Error("Max reconnection attempts reached"));
      return;
    }

    const delay = this.options.reconnectDelay ?? 3000;
    const backoff = Math.min(delay * Math.pow(1.5, this.reconnectAttempts), 30000);

    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectAttempts++;
      this.createConnection();
    }, backoff);
  }

  private cleanup(): void {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  disconnect(): void {
    this.isManualClose = true;
    this.cleanup();
    this.options.onDisconnect?.();
  }

  isConnected(): boolean {
    return this.eventSource?.readyState === EventSource.OPEN;
  }
}

// Hook for React components
import { useEffect, useRef, useState, useCallback } from "react";

export interface UseEventStreamOptions {
  baseUrl: string;
  enabled?: boolean;
  onEvent?: EventCallback;
  maxEvents?: number;
}

export interface UseEventStreamResult {
  events: DaemonEvent[];
  isConnected: boolean;
  isLive: boolean;
  error?: string;
  toggleLive: () => void;
  clearEvents: () => void;
}

export function useEventStream(options: UseEventStreamOptions): UseEventStreamResult {
  const { baseUrl, enabled = true, onEvent, maxEvents = 1000 } = options;

  const [events, setEvents] = useState<DaemonEvent[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isLive, setIsLive] = useState(true);
  const [error, setError] = useState<string>();

  const streamRef = useRef<EventStream | null>(null);

  const handleEvent = useCallback(
    (event: DaemonEvent) => {
      if (isLive) {
        setEvents((prev) => {
          const next = [event, ...prev];
          return next.slice(0, maxEvents);
        });
      }
      onEvent?.(event);
    },
    [isLive, maxEvents, onEvent]
  );

  useEffect(() => {
    if (!enabled) {
      streamRef.current?.disconnect();
      streamRef.current = null;
      setIsConnected(false);
      return;
    }

    const stream = new EventStream(baseUrl, {
      onEvent: handleEvent,
      onConnect: () => {
        setIsConnected(true);
        setError(undefined);
      },
      onDisconnect: () => {
        setIsConnected(false);
      },
      onError: (e) => {
        setError(e.message);
      },
    });

    streamRef.current = stream;
    stream.connect();

    return () => {
      stream.disconnect();
    };
  }, [baseUrl, enabled, handleEvent]);

  const toggleLive = useCallback(() => {
    setIsLive((prev) => !prev);
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  return {
    events,
    isConnected,
    isLive,
    error,
    toggleLive,
    clearEvents,
  };
}
