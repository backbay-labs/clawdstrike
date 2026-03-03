import { useEffect, useRef, useState } from "react";
import { useSharedSSE } from "../../context/SSEContext";
import type { SSEConnectionStatus } from "../../hooks/useSSE";

interface Toast {
  id: number;
  message: string;
  type: "info" | "success" | "warning" | "error";
}

const TYPE_STYLES: Record<Toast["type"], { border: string; color: string; glow: string }> = {
  info: { border: "rgba(214,177,90,0.3)", color: "#d6b15a", glow: "rgba(214,177,90,0.15)" },
  success: { border: "rgba(45,170,106,0.3)", color: "#2daa6a", glow: "rgba(45,170,106,0.15)" },
  warning: { border: "rgba(210,163,75,0.3)", color: "#d2a34b", glow: "rgba(210,163,75,0.15)" },
  error: { border: "rgba(194,59,59,0.3)", color: "#c23b3b", glow: "rgba(194,59,59,0.15)" },
};

const STATUS_TOAST: Partial<Record<SSEConnectionStatus, { msg: string; type: Toast["type"] }>> = {
  connected: { msg: "SSE stream connected", type: "success" },
  disconnected: { msg: "SSE stream disconnected", type: "warning" },
  unauthorized: { msg: "SSE authentication failed", type: "error" },
  network_error: { msg: "SSE network error — retrying", type: "error" },
};

export function SSENotifier() {
  const { status } = useSharedSSE();
  const prevStatus = useRef<SSEConnectionStatus>(status);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toastIdRef = useRef(0);
  const timersRef = useRef(new Set<ReturnType<typeof setTimeout>>());

  useEffect(() => {
    return () => {
      for (const t of timersRef.current) clearTimeout(t);
      timersRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (status === prevStatus.current) return;
    const prev = prevStatus.current;
    prevStatus.current = status;

    if (prev === "connecting" && status === "connected") return;

    const cfg = STATUS_TOAST[status];
    if (!cfg) return;

    const id = ++toastIdRef.current;
    setToasts((t) => [...t, { id, message: cfg.msg, type: cfg.type }]);

    const timer = setTimeout(() => {
      setToasts((t) => t.filter((toast) => toast.id !== id));
      timersRef.current.delete(timer);
    }, 4000);
    timersRef.current.add(timer);
  }, [status]);

  if (toasts.length === 0) return null;

  return (
    <div
      style={{
        position: "fixed",
        top: 16,
        right: 16,
        zIndex: 99999,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
      }}
    >
      {toasts.map((toast) => {
        const s = TYPE_STYLES[toast.type];
        return (
          <div
            key={toast.id}
            className="font-mono"
            style={{
              pointerEvents: "auto",
              background: "rgba(11,13,16,0.96)",
              backdropFilter: "blur(24px)",
              border: `1px solid ${s.border}`,
              borderRadius: 8,
              padding: "10px 16px",
              boxShadow: `inset 0 1px 0 rgba(255,255,255,0.02), 0 4px 16px ${s.glow}`,
              fontSize: 12,
              letterSpacing: "0.06em",
              color: s.color,
              animation: "toastSlideIn 0.25s ease-out",
            }}
          >
            {toast.message}
          </div>
        );
      })}
    </div>
  );
}
