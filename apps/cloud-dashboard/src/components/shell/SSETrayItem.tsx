import { useEffect } from "react";
import { useSystemTray } from "@backbay/glia-desktop";
import { useSharedSSE } from "../../context/SSEContext";

const STATUS_CONFIG = {
  connected:     { color: "#10B981", label: "SSE Connected" },
  connecting:    { color: "#3B82F6", label: "SSE Connecting..." },
  disconnected:  { color: "#EAB308", label: "SSE Disconnected" },
  unauthorized:  { color: "#F97316", label: "SSE Unauthorized" },
  network_error: { color: "#EF4444", label: "SSE Network Error" },
} as const;

function StatusDot({ color }: { color: string }) {
  return (
    <svg width={14} height={14} viewBox="0 0 14 14" aria-hidden>
      <circle cx={7} cy={7} r={4} fill={color} />
      <circle cx={7} cy={7} r={6} fill="none" stroke={color} strokeWidth={1} opacity={0.4} />
    </svg>
  );
}

export function SSETrayItem() {
  const { status, error, reconnect } = useSharedSSE();
  const { registerItem, updateItem, unregisterItem } = useSystemTray();
  const cfg = STATUS_CONFIG[status];

  // Mount-only: register and unregister the tray item
  useEffect(() => {
    registerItem({
      id: "sse-status",
      icon: <StatusDot color={STATUS_CONFIG.connecting.color} />,
      tooltip: STATUS_CONFIG.connecting.label,
      onClick: () => {},
      order: 10,
    });
    return () => unregisterItem("sse-status");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Dynamic update: refresh icon/tooltip/onClick when status/error change
  useEffect(() => {
    updateItem("sse-status", {
      icon: <StatusDot color={cfg.color} />,
      tooltip: error ? `${cfg.label} — ${error}` : cfg.label,
      onClick: reconnect,
    });
  }, [status, error, cfg, updateItem, reconnect]);

  return null;
}
