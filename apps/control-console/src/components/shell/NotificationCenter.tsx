import { useEffect, useRef, useState } from "react";
import type { AppNotification } from "../../hooks/useNotifications";
import { NoiseGrain } from "../ui";

function relativeTime(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "now";
  if (mins < 60) return `${mins}m`;
  return `${Math.floor(mins / 60)}h`;
}

const TYPE_COLORS: Record<string, string> = {
  info: "var(--teal)",
  warning: "var(--gold)",
  error: "var(--crimson)",
};

export function NotificationCenter({
  notifications,
  onMarkAllRead,
  onClear,
  unreadCount,
}: {
  notifications: AppNotification[];
  onMarkAllRead: () => void;
  onClear: () => void;
  unreadCount: number;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div
      ref={ref}
      style={{ position: "relative", height: "100%", display: "flex", alignItems: "center" }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        style={{
          background: "none",
          border: "none",
          cursor: "pointer",
          padding: "4px 8px",
          position: "relative",
          color: "var(--muted)",
          display: "flex",
          alignItems: "center",
        }}
      >
        <svg
          viewBox="0 0 24 24"
          width={16}
          height={16}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
        >
          <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0" />
        </svg>
        {unreadCount > 0 && (
          <span
            style={{
              position: "absolute",
              top: 0,
              right: 2,
              background: "var(--crimson)",
              color: "#fff",
              borderRadius: "50%",
              width: 14,
              height: 14,
              fontSize: 9,
              fontWeight: 700,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div
          className="glass-panel"
          style={{
            position: "absolute",
            bottom: "100%",
            right: 0,
            marginBottom: 6,
            width: 320,
            maxHeight: 400,
            overflow: "hidden",
            display: "flex",
            flexDirection: "column",
          }}
        >
          <NoiseGrain />
          <div
            style={{
              position: "relative",
              zIndex: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "10px 14px",
              borderBottom: "1px solid var(--slate)",
            }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 10,
                textTransform: "uppercase",
                letterSpacing: "0.1em",
                color: "var(--gold)",
              }}
            >
              Notifications
            </span>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                onClick={onMarkAllRead}
                className="font-mono"
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--muted)",
                  fontSize: 10,
                  cursor: "pointer",
                }}
              >
                Mark read
              </button>
              <button
                type="button"
                onClick={onClear}
                className="font-mono"
                style={{
                  background: "none",
                  border: "none",
                  color: "var(--muted)",
                  fontSize: 10,
                  cursor: "pointer",
                }}
              >
                Clear
              </button>
            </div>
          </div>
          <div style={{ position: "relative", zIndex: 2, overflowY: "auto", flex: 1 }}>
            {notifications.length === 0 ? (
              <div
                className="font-mono"
                style={{
                  padding: 20,
                  textAlign: "center",
                  fontSize: 11,
                  color: "rgba(154,167,181,0.4)",
                }}
              >
                No notifications
              </div>
            ) : (
              notifications.map((n) => (
                <div
                  key={n.id}
                  style={{
                    padding: "8px 14px",
                    display: "flex",
                    gap: 8,
                    alignItems: "flex-start",
                    background: n.read ? "transparent" : "rgba(214,177,90,0.03)",
                    borderBottom: "1px solid rgba(27,34,48,0.3)",
                  }}
                >
                  <span
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: TYPE_COLORS[n.type] || "var(--muted)",
                      flexShrink: 0,
                      marginTop: 4,
                    }}
                  />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p
                      className="font-body"
                      style={{ fontSize: 12, color: "var(--text)", margin: 0, lineHeight: 1.4 }}
                    >
                      {n.message}
                    </p>
                    <p
                      className="font-mono"
                      style={{
                        fontSize: 9,
                        color: "rgba(154,167,181,0.4)",
                        margin: "2px 0 0",
                        letterSpacing: "0.04em",
                      }}
                    >
                      {relativeTime(n.timestamp)}
                    </p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
