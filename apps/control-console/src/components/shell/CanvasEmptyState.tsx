export interface CanvasEmptyStateProps {
  onLaunch: () => void;
}

/**
 * Resting state of the OS canvas — shown when no window is open.
 * Gently teaches the surface: the canonical entry point is the Monitor.
 * Centered column; the integrator positions it to fill the canvas below the header.
 */
export function CanvasEmptyState({ onLaunch }: CanvasEmptyStateProps) {
  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexDirection: "column",
        gap: 14,
      }}
    >
      <p
        className="font-display"
        style={{
          margin: 0,
          fontSize: 18,
          color: "rgba(154,167,181,0.6)",
          lineHeight: 1.3,
        }}
      >
        No window open
      </p>
      <button
        type="button"
        onClick={onLaunch}
        className="font-mono cs-nav-focus"
        style={{
          padding: "8px 16px",
          borderRadius: 8,
          border: "1px solid var(--gold-edge)",
          background: "rgba(214,177,90,0.08)",
          color: "var(--gold)",
          fontSize: 10.5,
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          cursor: "pointer",
          transition: "background 0.14s ease, border-color 0.14s ease",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLButtonElement).style.background = "rgba(214,177,90,0.14)";
          (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(214,177,90,0.55)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLButtonElement).style.background = "rgba(214,177,90,0.08)";
          (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--gold-edge)";
        }}
        aria-label="Launch Monitor"
      >
        Launch Monitor
      </button>
    </div>
  );
}
