import { GlassButton } from "../ui";

const SPEEDS = [1, 2, 5, 10];

export function PlaybackControls({
  playing,
  onPlayPause,
  speed,
  onSpeedChange,
  position,
  total,
  onSeek,
}: {
  playing: boolean;
  onPlayPause: () => void;
  speed: number;
  onSpeedChange: (speed: number) => void;
  position: number;
  total: number;
  onSeek: (position: number) => void;
}) {
  return (
    <div
      className="glass-panel"
      style={{ padding: "8px 16px", display: "flex", alignItems: "center", gap: 12 }}
    >
      <GlassButton onClick={onPlayPause}>{playing ? "\u23F8" : "\u25B6"}</GlassButton>
      <div style={{ display: "flex", gap: 4 }}>
        {SPEEDS.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onSpeedChange(s)}
            className="font-mono"
            style={{
              padding: "2px 8px",
              borderRadius: 4,
              border: "1px solid var(--slate)",
              background: speed === s ? "var(--gold)" : "transparent",
              color: speed === s ? "var(--void)" : "var(--muted)",
              fontSize: 10,
              cursor: "pointer",
            }}
          >
            {s}x
          </button>
        ))}
      </div>
      <input
        type="range"
        min={0}
        max={Math.max(total - 1, 0)}
        value={position}
        onChange={(e) => onSeek(+e.target.value)}
        style={{ flex: 1, accentColor: "var(--gold)" }}
      />
      <span
        className="font-mono"
        style={{ fontSize: 11, color: "var(--muted)", whiteSpace: "nowrap" }}
      >
        {total === 0 ? "— / —" : `${position + 1} / ${total}`}
      </span>
    </div>
  );
}
