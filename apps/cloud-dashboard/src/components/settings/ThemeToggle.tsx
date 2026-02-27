export function ThemeToggle({
  theme,
  onToggle,
}: {
  theme: "dark" | "light";
  onToggle: () => void;
}) {
  const isLight = theme === "light";

  return (
    <div className="relative z-10 space-y-3">
      <p
        className="font-mono text-[10px]"
        style={{
          color: "rgba(214,177,90,0.55)",
          textTransform: "uppercase",
          letterSpacing: "0.1em",
        }}
      >
        Color Theme
      </p>
      <button
        type="button"
        onClick={onToggle}
        className="flex items-center rounded-full transition-colors duration-200"
        style={{
          width: 72,
          height: 34,
          background: "rgba(27,34,48,0.6)",
          border: "1px solid rgba(214,177,90,0.25)",
          position: "relative",
          cursor: "pointer",
          padding: 3,
        }}
      >
        {/* Moon icon (dark) */}
        <span
          className="flex items-center justify-center rounded-full transition-all duration-200"
          style={{
            width: 26,
            height: 26,
            background: !isLight ? "#d6b15a" : "transparent",
            position: "absolute",
            left: 3,
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke={!isLight ? "#0b0d10" : "rgba(229,231,235,0.3)"}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
        </span>
        {/* Sun icon (light) */}
        <span
          className="flex items-center justify-center rounded-full transition-all duration-200"
          style={{
            width: 26,
            height: 26,
            background: isLight ? "#d6b15a" : "transparent",
            position: "absolute",
            right: 3,
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke={isLight ? "#0b0d10" : "rgba(229,231,235,0.3)"}
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="5" />
            <line x1="12" y1="1" x2="12" y2="3" />
            <line x1="12" y1="21" x2="12" y2="23" />
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
            <line x1="1" y1="12" x2="3" y2="12" />
            <line x1="21" y1="12" x2="23" y2="12" />
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
          </svg>
        </span>
      </button>
      <p
        className="font-body text-xs"
        style={{ color: "rgba(229,231,235,0.4)" }}
      >
        Currently using {isLight ? "light" : "dark"} mode. Theme applies to all panels and
        overlays.
      </p>
    </div>
  );
}
