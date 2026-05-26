import { useId } from "react";

export interface BrandMarkProps {
  size?: number;
  showWordmark?: boolean;
  version?: string;
}

export function BrandMark({ size = 36, showWordmark = false, version = "0.2.0" }: BrandMarkProps) {
  // Unique id per instance prevents linearGradient id collisions when rendered twice
  const uid = useId().replace(/:/g, "");
  const gradientId = `cg-${uid}`;

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      {/* Engraved gold tile */}
      <div
        data-testid="brandmark-tile"
        style={{
          width: size,
          height: size,
          borderRadius: 9,
          background:
            "radial-gradient(circle at 30% 25%, rgba(214,177,90,0.35), rgba(214,177,90,0.05) 60%, transparent 70%), linear-gradient(180deg, #1a1410, #0a0807)",
          border: "1px solid rgba(214,177,90,0.42)",
          boxShadow: "inset 0 1px 0 rgba(255,220,140,0.18), 0 0 14px rgba(214,177,90,0.18)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          overflow: "hidden",
          position: "relative",
        }}
      >
        {/* C glyph — gradient fill on a graphic element is intentional and allowed */}
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <defs>
            <linearGradient
              id={gradientId}
              x1="0"
              y1="0"
              x2="0"
              y2="24"
              gradientUnits="userSpaceOnUse"
            >
              <stop offset="0" stopColor="#f3d889" />
              <stop offset="1" stopColor="#a07e2c" />
            </linearGradient>
          </defs>
          {/* C arc */}
          <path
            d="M18 6.5C16.5 4.5 14.4 3.5 12 3.5C7.3 3.5 3.5 7.3 3.5 12C3.5 16.7 7.3 20.5 12 20.5C14.4 20.5 16.5 19.5 18 17.5"
            stroke={`url(#${gradientId})`}
            strokeWidth="2.2"
            strokeLinecap="round"
          />
          {/* Claw accent */}
          <path
            d="M11 9.5L13 12L11 14.5"
            stroke="var(--crimson)"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
            opacity="0.9"
          />
        </svg>
      </div>

      {showWordmark && (
        <div style={{ display: "flex", flexDirection: "column", gap: 1, minWidth: 0 }}>
          {/* Solid gold — gradient text is explicitly banned for wordmarks */}
          <span
            className="font-display"
            style={{
              fontSize: 14,
              fontWeight: 600,
              letterSpacing: "0.04em",
              color: "var(--gold)",
            }}
          >
            clawdstrike
          </span>
          <span
            className="font-mono"
            style={{
              fontSize: 8.5,
              letterSpacing: "0.20em",
              textTransform: "uppercase",
              color: "rgba(154,167,181,0.55)",
            }}
          >
            Control Console · v{version}
          </span>
        </div>
      )}
    </div>
  );
}
