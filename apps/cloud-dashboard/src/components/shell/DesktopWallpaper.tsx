const GRID_SVG = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60'%3E%3Cpath d='M60 0H0v60' fill='none' stroke='rgba(34,211,238,0.04)' stroke-width='0.5'/%3E%3C/svg%3E")`;

export function DesktopWallpaper() {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        background: `
          radial-gradient(ellipse 80% 60% at 50% 40%, rgba(34,211,238,0.06) 0%, transparent 70%),
          radial-gradient(ellipse 60% 50% at 80% 70%, rgba(139,92,246,0.04) 0%, transparent 60%),
          ${GRID_SVG},
          linear-gradient(180deg, #020410 0%, #02040a 50%, #030508 100%)
        `,
        pointerEvents: "none",
      }}
    >
      {/* noise grain overlay */}
      <svg
        style={{ position: "absolute", inset: 0, width: "100%", height: "100%", opacity: 0.04 }}
        aria-hidden
      >
        <filter id="wallpaper-noise">
          <feTurbulence type="fractalNoise" baseFrequency="0.65" numOctaves="3" stitchTiles="stitch" />
        </filter>
        <rect width="100%" height="100%" filter="url(#wallpaper-noise)" />
      </svg>
    </div>
  );
}
