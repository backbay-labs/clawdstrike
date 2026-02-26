const GRID_SVG = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='60' height='60'%3E%3Cpath d='M60 0H0v60' fill='none' stroke='rgba(34,211,238,0.04)' stroke-width='0.5'/%3E%3C/svg%3E")`;

const NOISE_BG = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.65' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`;

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
      {/* noise grain overlay — tiled CSS background instead of full-viewport SVG filter */}
      <div
        aria-hidden
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage: NOISE_BG,
          backgroundRepeat: "repeat",
          opacity: 0.04,
          pointerEvents: "none",
        }}
      />
    </div>
  );
}
