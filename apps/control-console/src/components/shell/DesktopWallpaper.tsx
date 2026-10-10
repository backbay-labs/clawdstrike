import { useEffect, useState } from "react";
import { WALLPAPERS } from "../../state/wallpapers";

const NOISE_BG = `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")`;

const WALLPAPER_CHANGED_EVENT = "clawdstrike:wallpaper-changed";

function getWallpaperGradient(): string {
  const id = localStorage.getItem("cs_wallpaper") || "default";
  const wp = WALLPAPERS.find((w) => w.id === id);
  return wp?.gradient ?? WALLPAPERS[0].gradient;
}

export function DesktopWallpaper() {
  const [gradient, setGradient] = useState(getWallpaperGradient);

  useEffect(() => {
    const handler = () => setGradient(getWallpaperGradient());
    window.addEventListener(WALLPAPER_CHANGED_EVENT, handler);
    return () => window.removeEventListener(WALLPAPER_CHANGED_EVENT, handler);
  }, []);

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        background: gradient,
        pointerEvents: "none",
      }}
    >
      {/* dot grid — faint forged lattice, masked to a central bloom */}
      <div
        aria-hidden
        style={{
          position: "absolute",
          inset: 0,
          opacity: 0.5,
          backgroundImage: "radial-gradient(rgba(214,177,90,0.05) 1px, transparent 1px)",
          backgroundSize: "32px 32px",
          maskImage: "radial-gradient(ellipse at center, black 30%, transparent 80%)",
          WebkitMaskImage: "radial-gradient(ellipse at center, black 30%, transparent 80%)",
          pointerEvents: "none",
        }}
      />

      {/* noise grain overlay */}
      <div
        aria-hidden
        style={{
          position: "absolute",
          inset: 0,
          backgroundImage: NOISE_BG,
          backgroundRepeat: "repeat",
          opacity: 0.03,
          pointerEvents: "none",
        }}
      />

      {/* engraved brand watermark — solid gold wordmark, never gradient text */}
      <div
        aria-hidden
        className="font-display"
        style={{
          position: "absolute",
          bottom: "8%",
          right: "4%",
          fontWeight: 600,
          fontSize: 240,
          letterSpacing: "-0.04em",
          lineHeight: 0.8,
          color: "var(--gold)",
          opacity: 0.04,
          userSelect: "none",
          pointerEvents: "none",
        }}
      >
        cs
      </div>
    </div>
  );
}
