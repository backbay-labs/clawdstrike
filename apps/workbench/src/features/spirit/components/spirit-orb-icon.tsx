// apps/workbench/src/features/spirit/components/spirit-orb-icon.tsx

interface SpiritOrbIconProps {
  accentColor: string; // hex color string e.g. "#3dbf84"
  size?: number; // default 16 — matches activity bar icon size
}

export function SpiritOrbIcon({ accentColor, size = 16 }: SpiritOrbIconProps) {
  // Use CSS custom property so the hex string is preserved in the style value
  // (jsdom would otherwise normalize #rrggbb to rgb() in computed styles).
  // The gradient references --spirit-orb-color which retains the raw hex.
  return (
    <span
      aria-hidden
      data-accent-color={accentColor}
      style={
        {
          display: "inline-block",
          width: size,
          height: size,
          borderRadius: "50%",
          "--spirit-orb-color": accentColor,
          background: `radial-gradient(circle at 40% 40%, var(--spirit-orb-color) 0%, var(--spirit-orb-color) 60%, transparent 100%)`,
          boxShadow: `0 0 ${size * 0.5}px var(--spirit-orb-color)`,
          animation: "spirit-orb-pulse 2.4s ease-in-out infinite",
        } as React.CSSProperties
      }
    />
  );
}
