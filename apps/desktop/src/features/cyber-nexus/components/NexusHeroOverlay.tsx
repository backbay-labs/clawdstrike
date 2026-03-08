import { useCallback, useEffect, useState } from "react";

export interface NexusHeroOverlayProps {
  visible: boolean;
  onDismiss: () => void;
}

export function NexusHeroOverlay({ visible, onDismiss }: NexusHeroOverlayProps) {
  const [isExiting, setIsExiting] = useState(false);

  const handleDismiss = useCallback(() => {
    if (isExiting) return;
    setIsExiting(true);
    window.setTimeout(() => onDismiss(), 500);
  }, [isExiting, onDismiss]);

  useEffect(() => {
    if (!visible || isExiting) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Enter" || event.key === "Escape") {
        event.preventDefault();
        handleDismiss();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [handleDismiss, isExiting, visible]);

  if (!visible) return null;

  return (
    <div
      className={`nexus-hero-overlay ${isExiting ? "nexus-hero-overlay--exiting" : ""}`}
      role="dialog"
      aria-label="Open Huntronomer"
      onClick={handleDismiss}
    >
      <div className="nexus-hero-backdrop" />

      <div
        className="nexus-hero-content origin-chrome-panel rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="nexus-hero-sigil">
          <div className="nexus-hero-sigil-glow" />
          <span className="origin-glyph-orb" aria-hidden="true" />
        </div>

        <div>
          <div className="origin-label text-[10px] tracking-[0.18em]">
            Autonomous Threat Hunting
          </div>
          <h1 className="nexus-hero-title">Huntronomer</h1>
          <p className="nexus-hero-subtitle">
            Direct swarms. Track telemetry. Retask with intent.
          </p>
        </div>

        <button
          type="button"
          onClick={handleDismiss}
          className="origin-focus-ring origin-glass-button nexus-hero-enter-btn"
          data-active="true"
        >
          ENTER COMMAND DECK
        </button>
      </div>

      <div className="nexus-hero-corner nexus-hero-corner--tl" />
      <div className="nexus-hero-corner nexus-hero-corner--tr" />
      <div className="nexus-hero-corner nexus-hero-corner--bl" />
      <div className="nexus-hero-corner nexus-hero-corner--br" />
    </div>
  );
}

export default NexusHeroOverlay;
