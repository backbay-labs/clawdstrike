/**
 * CyberNexusOrb - global mode dial + home route anchor.
 */
import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  CYBER_NEXUS_MODE_EVENT,
  cycleNexusOperationMode,
  getNexusModeDescriptor,
  getNexusOperationMode,
  NEXUS_MODES,
  setNexusOperationMode,
} from "@/features/cyber-nexus/mode";
import type { NexusOperationMode } from "@/features/cyber-nexus/types";

const LONG_PRESS_MS = 420;

export function CyberNexusOrb() {
  const navigate = useNavigate();
  const location = useLocation();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const pressTimerRef = useRef<number | null>(null);
  const [mode, setMode] = useState<NexusOperationMode>(() => getNexusOperationMode());
  const [menuOpen, setMenuOpen] = useState(false);
  const isActive = location.pathname.startsWith("/cyber-nexus");
  const descriptor = useMemo(() => getNexusModeDescriptor(mode), [mode]);
  const modeIndex = useMemo(() => NEXUS_MODES.findIndex((entry) => entry.id === mode), [mode]);

  useEffect(() => {
    const listener = (event: Event) => {
      const next = (event as CustomEvent<NexusOperationMode>).detail;
      if (!next) return;
      setMode(next);
    };

    window.addEventListener(CYBER_NEXUS_MODE_EVENT, listener);
    return () => window.removeEventListener(CYBER_NEXUS_MODE_EVENT, listener);
  }, []);

  useEffect(() => {
    if (!menuOpen) return;

    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null;
      if (!target) return;
      if (!containerRef.current?.contains(target)) {
        setMenuOpen(false);
      }
    };

    window.addEventListener("pointerdown", onPointerDown);
    return () => window.removeEventListener("pointerdown", onPointerDown);
  }, [menuOpen]);

  const cycleMode = () => {
    const next = cycleNexusOperationMode(mode);
    setNexusOperationMode(next);
    setMode(next);
  };

  const clearHoldTimer = () => {
    if (pressTimerRef.current === null) return;
    window.clearTimeout(pressTimerRef.current);
    pressTimerRef.current = null;
  };

  const handlePressStart = () => {
    clearHoldTimer();
    pressTimerRef.current = window.setTimeout(() => {
      setMenuOpen(true);
      pressTimerRef.current = null;
    }, LONG_PRESS_MS);
  };

  const handleSelectMode = (nextMode: NexusOperationMode) => {
    setNexusOperationMode(nextMode);
    setMode(nextMode);
    setMenuOpen(false);
    if (!location.pathname.startsWith("/cyber-nexus")) {
      navigate("/cyber-nexus");
    }
  };

  const handleClick = () => {
    cycleMode();
    if (!isActive) {
      navigate("/cyber-nexus");
    }
  };

  return (
    <>
      <div ref={containerRef} className="relative">
        <button
          type="button"
          className={`nexus-orb ${isActive ? "active" : ""}`}
          onClick={handleClick}
          onContextMenu={(event) => {
            event.preventDefault();
            setMenuOpen((value) => !value);
          }}
          onPointerDown={handlePressStart}
          onPointerUp={clearHoldTimer}
          onPointerLeave={clearHoldTimer}
          onPointerCancel={clearHoldTimer}
          title={`${descriptor.label}: ${descriptor.description}`}
          aria-label={`Nexus mode ${descriptor.label}. ${descriptor.description}`}
          data-tone={descriptor.tone}
        >
          <div className="nexus-orb-glow" />
          <div className="nexus-orb-mode-ring" data-mode-index={modeIndex} data-tone={descriptor.tone} />
          <div className="nexus-orb-visual">
            <NexusIcon />
          </div>
          <div className="nexus-orb-tooltip">
            <div className="nexus-orb-tooltip-title">{descriptor.label}</div>
            <div className="nexus-orb-tooltip-copy">{descriptor.description}</div>
          </div>
        </button>

        {menuOpen ? (
          <div className="nexus-orb-mode-menu" role="menu" aria-label="Nexus modes">
            {NEXUS_MODES.map((entry, index) => (
              <button
                key={entry.id}
                type="button"
                role="menuitemradio"
                aria-checked={entry.id === mode}
                data-active={entry.id === mode ? "true" : "false"}
                data-tone={entry.tone}
                className="nexus-orb-mode-menu-item origin-focus-ring"
                style={{ "--orb-menu-angle": `${index * 90}deg` } as CSSProperties}
                onClick={() => handleSelectMode(entry.id)}
              >
                {entry.label}
              </button>
            ))}
          </div>
        ) : null}
      </div>

      <div className="nexus-divider" />
    </>
  );
}

function NexusIcon() {
  return (
    <svg
      className="nexus-orb-icon"
      viewBox="0 0 24 24"
      width="28"
      height="28"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" opacity="0.4" />
      <circle cx="12" cy="12" r="5" fill="currentColor" opacity="0.3" />
      <path d="M12 3a9 9 0 0 1 6.36 2.64" opacity="0.6" />
      <circle cx="12" cy="12" r="2" fill="currentColor" />
      <ellipse cx="12" cy="12" rx="9" ry="3" transform="rotate(-30 12 12)" opacity="0.2" />
    </svg>
  );
}

export default CyberNexusOrb;
