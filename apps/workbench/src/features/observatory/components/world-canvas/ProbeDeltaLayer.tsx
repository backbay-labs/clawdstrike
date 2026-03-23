/**
 * ProbeDeltaLayer.tsx — Phase 40 PRBI-05
 *
 * Manages the lifecycle of the floating ProbeDeltaCard: shows a single card
 * 8 units above the target station when probe guidance is active, auto-dismisses
 * after 8 seconds with a 0.5s opacity fade, and dismisses on any keypress or
 * card click. Replaces the previous card immediately when a new probe targets
 * a different station.
 *
 * Rendering: drei <Html transform sprite> places a DOM card in 3D space above
 * the station. distanceFactor={80} ensures readable text at typical orbit distance.
 */

import { useEffect, useRef, useState, type JSX } from "react";
import { Html } from "@react-three/drei";
import type { ObservatoryProbeGuidance } from "../../world/observatory-recommendations";
import type { HuntStationId } from "../../world/types";
import { ProbeDeltaCard } from "./ProbeDeltaCard";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Card stays visible for this long before starting the fade. */
const AUTO_DISMISS_DELAY_MS = 7500;
/** Card fully dismissed after visible + fade duration. */
const AUTO_DISMISS_TOTAL_MS = 8000;
/** drei Html distance factor for readable card scale at typical orbit distance. */
const DISTANCE_FACTOR = 80;
/** Units above the station Y position to render the card. */
const CARD_Y_OFFSET = 8;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ProbeDeltaLayerProps {
  /** Current probe guidance. null = no probe active or in ready state. */
  probeGuidance: ObservatoryProbeGuidance | null;
  /** Station world positions, keyed by station ID. */
  stationPositions: Record<HuntStationId, readonly [number, number, number]>;
}

interface ActiveCard {
  guidance: ObservatoryProbeGuidance;
  showAtMs: number;
  opacity: number;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ProbeDeltaLayer({
  probeGuidance,
  stationPositions,
}: ProbeDeltaLayerProps): JSX.Element | null {
  const [activeCard, setActiveCard] = useState<ActiveCard | null>(null);
  const dismissTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fadeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function clearTimers() {
    if (dismissTimerRef.current !== null) {
      clearTimeout(dismissTimerRef.current);
      dismissTimerRef.current = null;
    }
    if (fadeTimerRef.current !== null) {
      clearTimeout(fadeTimerRef.current);
      fadeTimerRef.current = null;
    }
  }

  function dismiss() {
    clearTimers();
    setActiveCard(null);
  }

  // ---------------------------------------------------------------------------
  // Activate / replace card when probeGuidance changes
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (probeGuidance === null) {
      // Guidance cleared — dismiss any active card
      dismiss();
      return;
    }

    // Replace if different guidance (new station or new guidance object)
    setActiveCard((prev) => {
      // Same guidance object identity — no change needed
      if (prev !== null && prev.guidance === probeGuidance) {
        return prev;
      }
      // Clear old timers before starting new ones
      clearTimers();
      return { guidance: probeGuidance, showAtMs: Date.now(), opacity: 1 };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [probeGuidance]);

  // ---------------------------------------------------------------------------
  // Auto-dismiss timer
  // ---------------------------------------------------------------------------

  useEffect(() => {
    if (activeCard === null) {
      return;
    }

    // After 7.5s begin fade
    fadeTimerRef.current = setTimeout(() => {
      setActiveCard((prev) => (prev !== null ? { ...prev, opacity: 0 } : null));
    }, AUTO_DISMISS_DELAY_MS);

    // After 8s remove card entirely
    dismissTimerRef.current = setTimeout(() => {
      setActiveCard(null);
    }, AUTO_DISMISS_TOTAL_MS);

    return () => {
      clearTimers();
    };
    // Re-run whenever a new card is installed (guidance reference changes)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCard?.guidance]);

  // ---------------------------------------------------------------------------
  // Keypress dismiss
  // ---------------------------------------------------------------------------

  useEffect(() => {
    function handleKeyDown() {
      dismiss();
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  if (activeCard === null) {
    return null;
  }

  const stationPos = stationPositions[activeCard.guidance.stationId];
  if (!stationPos) {
    return null;
  }

  const stationX = stationPos[0];
  const stationY = stationPos[1];
  const stationZ = stationPos[2];

  return (
    <group position={[stationX, stationY + CARD_Y_OFFSET, stationZ]}>
      <Html
        transform
        distanceFactor={DISTANCE_FACTOR}
        sprite
        style={{
          opacity: activeCard.opacity,
          transition: "opacity 0.5s ease-out",
        }}
      >
        <ProbeDeltaCard
          guidance={activeCard.guidance}
          onDismiss={dismiss}
        />
      </Html>
    </group>
  );
}
