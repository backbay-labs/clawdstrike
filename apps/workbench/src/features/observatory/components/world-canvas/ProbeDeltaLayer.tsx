import { useEffect, useRef, useState, type JSX } from "react";
import { Html } from "@react-three/drei";
import type { ObservatoryProbeGuidance } from "../../world/observatory-recommendations";
import type { HuntStationId } from "../../world/types";
import { ProbeDeltaCard } from "./ProbeDeltaCard";

const AUTO_DISMISS_DELAY_MS = 7500;
const AUTO_DISMISS_TOTAL_MS = 8000;
const DISTANCE_FACTOR = 80;
const CARD_Y_OFFSET = 8;

export interface ProbeDeltaLayerProps {
  probeGuidance: ObservatoryProbeGuidance | null;
  stationPositions: Record<HuntStationId, readonly [number, number, number]>;
}

interface ActiveCard {
  guidance: ObservatoryProbeGuidance;
  showAtMs: number;
  opacity: number;
}

export function ProbeDeltaLayer({
  probeGuidance,
  stationPositions,
}: ProbeDeltaLayerProps): JSX.Element | null {
  const [activeCard, setActiveCard] = useState<ActiveCard | null>(null);
  const dismissTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fadeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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

  useEffect(() => {
    if (probeGuidance === null) {
      dismiss();
      return;
    }

    setActiveCard((prev) => {
      if (prev !== null && prev.guidance === probeGuidance) return prev;
      clearTimers();
      return { guidance: probeGuidance, showAtMs: Date.now(), opacity: 1 };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [probeGuidance]);

  useEffect(() => {
    if (activeCard === null) return;

    fadeTimerRef.current = setTimeout(() => {
      setActiveCard((prev) => (prev !== null ? { ...prev, opacity: 0 } : null));
    }, AUTO_DISMISS_DELAY_MS);

    dismissTimerRef.current = setTimeout(() => {
      setActiveCard(null);
    }, AUTO_DISMISS_TOTAL_MS);

    return () => clearTimers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeCard?.guidance]);

  useEffect(() => {
    window.addEventListener("keydown", dismiss);
    return () => window.removeEventListener("keydown", dismiss);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (activeCard === null) return null;

  const stationPos = stationPositions[activeCard.guidance.stationId];
  if (!stationPos) return null;

  return (
    <group position={[stationPos[0], stationPos[1] + CARD_Y_OFFSET, stationPos[2]]}>
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
