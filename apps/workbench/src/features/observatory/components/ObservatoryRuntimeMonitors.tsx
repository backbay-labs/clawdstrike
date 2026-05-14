import { PerformanceMonitor } from "@react-three/drei";
import { useFrame, useThree } from "@react-three/fiber";
import { useRef, type RefObject } from "react";
import type { ObservatoryPlayerFocusState } from "./flow-runtime/observatory-player-types";
import type { ObservatoryProbeState } from "../world/probeRuntime";
import type { ObservatoryRuntimeQuality } from "../utils/observatory-performance";

export interface ObservatoryRuntimeActivityMonitorProps {
  activeHeroInteractionActive: boolean;
  enabled: boolean;
  hasActiveEruptions: boolean;
  onHighActivityChange: (next: boolean) => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  probeStatus: ObservatoryProbeState["status"];
}

export function ObservatoryRuntimeActivityMonitor({
  activeHeroInteractionActive,
  enabled,
  hasActiveEruptions,
  onHighActivityChange,
  playerFocusRef,
  probeStatus,
}: ObservatoryRuntimeActivityMonitorProps) {
  const regress = useThree((state) => state.performance.regress);
  const previousHighActivityRef = useRef(false);

  useFrame(() => {
    const playerFocus = playerFocusRef.current;
    const highActivity =
      enabled
      && (
        probeStatus === "active"
        || hasActiveEruptions
        || activeHeroInteractionActive
        || playerFocus?.moving === true
        || playerFocus?.airborne === true
        || playerFocus?.sprinting === true
      );

    if (highActivity === previousHighActivityRef.current) {
      return;
    }

    previousHighActivityRef.current = highActivity;
    onHighActivityChange(highActivity);
    if (highActivity) {
      regress();
    }
  });

  return null;
}

export interface ObservatoryQualityMonitorProps {
  enabled: boolean;
  onQualityChange: (quality: ObservatoryRuntimeQuality) => void;
}

export function ObservatoryQualityMonitor({
  enabled,
  onQualityChange,
}: ObservatoryQualityMonitorProps) {
  if (!enabled) {
    return null;
  }

  return (
    <PerformanceMonitor
      bounds={(refreshrate) => [refreshrate * 0.5, refreshrate * 0.78]}
      flipflops={3}
      onChange={({ factor }) => {
        if (factor <= 0.4) {
          onQualityChange("low");
          return;
        }
        if (factor <= 0.72) {
          onQualityChange("balanced");
          return;
        }
        onQualityChange("high");
      }}
      onDecline={() => onQualityChange("low")}
      onFallback={() => onQualityChange("low")}
      onIncline={() => onQualityChange("high")}
    />
  );
}
