import { Sparkles } from "@react-three/drei";
import { useThree } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import type { ObservatoryWeatherState } from "../../world/observatory-weather";

export interface ObservatoryWeatherLayerProps {
  weatherState: ObservatoryWeatherState;
}

/**
 * ObservatoryWeatherLayer — atmospheric effects driven by effectiveWeatherState.
 *
 * Three effects rendered as a single fragment:
 * 1. FOG MODULATION — mutates scene.fog.density (FogExp2) by weatherState.density * 0.006
 *    capped at +0.0007; restored on unmount.
 * 2. AMBIENT TINT LIGHT — pointLight at Y=60 using weatherState.tint, intensity ∝ density.
 * 3. ATMOSPHERIC PARTICLES — <Sparkles> scaled to budget and density. Not rendered when count=0.
 */
export function ObservatoryWeatherLayer({ weatherState }: ObservatoryWeatherLayerProps) {
  const { scene } = useThree();
  const originalFogDensityRef = useRef<number | null>(null);

  // FOG MODULATION
  useEffect(() => {
    if (!(scene.fog instanceof THREE.FogExp2)) {
      return;
    }

    // Capture the original density on first mount or when scene.fog changes.
    if (originalFogDensityRef.current === null) {
      originalFogDensityRef.current = scene.fog.density;
    }

    const base = originalFogDensityRef.current;
    // Cap the delta at +0.0007 regardless of density value.
    const delta = Math.min(weatherState.density * 0.006, 0.0007);
    scene.fog.density = base + delta;

    return () => {
      // Restore original density on unmount or before next effect run.
      if (scene.fog instanceof THREE.FogExp2 && originalFogDensityRef.current !== null) {
        scene.fog.density = originalFogDensityRef.current;
      }
    };
  }, [scene, weatherState.density, weatherState.tint, weatherState.style]);

  // AMBIENT TINT LIGHT — intensity proportional to density, zero when density=0.
  const lightIntensity = weatherState.density * 3.5;

  // ATMOSPHERIC PARTICLES — count scaled to budget and density.
  const sparkleCount = useMemo(() => {
    const multiplier = weatherState.budget === "full" ? 600 : 280;
    return Math.round(weatherState.density * multiplier);
  }, [weatherState.budget, weatherState.density]);

  const sparkleOpacity = Math.min(weatherState.density * 1.8, 0.22);
  const sparkleSpeed = 0.04 + weatherState.phaseOffset * 0.02;

  return (
    <>
      <pointLight
        position={[0, 60, 0]}
        color={weatherState.tint}
        intensity={lightIntensity}
        distance={200}
        decay={2}
      />
      {sparkleCount > 0 ? (
        <Sparkles
          count={sparkleCount}
          size={0.8}
          speed={sparkleSpeed}
          opacity={sparkleOpacity}
          color={weatherState.tint}
          scale={[160, 80, 160]}
        />
      ) : null}
    </>
  );
}
