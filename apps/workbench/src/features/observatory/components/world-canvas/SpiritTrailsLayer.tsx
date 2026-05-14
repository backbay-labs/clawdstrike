import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import type { RefObject } from "react";
import type { SpiritMood } from "@/features/spirit/types";
import type { ObservatoryPlayerFocusState } from "../flow-runtime/grounding";

const MAX_TRAIL_POINTS = 150;
const TRAIL_SAMPLE_DISTANCE = 8;
const FADE_START_FRACTION = 0.75;

interface MoodConfig {
  opacityBase: number;
  widthBase: number;
  pulse: boolean;
}

const MOOD_CONFIG: Record<SpiritMood, MoodConfig> = {
  idle:    { opacityBase: 0.25, widthBase: 0.8,  pulse: false },
  active:  { opacityBase: 0.55, widthBase: 1.2,  pulse: false },
  alert:   { opacityBase: 0.7,  widthBase: 1.5,  pulse: true  },
  dormant: { opacityBase: 0.1,  widthBase: 0.5,  pulse: false },
};

export interface SpiritTrailsLayerProps {
  spiritAccentColor: string;
  spiritMood: SpiritMood;
  spiritLevel: number;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
}

export function SpiritTrailsLayer({
  spiritAccentColor,
  spiritMood,
  spiritLevel,
  playerFocusRef,
}: SpiritTrailsLayerProps) {
  const trailPointsRef = useRef<THREE.Vector3[]>([]);
  const versionRef = useRef(0);
  const lastSampledRef = useRef<THREE.Vector3 | null>(null);
  const pulseOpacityRef = useRef<number>(0);

  useFrame(({ clock }) => {
    const focus = playerFocusRef.current;
    if (!focus) return;

    const [px, , pz] = focus.position;
    const newPoint = new THREE.Vector3(px, 2, pz);

    const last = lastSampledRef.current;
    const distSq = last
      ? (newPoint.x - last.x) ** 2 + (newPoint.z - last.z) ** 2
      : Infinity;

    if (distSq >= TRAIL_SAMPLE_DISTANCE * TRAIL_SAMPLE_DISTANCE) {
      trailPointsRef.current.push(newPoint);
      if (trailPointsRef.current.length > MAX_TRAIL_POINTS) {
        trailPointsRef.current.shift();
      }
      lastSampledRef.current = newPoint;
      versionRef.current++;
    }

    if (spiritMood === "alert") {
      const t = Math.sin(clock.elapsedTime * 4) * 0.5 + 0.5;
      pulseOpacityRef.current = MOOD_CONFIG.alert.opacityBase * (0.6 + t * 0.4);
    }
  });

  const points = trailPointsRef.current;
  if (points.length < 2) return null;

  const moodCfg = MOOD_CONFIG[spiritMood];
  const levelMultiplier = 0.3 + (spiritLevel - 1) * 0.175;
  const lineWidth = moodCfg.widthBase * levelMultiplier;
  const baseOpacity = spiritMood === "alert"
    ? pulseOpacityRef.current || moodCfg.opacityBase
    : moodCfg.opacityBase;
  const opacity = baseOpacity * levelMultiplier;

  const fadeEndIndex = Math.floor(points.length * (1 - FADE_START_FRACTION));
  const fadeSegmentPoints = points.slice(0, Math.min(fadeEndIndex + 1, points.length));
  const mainSegmentPoints = points.slice(Math.max(0, fadeEndIndex - 1));
  const color = new THREE.Color(spiritAccentColor);

  return (
    <group name="spirit-trails">
      {fadeSegmentPoints.length >= 2 && (
        <Line
          points={fadeSegmentPoints}
          color={color}
          lineWidth={lineWidth}
          transparent
          opacity={opacity * 0.35}
          depthWrite={false}
          toneMapped={false}
        />
      )}
      {mainSegmentPoints.length >= 2 && (
        <Line
          points={mainSegmentPoints}
          color={color}
          lineWidth={lineWidth}
          transparent
          opacity={opacity}
          depthWrite={false}
          toneMapped={false}
        />
      )}
    </group>
  );
}
