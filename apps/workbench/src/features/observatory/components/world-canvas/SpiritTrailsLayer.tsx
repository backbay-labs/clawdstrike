/**
 * SpiritTrailsLayer.tsx — Phase 41 SPRT-01, SPRT-02, SPRT-03, SPRT-05
 *
 * Renders a luminous trail of the player's movement through the observatory.
 * Trail visuals are driven by spirit mood and XP level.
 *
 * - Trail color matches spirit accent color
 * - Mood controls opacity/width (idle=dim, active=bright, alert=pulsing)
 * - Level multiplier scales intensity from 0.3 (level 1, faint) to 1.0 (level 5, vivid)
 * - Fixed-capacity buffer: max 150 points with oldest quarter fading
 */

import { useRef } from "react";
import { useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import type { RefObject } from "react";
import type { SpiritMood } from "@/features/spirit/types";
import type { ObservatoryPlayerFocusState } from "../flow-runtime/grounding";

// ── Constants (SPRT-05 locked) ────────────────────────────────────────────────

/** Maximum trail points — fixed capacity (SPRT-05 requirement). */
const MAX_TRAIL_POINTS = 150;

/** Minimum world-unit distance between consecutive trail samples to prevent clumping. */
const TRAIL_SAMPLE_DISTANCE = 8;

/** Fraction of trail length at which the oldest segment begins fading. */
const FADE_START_FRACTION = 0.75;

// ── Mood config (SPRT-02) ────────────────────────────────────────────────────

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

// ── Props ─────────────────────────────────────────────────────────────────────

export interface SpiritTrailsLayerProps {
  spiritAccentColor: string;
  spiritMood: SpiritMood;
  spiritLevel: number;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
}

// ── Component ─────────────────────────────────────────────────────────────────

export function SpiritTrailsLayer({
  spiritAccentColor,
  spiritMood,
  spiritLevel,
  playerFocusRef,
}: SpiritTrailsLayerProps) {
  /** Accumulated trail points (mutable, not React state to avoid re-renders per frame). */
  const trailPointsRef = useRef<THREE.Vector3[]>([]);
  /** Version counter to force re-render when trail changes. */
  const versionRef = useRef(0);
  /** Track last sampled position for distance comparison. */
  const lastSampledRef = useRef<THREE.Vector3 | null>(null);
  /** Current pulsing opacity for alert mood. */
  const pulseOpacityRef = useRef<number>(0);

  useFrame(({ clock }, _delta) => {
    const focus = playerFocusRef.current;
    if (!focus) return;

    const [px, py, pz] = focus.position;
    const newPoint = new THREE.Vector3(px, 2, pz); // Y=2 slightly above ground

    // Sample only if moved far enough from last point
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

    // Compute alert pulse opacity
    if (spiritMood === "alert") {
      const moodCfg = MOOD_CONFIG.alert;
      const t = Math.sin(clock.elapsedTime * 4) * 0.5 + 0.5; // 0..1
      pulseOpacityRef.current = moodCfg.opacityBase * (0.6 + t * 0.4);
    }
  });

  const points = trailPointsRef.current;
  if (points.length < 2) return null;

  const moodCfg = MOOD_CONFIG[spiritMood];

  // Level-driven intensity: level 1 = 0.3 (faint wisps), level 5 = 1.0 (vivid ribbons)
  const levelMultiplier = 0.3 + (spiritLevel - 1) * 0.175;

  const lineWidth = moodCfg.widthBase * levelMultiplier;
  const baseOpacity = spiritMood === "alert"
    ? pulseOpacityRef.current || moodCfg.opacityBase
    : moodCfg.opacityBase;
  const opacity = baseOpacity * levelMultiplier;

  // Split into fade segment (oldest quarter) and main segment (newest 75%)
  const fadeEndIndex = Math.floor(points.length * (1 - FADE_START_FRACTION));

  // Oldest quarter: fade segment at 35% of opacity
  const fadeSegmentPoints = points.slice(0, Math.min(fadeEndIndex + 1, points.length));
  // Newest 75%: full opacity, overlaps by 1 point for visual continuity
  const mainSegmentPoints = points.slice(Math.max(0, fadeEndIndex - 1));

  const color = new THREE.Color(spiritAccentColor);

  return (
    <group name="spirit-trails">
      {/* Faded oldest quarter */}
      {fadeSegmentPoints.length >= 2 ? (
        <Line
          points={fadeSegmentPoints}
          color={color}
          lineWidth={lineWidth}
          transparent
          opacity={opacity * 0.35}
          depthWrite={false}
          toneMapped={false}
        />
      ) : null}
      {/* Full-opacity newest 75% */}
      {mainSegmentPoints.length >= 2 ? (
        <Line
          points={mainSegmentPoints}
          color={color}
          lineWidth={lineWidth}
          transparent
          opacity={opacity}
          depthWrite={false}
          toneMapped={false}
        />
      ) : null}
    </group>
  );
}
