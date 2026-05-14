/**
 * ObservatorySpaceLanes.tsx — Phase 22 SPC-05 + SPC-06
 *
 * Emissive CatmullRom TubeGeometry lanes connecting adjacent stations with
 * animated energy flow (dash-offset scroll) and wawa-vfx particle streams.
 *
 * Lanes (4 pairs):
 *   signal -> targets -> run -> receipts -> case-notes
 *
 * Visual approach:
 *   SPC-05: TubeGeometry with ShaderMaterial — scrolling dash pattern via dashOffset uniform,
 *           AdditiveBlending + toneMapped:false for bloom glow
 *   SPC-06: VFXEmitter per lane using "lane-particle-stream" pool,
 *           position updated each frame along the CatmullRom curve tangent
 */

import { useRef, useMemo } from "react";
import { useFrame } from "@react-three/fiber";
import { VFXEmitter, type VFXEmitterSettings } from "wawa-vfx";
import * as THREE from "three";
import {
  OBSERVATORY_STATION_POSITIONS,
  buildLanePoints,
  type ObservatoryVec3,
} from "../../world/observatory-world-template";
import type { HuntStationId } from "../../world/types";

// ---------------------------------------------------------------------------
// Lane topology — 4 adjacent station pairs (matches LANE_PAIRS in deriveObservatoryWorld)
// ---------------------------------------------------------------------------

const SPACE_LANE_PAIRS: Array<[HuntStationId, HuntStationId]> = [
  ["signal", "targets"],
  ["targets", "run"],
  ["run", "receipts"],
  ["receipts", "case-notes"],
];

// Lane accent color — bright cyan-blue, consistent with station theme
const LANE_COLOR = new THREE.Color("#4488ff");

// Tube geometry parameters (SPC-05)
const TUBE_RADIUS = 0.3;
const TUBE_SEGMENTS = 64;
const TUBE_RADIAL_SEGMENTS = 8;

// Dash animation speed — ~3 units/s scroll (CONTEXT.md spec)
const DASH_SPEED = 3.0;

// Particle emission settings (SPC-06)
const LANE_PARTICLE_SETTINGS: VFXEmitterSettings = {
  spawnMode: "time",
  nbParticles: 2,
  duration: 0.016,
  loop: false,
  particlesLifetime: [1.8, 2.2],
  size: [0.15, 0.3],
  colorStart: ["#4488ff", "#66aaff"],
  colorEnd: ["#224488", "#1133aa"],
  directionMin: [0, 0, 0],
  directionMax: [0, 0, 0],
  speed: [18, 22],
};

// ---------------------------------------------------------------------------
// Vertex + Fragment shader for animated dash-offset energy tube
// ---------------------------------------------------------------------------

const VERT_SHADER = /* glsl */ `
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const FRAG_SHADER = /* glsl */ `
  uniform float dashOffset;
  uniform vec3 color;
  varying vec2 vUv;
  void main() {
    float pattern = step(0.5, fract(vUv.x * 8.0 + dashOffset));
    float alpha = pattern * 0.7;
    gl_FragColor = vec4(color, alpha);
  }
`;

// ---------------------------------------------------------------------------
// Build lane data (curves + geometries) once in useMemo
// ---------------------------------------------------------------------------

interface LaneData {
  key: string;
  curve: THREE.CatmullRomCurve3;
  geometry: THREE.TubeGeometry;
  materialRef: React.RefObject<THREE.ShaderMaterial | null>;
}

// Emitter ref interface (matches ShipThrusterVFX.tsx pattern)
interface VFXEmitterRef extends THREE.Object3D {
  startEmitting: (reset?: boolean) => void;
  stopEmitting: () => void;
  emitAtPos: (position: THREE.Vector3 | null, reset?: boolean) => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function ObservatorySpaceLanes() {
  // Per-lane emission progress trackers — t in [0, 1] along the curve
  const emitProgressRef = useRef<number[]>(SPACE_LANE_PAIRS.map(() => 0));
  // Per-lane emitter refs
  const emitterRefs = useRef<(VFXEmitterRef | null)[]>(SPACE_LANE_PAIRS.map(() => null));
  // Per-lane material refs for dashOffset animation
  const materialRefs = useRef<(THREE.ShaderMaterial | null)[]>(SPACE_LANE_PAIRS.map(() => null));

  // Pre-allocate reusable vectors
  const _emitPos = useRef(new THREE.Vector3()).current;
  const _emitDir = useRef(new THREE.Vector3()).current;

  // Build curves + geometries once
  const lanes = useMemo<LaneData[]>(() => {
    return SPACE_LANE_PAIRS.map(([fromId, toId]) => {
      const fromPos: ObservatoryVec3 = OBSERVATORY_STATION_POSITIONS[fromId];
      const toPos: ObservatoryVec3 = OBSERVATORY_STATION_POSITIONS[toId];

      // Get 25 CatmullRom-interpolated points with Y-lift midpoint
      const pts = buildLanePoints(fromPos, toPos, "flow");
      const curve = new THREE.CatmullRomCurve3(
        pts.map((p) => new THREE.Vector3(p[0], p[1], p[2])),
      );

      const geometry = new THREE.TubeGeometry(
        curve,
        TUBE_SEGMENTS,
        TUBE_RADIUS,
        TUBE_RADIAL_SEGMENTS,
        false,
      );

      return {
        key: `space-lane-${fromId}-${toId}`,
        curve,
        geometry,
        // materialRef is managed via the materialRefs array instead
        materialRef: { current: null } as React.RefObject<THREE.ShaderMaterial | null>,
      };
    });
  }, []);

  // Animate dashOffset each frame + emit particles along the curve
  useFrame((_state, delta) => {
    for (let i = 0; i < lanes.length; i++) {
      const mat = materialRefs.current[i];
      if (mat) {
        mat.uniforms.dashOffset.value += delta * DASH_SPEED;
      }

      // Advance emission progress along the curve
      const lane = lanes[i];
      const emitter = emitterRefs.current[i];
      if (emitter && lane) {
        // Advance t by delta * 0.4 so particles cycle in ~2.5s per pass
        const prev = emitProgressRef.current[i];
        const next = (prev + delta * 0.4) % 1.0;
        emitProgressRef.current[i] = next;

        // Get world position + tangent at current t
        lane.curve.getPointAt(next, _emitPos);
        lane.curve.getTangentAt(next, _emitDir).normalize();

        // Update emitter world position and fire
        emitter.position.copy(_emitPos);
        emitter.startEmitting(false);
      }
    }
  });

  return (
    <group name="observatory-space-lanes">
      {lanes.map((lane, i) => (
        <group key={lane.key}>
          {/* SPC-05: Emissive tube with scrolling dash-offset energy flow */}
          <mesh geometry={lane.geometry}>
            <shaderMaterial
              ref={(el: THREE.ShaderMaterial | null) => {
                materialRefs.current[i] = el;
              }}
              vertexShader={VERT_SHADER}
              fragmentShader={FRAG_SHADER}
              uniforms={{
                dashOffset: { value: (i * 2.1) },
                color: { value: LANE_COLOR },
              }}
              transparent
              depthWrite={false}
              blending={THREE.AdditiveBlending}
              toneMapped={false}
              side={THREE.DoubleSide}
            />
          </mesh>
          {/* SPC-06: Particle emitter streaming along the curve */}
          <VFXEmitter
            ref={(el: VFXEmitterRef | null) => {
              emitterRefs.current[i] = el;
            }}
            emitter="lane-particle-stream"
            settings={LANE_PARTICLE_SETTINGS}
            autoStart={false}
          />
        </group>
      ))}
    </group>
  );
}
