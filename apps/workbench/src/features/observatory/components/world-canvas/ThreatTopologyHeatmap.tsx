import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { WORLD_RADIUS, OBSERVATORY_STATION_POSITIONS } from "../../world/observatory-world-template";
import { HUNT_STATION_ORDER } from "../../world/stations";
import type { HuntStationId } from "../../world/types";

// blue (calm) → teal (low) → green (moderate-low) → yellow (moderate) → amber (elevated) → red (critical)
export const HEATMAP_SOC_COLORS: THREE.Color[] = [
  new THREE.Color("#1a5fb4"),
  new THREE.Color("#26a269"),
  new THREE.Color("#33d17a"),
  new THREE.Color("#f5c211"),
  new THREE.Color("#e66100"),
  new THREE.Color("#c01c28"),
];

const VERTEX_SHADER = /* glsl */ `
  varying vec2 vWorldXZ;
  void main() {
    vec4 worldPos = modelMatrix * vec4(position, 1.0);
    vWorldXZ = worldPos.xz;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const FRAGMENT_SHADER = /* glsl */ `
  uniform vec2 uStation0;
  uniform vec2 uStation1;
  uniform vec2 uStation2;
  uniform vec2 uStation3;
  uniform vec2 uStation4;
  uniform vec2 uStation5;

  uniform float uPressure0;
  uniform float uPressure1;
  uniform float uPressure2;
  uniform float uPressure3;
  uniform float uPressure4;
  uniform float uPressure5;

  uniform vec3 uColor0;
  uniform vec3 uColor1;
  uniform vec3 uColor2;
  uniform vec3 uColor3;
  uniform vec3 uColor4;
  uniform vec3 uColor5;

  uniform float uPulse;
  uniform float uOpacityMultiplier;

  varying vec2 vWorldXZ;

  vec3 socColorRamp(float t) {
    // Map t in [0,1] to SOC 6-stop color ramp via piecewise linear mix
    float s = clamp(t, 0.0, 1.0) * 5.0; // scale to [0,5]
    int idx = int(floor(s));
    float frac = fract(s);

    if (idx == 0) return mix(uColor0, uColor1, frac);
    if (idx == 1) return mix(uColor1, uColor2, frac);
    if (idx == 2) return mix(uColor2, uColor3, frac);
    if (idx == 3) return mix(uColor3, uColor4, frac);
    return mix(uColor4, uColor5, frac);
  }

  void main() {
    // Compute inverse-distance-weighted pressure blend for this fragment
    float eps = 1.0; // prevent division by zero
    float w0 = 1.0 / (distance(vWorldXZ, uStation0) + eps);
    float w1 = 1.0 / (distance(vWorldXZ, uStation1) + eps);
    float w2 = 1.0 / (distance(vWorldXZ, uStation2) + eps);
    float w3 = 1.0 / (distance(vWorldXZ, uStation3) + eps);
    float w4 = 1.0 / (distance(vWorldXZ, uStation4) + eps);
    float w5 = 1.0 / (distance(vWorldXZ, uStation5) + eps);

    float totalW = w0 + w1 + w2 + w3 + w4 + w5;
    float blendedPressure = (
      w0 * uPressure0 +
      w1 * uPressure1 +
      w2 * uPressure2 +
      w3 * uPressure3 +
      w4 * uPressure4 +
      w5 * uPressure5
    ) / totalW;

    vec3 color = socColorRamp(blendedPressure);
    float opacity = clamp(mix(0.3, 0.7, uPulse) * uOpacityMultiplier, 0.0, 1.0);

    gl_FragColor = vec4(color, opacity);
  }
`;

export interface ThreatTopologyHeatmapProps {
  pressureData: Float32Array;
  stationPositions: Record<HuntStationId, readonly [number, number, number]>;
  visible?: boolean;
  presetOpacityMultiplier?: number;
}

function colorToVec3(c: THREE.Color): THREE.Vector3 {
  return new THREE.Vector3(c.r, c.g, c.b);
}

export function ThreatTopologyHeatmap({
  pressureData,
  stationPositions,
  visible = true,
  presetOpacityMultiplier = 1.0,
}: ThreatTopologyHeatmapProps) {
  const materialRef = useRef<THREE.ShaderMaterial>(null);

  const stationUniforms = useMemo(() => {
    const result: Record<string, { value: THREE.Vector2 }> = {};
    HUNT_STATION_ORDER.forEach((stationId, i) => {
      const pos = stationPositions[stationId] ?? OBSERVATORY_STATION_POSITIONS[stationId];
      result[`uStation${i}`] = { value: new THREE.Vector2(pos[0], pos[2]) };
    });
    return result;
  }, [stationPositions]);

  const material = useMemo(() => {
    const colorUniforms: Record<string, { value: THREE.Vector3 }> = {};
    HEATMAP_SOC_COLORS.forEach((c, i) => {
      colorUniforms[`uColor${i}`] = { value: colorToVec3(c) };
    });

    const pressureUniforms: Record<string, { value: number }> = {};
    for (let i = 0; i < 6; i++) {
      pressureUniforms[`uPressure${i}`] = { value: 0 };
    }

    return new THREE.ShaderMaterial({
      vertexShader: VERTEX_SHADER,
      fragmentShader: FRAGMENT_SHADER,
      uniforms: {
        ...stationUniforms,
        ...pressureUniforms,
        ...colorUniforms,
        uPulse: { value: 0 },
        uOpacityMultiplier: { value: presetOpacityMultiplier },
      },
      transparent: true,
      depthWrite: false,
      side: THREE.DoubleSide,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stationUniforms]);

  useEffect(() => {
    materialRef.current = material;
  }, [material]);

  useFrame(({ clock }) => {
    const mat = materialRef.current;
    if (!mat) return;

    mat.uniforms.uPulse.value =
      Math.sin(clock.elapsedTime * ((2 * Math.PI) / 3)) * 0.5 + 0.5;

    for (let i = 0; i < 6; i++) {
      mat.uniforms[`uPressure${i}`].value = pressureData[i] ?? 0;
    }

    mat.uniforms.uOpacityMultiplier.value = presetOpacityMultiplier;
  });

  if (!visible) return null;

  return (
    <mesh
      material={material}
      position={[0, -2, 0]}
      rotation={[-Math.PI / 2, 0, 0]}
    >
      <circleGeometry args={[WORLD_RADIUS * 1.2, 128]} />
    </mesh>
  );
}
