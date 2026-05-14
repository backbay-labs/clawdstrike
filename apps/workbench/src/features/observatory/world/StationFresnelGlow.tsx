/**
 * StationFresnelGlow.tsx — STN-04
 *
 * Fresnel rim-glow ShaderMaterial on a scaled sphere surrounding the station.
 * The fresnel term makes the glow visible only at glancing angles (the rim),
 * giving stations a visible energy halo at near range (0-60 units).
 */

import { useMemo, type ReactElement } from "react";
import * as THREE from "three";

const VERTEX_SHADER = /* glsl */ `
  varying vec3 vNormal;
  varying vec3 vViewDir;

  void main() {
    vNormal = normalize(normalMatrix * normal);
    vec4 worldPosition = modelMatrix * vec4(position, 1.0);
    vViewDir = normalize(cameraPosition - worldPosition.xyz);
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const FRAGMENT_SHADER = /* glsl */ `
  uniform vec3 uColor;

  varying vec3 vNormal;
  varying vec3 vViewDir;

  void main() {
    float fresnel = pow(1.0 - max(dot(vNormal, vViewDir), 0.0), 4.0);
    gl_FragColor = vec4(uColor, fresnel * 0.6);
  }
`;

export interface StationFresnelGlowProps {
  colorHex: string;
  /** Approximate bounding radius of the station mesh. Default: 5. */
  radius?: number;
}

/**
 * Renders a Fresnel rim-glow sphere around the station geometry.
 * Only visible at glancing angles — pure additive contribution on station edges.
 */
export function StationFresnelGlow({
  colorHex,
  radius = 5,
}: StationFresnelGlowProps): ReactElement {
  const material = useMemo(
    () =>
      new THREE.ShaderMaterial({
        vertexShader: VERTEX_SHADER,
        fragmentShader: FRAGMENT_SHADER,
        uniforms: {
          uColor: { value: new THREE.Color(colorHex) },
        },
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
        side: THREE.FrontSide,
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [colorHex],
  );

  return (
    <mesh material={material}>
      <sphereGeometry args={[radius * 1.3, 24, 24]} />
    </mesh>
  );
}
