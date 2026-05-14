import { Sparkles } from "@react-three/drei";
import { useFrame } from "@react-three/fiber";
import { useMemo, useRef } from "react";
import * as THREE from "three";

// Star Nest GLSL shader — inline to avoid raw import issues in tests
const STAR_NEST_VERT = /* glsl */ `
varying vec2 vUv;
void main() {
  vUv = uv;
  gl_Position = vec4(position, 1.0);
}
`;

const STAR_NEST_FRAG = /* glsl */ `
uniform float time;
uniform vec2 resolution;
varying vec2 vUv;

#define iterations 17
#define formuparam 0.53

#define volsteps 15
#define stepsize 0.12

#define zoom 0.800
#define tile 0.850
#define speed 0.010

#define brightness 0.003
#define darkmatter 0.300
#define distfading 0.730
#define saturation 0.650

void main() {
  vec2 uv = vUv - 0.5;
  uv.y *= resolution.y / max(resolution.x, 1.0);

  vec3 dir = vec3(uv * zoom, 1.0);
  float t = time * speed + 0.25;

  float a1 = 0.5 / max(resolution.x, 1.0) * 2.0;
  float a2 = 0.8 / max(resolution.y, 1.0) * 2.0;
  mat2 rot1 = mat2(cos(a1), sin(a1), -sin(a1), cos(a1));
  mat2 rot2 = mat2(cos(a2), sin(a2), -sin(a2), cos(a2));
  dir.xz *= rot1;
  dir.xy *= rot2;

  vec3 from = vec3(1.0, 0.5, 0.5);
  from += vec3(t * 2.0, t, -2.0);
  from.xz *= rot1;
  from.xy *= rot2;

  float s = 0.1;
  float fade = 1.0;
  vec3 v = vec3(0.0);

  for (int r = 0; r < volsteps; r++) {
    vec3 p = from + s * dir * 0.5;
    p = abs(vec3(tile) - mod(p, vec3(tile * 2.0)));

    float pa;
    float a = pa = 0.0;

    for (int i = 0; i < iterations; i++) {
      p = abs(p) / dot(p, p) - formuparam;
      a += abs(length(p) - pa);
      pa = length(p);
    }

    float dm = max(0.0, darkmatter - a * a * 0.001);
    a *= a * a;
    if (r > 6) {
      fade *= 1.0 - dm;
    }

    v += fade;
    v += vec3(s, s * s, s * s * s * s) * a * brightness * fade;
    fade *= distfading;
    s += stepsize;
  }

  v = mix(vec3(length(v)), v, saturation);
  gl_FragColor = vec4(v * 0.01, 1.0);
}
`;

// Mid-field instanced star count
const MID_STAR_COUNT = 15000;
const MID_STAR_INNER_RADIUS = 800;
const MID_STAR_OUTER_RADIUS = 1600;

/**
 * 3-layer deep space starfield:
 * - Far:  SphereGeometry(2000) with Star Nest ShaderMaterial (BackSide, depthWrite:false)
 * - Mid:  InstancedMesh of 15K small plane stars distributed across both hemispheres
 * - Near: drei Sparkles for near-dust parallax
 */
export function ObservatoryStarfield() {
  const shaderRef = useRef<THREE.ShaderMaterial | null>(null);
  const midMeshRef = useRef<THREE.InstancedMesh | null>(null);

  // Shader material for the far star background sphere
  const starNestMaterial = useMemo(
    () =>
      new THREE.ShaderMaterial({
        vertexShader: STAR_NEST_VERT,
        fragmentShader: STAR_NEST_FRAG,
        uniforms: {
          time: { value: 0.0 },
          resolution: { value: new THREE.Vector2(1024, 768) },
        },
        side: THREE.BackSide,
        depthWrite: false,
        depthTest: false,
      }),
    [],
  );

  // Pre-compute 15K instance matrices for mid-field stars (dual hemisphere)
  const midFieldMatrices = useMemo(() => {
    const matrices: THREE.Matrix4[] = [];
    const halfCount = MID_STAR_COUNT / 2;

    for (let index = 0; index < MID_STAR_COUNT; index++) {
      const isUpperHemisphere = index < halfCount;

      // Spherical coordinates — uniform distribution
      const u = Math.random();
      const v = Math.random();
      const theta = 2 * Math.PI * u;
      // Clamp phi to hemisphere: upper [0, PI/2], lower [PI/2, PI]
      const phiBase = isUpperHemisphere ? 0 : Math.PI / 2;
      const phi = phiBase + (Math.PI / 2) * v;

      const radius =
        MID_STAR_INNER_RADIUS +
        Math.random() * (MID_STAR_OUTER_RADIUS - MID_STAR_INNER_RADIUS);

      const x = radius * Math.sin(phi) * Math.cos(theta);
      const y = radius * Math.cos(phi);
      const z = radius * Math.sin(phi) * Math.sin(theta);

      const matrix = new THREE.Matrix4();
      matrix.setPosition(x, y, z);
      matrices.push(matrix);
    }
    return matrices;
  }, []);

  // Apply instance matrices after mesh mounts
  const midGeo = useMemo(() => new THREE.PlaneGeometry(0.3, 0.3), []);
  const midMat = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: "#ffffff",
        transparent: true,
        opacity: 0.7,
        depthWrite: false,
        side: THREE.DoubleSide,
      }),
    [],
  );

  useFrame((_, delta) => {
    if (shaderRef.current) {
      shaderRef.current.uniforms.time.value += delta;
    }
    // Very slow rotation of the mid-field star field for subtle drift
    if (midMeshRef.current) {
      midMeshRef.current.rotation.y += delta * 0.0001;
    }
  });

  return (
    <>
      {/* Far layer — Star Nest shader on BackSide sphere */}
      <mesh renderOrder={-1000}>
        <sphereGeometry args={[2000, 32, 32]} />
        <primitive
          ref={shaderRef}
          attach="material"
          object={starNestMaterial}
        />
      </mesh>

      {/* Mid-field layer — 15K instanced stars */}
      <instancedMesh
        ref={midMeshRef}
        args={[midGeo, midMat, MID_STAR_COUNT]}
        onUpdate={(self) => {
          midFieldMatrices.forEach((matrix, index) => {
            self.setMatrixAt(index, matrix);
          });
          self.instanceMatrix.needsUpdate = true;
        }}
        renderOrder={-999}
      />

      {/* Near dust layer — drei Sparkles (naturally parallaxes with camera) */}
      <Sparkles
        count={1500}
        size={0.5}
        speed={0.1}
        opacity={0.5}
        color="#aaccff"
        scale={[200, 200, 200]}
      />
    </>
  );
}
