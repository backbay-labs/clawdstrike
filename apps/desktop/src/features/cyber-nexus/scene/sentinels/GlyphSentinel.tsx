/**
 * GlyphSentinel - focus streak animation for Cyber Nexus
 *
 * Adapted from Origin Realm sentinels (`GlyphSentinel.tsx`).
 */
import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

export interface Vec3 {
  x: number;
  y: number;
  z: number;
}

export interface GlyphSentinelProps {
  from: Vec3;
  to: Vec3;
  onArrive?: () => void;
  hue?: number;
  duration?: number;
}

function easeOutExpo(t: number): number {
  return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
}

function easeInQuad(t: number): number {
  return t * t;
}

interface TrailPoint {
  position: THREE.Vector3;
  time: number;
}

export function GlyphSentinel({ from, to, onArrive, hue = 45, duration = 0.8 }: GlyphSentinelProps) {
  const groupRef = useRef<THREE.Group>(null);
  const coreRef = useRef<THREE.Mesh>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const trailRef = useRef<THREE.Points>(null);

  const startTimeRef = useRef<number | null>(null);
  const arrivedRef = useRef(false);
  const trailPointsRef = useRef<TrailPoint[]>([]);

  const fromVec = useMemo(() => new THREE.Vector3(from.x, from.y, from.z), [from]);
  const toVec = useMemo(() => new THREE.Vector3(to.x, to.y + 1, to.z), [to]);

  const maxTrailPoints = 50;
  const trailGeometry = useMemo(() => {
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(maxTrailPoints * 3);
    const alphas = new Float32Array(maxTrailPoints);

    geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute("alpha", new THREE.BufferAttribute(alphas, 1));

    return geometry;
  }, []);

  const trailMaterial = useMemo(() => {
    return new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: {
        color: { value: new THREE.Color(`hsl(${hue}, 80%, 70%)`) },
        time: { value: 0 },
      },
      vertexShader: `
        attribute float alpha;
        varying float vAlpha;
        void main() {
          vAlpha = alpha;
          vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
          gl_Position = projectionMatrix * mvPosition;
          gl_PointSize = 6.0 * (1.0 - (-mvPosition.z / 20.0));
        }
      `,
      fragmentShader: `
        uniform vec3 color;
        varying float vAlpha;
        void main() {
          float dist = length(gl_PointCoord - vec2(0.5));
          if (dist > 0.5) discard;
          float falloff = 1.0 - (dist * 2.0);
          gl_FragColor = vec4(color, vAlpha * falloff * 0.8);
        }
      `,
    });
  }, [hue]);

  const coreMaterial = useMemo(() => {
    return new THREE.MeshBasicMaterial({
      color: new THREE.Color(`hsl(${hue}, 85%, 75%)`),
      transparent: true,
      opacity: 1,
    });
  }, [hue]);

  const glowMaterial = useMemo(() => {
    return new THREE.MeshBasicMaterial({
      color: new THREE.Color(`hsl(${hue}, 70%, 60%)`),
      transparent: true,
      opacity: 0.4,
      side: THREE.BackSide,
    });
  }, [hue]);

  useFrame(({ clock }) => {
    if (arrivedRef.current) return;

    if (startTimeRef.current === null) {
      startTimeRef.current = clock.elapsedTime;
    }

    const elapsed = clock.elapsedTime - startTimeRef.current;
    const progress = Math.min(elapsed / duration, 1);
    const easedProgress = easeOutExpo(progress);

    const currentPos = new THREE.Vector3().lerpVectors(fromVec, toVec, easedProgress);
    const arcHeight = 2.5 * Math.sin(progress * Math.PI);
    currentPos.y += arcHeight;

    if (groupRef.current) {
      groupRef.current.position.copy(currentPos);
      groupRef.current.rotation.y = clock.elapsedTime * 4;
    }

    if (coreRef.current) {
      const pulse = 1 + Math.sin(clock.elapsedTime * 15) * 0.2;
      coreRef.current.scale.setScalar(pulse);
    }

    if (glowRef.current) {
      const glowPulse = 1.2 + Math.sin(clock.elapsedTime * 10) * 0.3;
      glowRef.current.scale.setScalar(glowPulse);
    }

    trailPointsRef.current.push({ position: currentPos.clone(), time: clock.elapsedTime });

    const trailLifetime = 0.4;
    trailPointsRef.current = trailPointsRef.current.filter((p) => clock.elapsedTime - p.time < trailLifetime);

    if (trailRef.current) {
      const positions = trailGeometry.attributes.position.array as Float32Array;
      const alphas = trailGeometry.attributes.alpha.array as Float32Array;

      for (let i = 0; i < maxTrailPoints; i++) {
        if (i < trailPointsRef.current.length) {
          const point = trailPointsRef.current[trailPointsRef.current.length - 1 - i];
          positions[i * 3] = point.position.x;
          positions[i * 3 + 1] = point.position.y;
          positions[i * 3 + 2] = point.position.z;

          const age = clock.elapsedTime - point.time;
          const normalizedAge = age / trailLifetime;
          alphas[i] = 1 - easeInQuad(normalizedAge);
        } else {
          positions[i * 3] = 0;
          positions[i * 3 + 1] = -1000;
          positions[i * 3 + 2] = 0;
          alphas[i] = 0;
        }
      }

      trailGeometry.attributes.position.needsUpdate = true;
      trailGeometry.attributes.alpha.needsUpdate = true;
    }

    if (progress >= 1 && !arrivedRef.current) {
      arrivedRef.current = true;
      onArrive?.();
    }
  });

  useEffect(() => {
    return () => {
      trailGeometry.dispose();
      trailMaterial.dispose();
      coreMaterial.dispose();
      glowMaterial.dispose();
    };
  }, [coreMaterial, glowMaterial, trailGeometry, trailMaterial]);

  return (
    <>
      <group ref={groupRef} position={[from.x, from.y, from.z]}>
        <mesh ref={coreRef} material={coreMaterial}>
          <sphereGeometry args={[0.15, 16, 16]} />
        </mesh>

        <mesh ref={glowRef} material={glowMaterial}>
          <sphereGeometry args={[0.35, 16, 16]} />
        </mesh>
      </group>

      <points ref={trailRef} geometry={trailGeometry} material={trailMaterial} />
    </>
  );
}

export default GlyphSentinel;

