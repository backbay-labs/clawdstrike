/**
 * StationLodWrapper.tsx — STN-02 / STN-05 / DSC-01
 *
 * Four-tier LOD system for space stations using drei's Detailed component.
 *
 * LOD tiers (distance thresholds):
 *   0  – 60  units  : Full SpaceStationMesh + Fresnel rim glow halo + docking ring
 *   60 – 180 units  : Simplified hub + ring geometry (~500 tris)
 *   180 – 500 units : Billboard text label with station name
 *   500+    units   : Pulsing beacon sprite + point light
 *
 * Phase 26 — Discovery gate:
 *   Undiscovered stations render as a dim uncharted marker (StationBeacon at low opacity).
 *   When the ship enters within DISCOVERY_RADIUS (200 units), the station is discovered:
 *     - discoverStation() called on the store (session-only, no localStorage)
 *     - CustomEvent "observatory:station-discovered" fired
 *     - 1.5s lights-on + unfold animation starts
 */

import { useRef, type ReactElement } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { Detailed, Billboard, Text } from "@react-three/drei";
import { SpaceStationMesh, type SpaceStationMeshProps } from "./districtGeometry";
import { StationBeacon } from "./StationBeacon";
import { StationFresnelGlow } from "./StationFresnelGlow";
import { StationDockingRing } from "./StationDockingRing";
import { useObservatoryStore } from "../stores/observatory-store";
import { OBSERVATORY_STATION_POSITIONS } from "./observatory-world-template";
import type { HuntStationId } from "./types";

export interface StationLodWrapperProps extends SpaceStationMeshProps {
  stationLabel: string;
  stationId: HuntStationId;
}

/** LOD distance thresholds: near / mid / far / beacon */
const LOD_DISTANCES: [number, number, number, number] = [0, 60, 180, 500];

/** Distance (world units) at which an undiscovered station is revealed. */
const DISCOVERY_RADIUS = 200;

/** Duration of the discovery animation in seconds. */
const DISCOVERY_ANIM_DURATION = 1.5;

// Module-level scratch vectors — avoids GC in useFrame hot path.
const _shipPos = new THREE.Vector3();
const _stationPos = new THREE.Vector3();

/** easeOutBack overshoot ease — t in [0,1]. */
function easeOutBack(t: number): number {
  const c1 = 1.70158;
  const c3 = c1 + 1;
  return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2);
}

/**
 * Wraps a space station in a 4-tier LOD system with Phase 26 discovery gate.
 * Uses a local coordinate group so children use [0,0,0] for their own position.
 */
export function StationLodWrapper({
  position,
  colorHex,
  seed,
  floatAmplitude = 0.12,
  pulseSpeed = 0.0018,
  stationLabel,
  stationId,
}: StationLodWrapperProps): ReactElement {
  const stationProps: SpaceStationMeshProps = {
    position: [0, 0, 0],
    colorHex,
    seed,
    floatAmplitude,
    pulseSpeed,
  };

  // Ref to the full LOD content group (hidden until discovery or already discovered).
  const lodGroupRef = useRef<THREE.Group>(null);
  // Ref to the uncharted beacon group (shown while undiscovered).
  const unchartedRef = useRef<THREE.Group>(null);
  // Ref to the docking ring group for scale animation.
  const dockingRingGroupRef = useRef<THREE.Group>(null);
  // Discovery animation phase tracker — ref-only, no re-renders.
  const discoveryPhaseRef = useRef<{ active: boolean; startTime: number }>({
    active: false,
    startTime: 0,
  });
  // Whether this instance has been discovered (local ref mirrors store Set, avoids subscription).
  const isDiscoveredRef = useRef<boolean>(false);

  // Pre-read station world position once (static — positions never change).
  const stationWorldPos = OBSERVATORY_STATION_POSITIONS[stationId];

  useFrame(({ clock }) => {
    const storeState = useObservatoryStore.getState();
    const { flightState, actions } = storeState;

    // Sync local discovered ref from store.
    const storeDiscovered = storeState.discoveredStations.has(stationId);

    if (!isDiscoveredRef.current && storeDiscovered) {
      // Store was updated externally (e.g. hydration or another consumer).
      isDiscoveredRef.current = true;
    }

    if (!isDiscoveredRef.current) {
      // --- Undiscovered: check proximity ---
      _shipPos.set(flightState.position[0], flightState.position[1], flightState.position[2]);
      _stationPos.set(stationWorldPos[0], stationWorldPos[1], stationWorldPos[2]);
      const dist = _shipPos.distanceTo(_stationPos);

      if (dist <= DISCOVERY_RADIUS) {
        // Trigger discovery
        isDiscoveredRef.current = true;
        actions.discoverStation(stationId);
        window.dispatchEvent(
          new CustomEvent("observatory:station-discovered", { detail: { stationId } }),
        );
        discoveryPhaseRef.current = { active: true, startTime: clock.elapsedTime };

        // Switch visibility: hide uncharted beacon, show LOD content.
        if (unchartedRef.current) unchartedRef.current.visible = false;
        if (lodGroupRef.current) {
          lodGroupRef.current.visible = true;
          // Start fully transparent — animation will fade in.
          lodGroupRef.current.traverse((child) => {
            const mesh = child as THREE.Mesh;
            if (mesh.isMesh && mesh.material) {
              const mat = mesh.material as THREE.Material;
              mat.transparent = true;
              mat.opacity = 0;
            }
          });
        }
        if (dockingRingGroupRef.current) {
          dockingRingGroupRef.current.scale.setScalar(0);
        }
      }
    } else if (discoveryPhaseRef.current.active) {
      // --- Discovery animation ---
      const t = Math.min(
        (clock.elapsedTime - discoveryPhaseRef.current.startTime) / DISCOVERY_ANIM_DURATION,
        1,
      );

      // Station geometry + LOD content: opacity lerp 0 → 1 over full 1.5s
      if (lodGroupRef.current) {
        const opacity = Math.min(t / 1.0, 1);
        lodGroupRef.current.traverse((child) => {
          const mesh = child as THREE.Mesh;
          if (mesh.isMesh && mesh.material) {
            const mat = mesh.material as THREE.Material;
            mat.transparent = true;
            mat.opacity = opacity;
          }
        });
      }

      // Docking ring: easeOutBack scale 0 → 1 over 1.2s
      if (dockingRingGroupRef.current) {
        const ringT = Math.min(t / 0.8, 1);
        const ringScale = easeOutBack(ringT);
        dockingRingGroupRef.current.scale.setScalar(Math.max(0, ringScale));
      }

      if (t >= 1) {
        // Animation complete — reset opacity to full, clear transparent flag where possible.
        discoveryPhaseRef.current.active = false;
        if (lodGroupRef.current) {
          lodGroupRef.current.traverse((child) => {
            const mesh = child as THREE.Mesh;
            if (mesh.isMesh && mesh.material) {
              const mat = mesh.material as THREE.Material;
              mat.opacity = 1;
            }
          });
        }
        if (dockingRingGroupRef.current) {
          dockingRingGroupRef.current.scale.setScalar(1);
        }
      }
    }
  });

  // Determine initial visibility: if already in discoveredStations at mount time, skip uncharted.
  // We read store state directly here (once, at render time) to set initial visibility.
  // The useFrame loop above keeps them in sync thereafter.
  const initiallyDiscovered = useObservatoryStore.getState().discoveredStations.has(stationId);
  // Sync local ref at mount.
  if (initiallyDiscovered && !isDiscoveredRef.current) {
    isDiscoveredRef.current = true;
  }

  return (
    <group position={position}>
      {/* Uncharted marker — visible only while station is undiscovered */}
      <group ref={unchartedRef} visible={!initiallyDiscovered}>
        <StationBeacon
          position={[0, 0, 0]}
          colorHex="#2d3a4f"
          opacity={0.15}
        />
      </group>

      {/* Full LOD content — hidden until discovered, then fade-in during animation */}
      <group ref={lodGroupRef} visible={initiallyDiscovered}>
        {/* drei Detailed switches between children based on camera distance */}
        <Detailed distances={LOD_DISTANCES}>
          {/* Tier 0 (near, 0-60 units): full geometry + Fresnel glow + docking ring */}
          <group>
            <SpaceStationMesh {...stationProps} />
            <StationFresnelGlow colorHex={colorHex} radius={5} />
            <group ref={dockingRingGroupRef}>
              <StationDockingRing colorHex={colorHex} stationId={stationId} />
            </group>
          </group>

          {/* Tier 1 (mid, 60-180 units): simplified hub + ring only */}
          <group>
            <mesh rotation={[Math.PI / 2, 0, 0]}>
              <torusGeometry args={[3, 0.2, 12, 32]} />
              <meshStandardMaterial
                color={colorHex}
                emissive={colorHex}
                emissiveIntensity={0.3}
                toneMapped={false}
                metalness={0.6}
                roughness={0.35}
              />
            </mesh>
            <mesh position={[0, 1, 0]}>
              <cylinderGeometry args={[0.7, 0.8, 2, 12]} />
              <meshStandardMaterial color="#1a2030" metalness={0.5} roughness={0.6} />
            </mesh>
          </group>

          {/* Tier 2 (far, 180-500 units): billboard label */}
          <group>
            <Billboard follow lockX={false} lockY={false} lockZ={false}>
              <Text
                fontSize={3}
                color={colorHex}
                anchorY="middle"
                outlineWidth={0.15}
                outlineColor="#000000"
              >
                {stationLabel}
              </Text>
            </Billboard>
          </group>

          {/* Tier 3 (beacon, 500+ units): sprite + point light */}
          <StationBeacon position={[0, 0, 0]} colorHex={colorHex} />
        </Detailed>
      </group>
    </group>
  );
}
