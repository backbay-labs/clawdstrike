import { Html, Line, OrbitControls } from "@react-three/drei";
import { Canvas, type ThreeEvent } from "@react-three/fiber";
import { type RefObject, Suspense, useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import type { OrbitControls as OrbitControlsImpl } from "three-stdlib";
import { calculateLayoutPositions } from "../layouts";
import { GlyphSentinel, type Vec3 } from "../scene/sentinels/GlyphSentinel";
import { GroundPlatform } from "../scene/terrain/GroundPlatform";
import type {
  NexusLayoutMode,
  NexusViewMode,
  Strikecell,
  StrikecellConnection,
  StrikecellDomainId,
  StrikecellStatus,
} from "../types";

interface NexusCanvasProps {
  strikecells: Strikecell[];
  connections: StrikecellConnection[];
  activeStrikecellId: StrikecellDomainId | null;
  expandedStrikecellIds: StrikecellDomainId[];
  selectedNodeIds: string[];
  focusedNodeId: string | null;
  layoutMode: NexusLayoutMode;
  viewMode: NexusViewMode;
  fieldVisible: boolean;
  cameraResetToken: number;
  onSelectStrikecell: (id: StrikecellDomainId) => void;
  onToggleExpandedStrikecell: (id: StrikecellDomainId) => void;
  onToggleNodeSelection: (nodeId: string) => void;
  onFocusNode: (nodeId: string | null) => void;
  onBackgroundClick: () => void;
  onContextMenu: (
    targetId: string,
    targetType: "strikecell" | "node",
    event: MouseEvent,
    strikecellId?: StrikecellDomainId,
  ) => void;
}

const STATUS_COLORS: Record<StrikecellStatus, string> = {
  healthy: "#3dbf84",
  warning: "#d4a84b",
  critical: "#c45c5c",
  offline: "#617089",
};

const STATUS_HUES: Record<StrikecellStatus, number> = {
  healthy: 145,
  warning: 50,
  critical: 10,
  offline: 210,
};

function toVectorMap(
  strikecells: Strikecell[],
  layoutMode: NexusLayoutMode,
  viewMode: NexusViewMode,
  connections: StrikecellConnection[],
): Map<StrikecellDomainId, THREE.Vector3> {
  const layoutNodes = strikecells.map((strikecell) => ({
    id: strikecell.id,
    activityCount: strikecell.activityCount,
    status: strikecell.status,
  }));
  const positions = calculateLayoutPositions(layoutMode, layoutNodes, connections);
  const map = new Map<StrikecellDomainId, THREE.Vector3>();

  strikecells.forEach((strikecell) => {
    const position = positions.get(strikecell.id);
    if (!position) return;
    const y = viewMode === "grid" ? 0.65 : position.y;
    const z = viewMode === "grid" ? position.z * 0.74 : position.z;
    map.set(strikecell.id, new THREE.Vector3(position.x, y, z));
  });

  return map;
}

function CameraRig({
  controlsRef,
  viewMode,
  activeStrikecellId,
  strikecellPositions,
  cameraResetToken,
}: {
  controlsRef: RefObject<OrbitControlsImpl | null>;
  viewMode: NexusViewMode;
  activeStrikecellId: StrikecellDomainId | null;
  strikecellPositions: Map<StrikecellDomainId, THREE.Vector3>;
  cameraResetToken: number;
}) {
  useEffect(() => {
    const controls = controlsRef.current;
    if (!controls) return;

    const preset =
      viewMode === "grid"
        ? { position: new THREE.Vector3(0, 25, 15), target: new THREE.Vector3(0, 0, 0) }
        : { position: new THREE.Vector3(0, 9, 22), target: new THREE.Vector3(0, 0.8, 0) };

    const active = activeStrikecellId ? strikecellPositions.get(activeStrikecellId) : null;
    if (active) {
      controls.target.copy(active);
      controls.object.position.set(
        active.x + preset.position.x * 0.26,
        preset.position.y,
        active.z + preset.position.z * 0.26,
      );
      controls.update();
      return;
    }

    controls.object.position.copy(preset.position);
    controls.target.copy(preset.target);
    controls.update();
  }, [activeStrikecellId, cameraResetToken, controlsRef, strikecellPositions, viewMode]);

  return null;
}

export function NexusCanvas({
  strikecells,
  connections,
  activeStrikecellId,
  expandedStrikecellIds,
  selectedNodeIds: _selectedNodeIds,
  focusedNodeId: _focusedNodeId,
  layoutMode,
  viewMode,
  fieldVisible,
  cameraResetToken,
  onSelectStrikecell,
  onToggleExpandedStrikecell,
  onToggleNodeSelection: _onToggleNodeSelection,
  onFocusNode: _onFocusNode,
  onBackgroundClick,
  onContextMenu,
}: NexusCanvasProps) {
  const controlsRef = useRef<OrbitControlsImpl>(null);
  const previousActiveRef = useRef<StrikecellDomainId | null>(null);
  const [sentinel, setSentinel] = useState<{ from: Vec3; to: Vec3; hue: number } | null>(null);

  const strikecellPositions = useMemo(
    () => toVectorMap(strikecells, layoutMode, viewMode, connections),
    [connections, layoutMode, strikecells, viewMode],
  );

  useEffect(() => {
    if (!activeStrikecellId) return;
    const next = strikecellPositions.get(activeStrikecellId);
    if (!next) return;

    const prevId = previousActiveRef.current;
    previousActiveRef.current = activeStrikecellId;
    if (!prevId) return;

    const prev = strikecellPositions.get(prevId);
    if (!prev) return;

    const status =
      strikecells.find((strikecell) => strikecell.id === activeStrikecellId)?.status ?? "healthy";
    const hue = STATUS_HUES[status];

    setSentinel({
      from: { x: prev.x, y: prev.y + 0.2, z: prev.z },
      to: { x: next.x, y: next.y, z: next.z },
      hue,
    });
  }, [activeStrikecellId, strikecellPositions, strikecells]);

  const connectionLines = useMemo(() => {
    return connections
      .map((connection) => {
        const source = strikecellPositions.get(connection.sourceId);
        const target = strikecellPositions.get(connection.targetId);
        if (!source || !target) return null;
        return {
          id: connection.id,
          points: [source.toArray(), target.toArray()] as [
            [number, number, number],
            [number, number, number],
          ],
          opacity: 0.16 + connection.strength * 0.34,
          strength: connection.strength,
        };
      })
      .filter(
        (
          line,
        ): line is {
          id: string;
          points: [[number, number, number], [number, number, number]];
          opacity: number;
          strength: number;
        } => Boolean(line),
      );
  }, [connections, strikecellPositions]);

  return (
    <div className="absolute inset-0">
      <Canvas
        camera={{ position: [0, 9, 22], fov: 46 }}
        dpr={[1, 1.5]}
        performance={{ min: 0.6 }}
        gl={{ antialias: true, powerPreference: "high-performance" }}
        onPointerMissed={onBackgroundClick}
      >
        <Suspense fallback={null}>
          <color attach="background" args={["#06080e"]} />
          <fog attach="fog" args={["#06080e", 15, 45]} />
          <ambientLight intensity={0.36} />
          <pointLight position={[12, 14, 10]} intensity={0.58} color="#7e8ba7" />
          <pointLight position={[-10, -2, -8]} intensity={0.43} color="#d5ad57" />

          {fieldVisible ? (
            <group position={[0, -2.2, 0]}>
              <GroundPlatform radius={16} hue={45} showGrid />
            </group>
          ) : null}

          {sentinel ? (
            <GlyphSentinel
              from={sentinel.from}
              to={sentinel.to}
              hue={sentinel.hue}
              onArrive={() => setSentinel(null)}
            />
          ) : null}

          {connectionLines.map((line) => (
            <Line
              key={line.id}
              points={line.points}
              color={line.strength > 0.7 ? "#d5ad57" : "#7e8ba7"}
              transparent
              opacity={line.opacity}
              lineWidth={1.1}
            />
          ))}

          {strikecells.map((strikecell) => {
            const position = strikecellPositions.get(strikecell.id);
            if (!position) return null;
            const active = strikecell.id === activeStrikecellId;
            const accent = STATUS_COLORS[strikecell.status];
            const ringOpacity = active ? 0.28 : 0.14;

            return (
              <group key={strikecell.id} position={position}>
                <mesh
                  scale={[active ? 1.3 : 1, active ? 1.3 : 1, active ? 1.3 : 1]}
                  onClick={(event) => {
                    event.stopPropagation();
                    onSelectStrikecell(strikecell.id);
                  }}
                  onDoubleClick={(event) => {
                    event.stopPropagation();
                    onToggleExpandedStrikecell(strikecell.id);
                  }}
                  onContextMenu={(event: ThreeEvent<MouseEvent>) => {
                    event.stopPropagation();
                    event.nativeEvent.preventDefault();
                    onContextMenu(strikecell.id, "strikecell", event.nativeEvent, strikecell.id);
                  }}
                >
                  <dodecahedronGeometry args={[1.05, 0]} />
                  <meshStandardMaterial
                    color="#0f141e"
                    roughness={0.3}
                    metalness={0.92}
                    emissive={accent}
                    emissiveIntensity={active ? 0.42 : 0.22}
                  />
                </mesh>

                <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.9, 0]}>
                  <ringGeometry args={[1.15, active ? 1.55 : 1.4, 48]} />
                  <meshBasicMaterial color={accent} transparent opacity={ringOpacity} />
                </mesh>

                <Html
                  center
                  position={[0, -1.78, 0]}
                  distanceFactor={10.5}
                  style={{ pointerEvents: "none" }}
                >
                  <div className="origin-card rounded-md border border-[color:color-mix(in_srgb,var(--origin-panel-border)_55%,transparent)] px-2 py-1 text-[10px] font-mono text-sdr-text-primary whitespace-nowrap">
                    {strikecell.name}
                  </div>
                </Html>

                {expandedStrikecellIds.includes(strikecell.id) ? (
                  <group>
                    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.82, 0]}>
                      <ringGeometry args={[1.7, 1.95, 56]} />
                      <meshBasicMaterial color="#d5ad57" transparent opacity={0.22} />
                    </mesh>
                    <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.82, 0]}>
                      <ringGeometry args={[2.15, 2.28, 56]} />
                      <meshBasicMaterial color={accent} transparent opacity={0.12} />
                    </mesh>
                  </group>
                ) : null}
              </group>
            );
          })}

          <OrbitControls
            ref={controlsRef}
            enablePan
            enableZoom
            enableRotate
            autoRotate={false}
            minDistance={8}
            maxDistance={38}
            minPolarAngle={viewMode === "grid" ? Math.PI * 0.1 : Math.PI * 0.24}
            maxPolarAngle={viewMode === "grid" ? Math.PI * 0.46 : Math.PI * 0.56}
            target={[0, 0, 0]}
          />

          <CameraRig
            controlsRef={controlsRef}
            viewMode={viewMode}
            activeStrikecellId={activeStrikecellId}
            strikecellPositions={strikecellPositions}
            cameraResetToken={cameraResetToken}
          />
        </Suspense>
      </Canvas>
    </div>
  );
}
