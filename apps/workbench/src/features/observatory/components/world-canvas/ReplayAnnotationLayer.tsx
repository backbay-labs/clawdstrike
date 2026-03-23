/**
 * ReplayAnnotationLayer.tsx — Phase 42 ANNO-01 / ANNO-02 / ANNO-06
 *
 * R3F scene layer that renders analyst annotation pins during replay.
 *
 * - Diamond pin geometry (two ConeGeometry meshes tip-to-tip)
 * - Invisible ground plane for click-to-drop (only when replayEnabled)
 * - drei Html glassmorphism overlay for note editing and delete
 * - drei Text label floating above each pin
 *
 * Pin interactions:
 *   • Click empty ground → calls onDropPin → parent adds pin to store
 *   • Click pin → opens edit overlay (only when replayEnabled)
 *   • Enter/blur in input → replace pin note via remove+add pattern
 *   • Click delete button → remove pin from store
 */

import { useRef, useState, type JSX } from "react";
import { Html, Text } from "@react-three/drei";
import * as THREE from "three";
import type { ThreeEvent } from "@react-three/fiber";
import type { ObservatoryAnnotationPin } from "../../types";
import { useObservatoryStore } from "../../stores/observatory-store";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Pin color when no spirit is bound */
const DEFAULT_PIN_COLOR = "#00d4ff";
/** Label Y offset above the pin group center */
const LABEL_Y_OFFSET = 1.2;
/** Edit overlay Y offset above the pin */
const EDIT_OVERLAY_Y_OFFSET = 2;
/** drei Html distanceFactor for readable overlay text at orbit distance */
const EDIT_DISTANCE_FACTOR = 60;

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface ReplayAnnotationLayerProps {
  /** Current pins from the observatory store */
  annotationPins: ObservatoryAnnotationPin[];
  /** Gates whether clicking drops a pin — only active during replay */
  replayEnabled: boolean;
  /** Current replay frame index to stamp on new pins */
  replayFrameIndex: number;
  /** Current replay frame timestamp in ms */
  replayFrameMs: number | null;
  /** Spirit accent color for pin emissive tint (hex) or null for default */
  spiritAccentColor: string | null;
  /** Callback when ground plane is clicked during replay */
  onDropPin: (worldPosition: [number, number, number]) => void;
}

// ---------------------------------------------------------------------------
// Diamond pin mesh (two cones tip-to-tip)
// ---------------------------------------------------------------------------

interface DiamondPinMeshProps {
  pin: ObservatoryAnnotationPin;
  color: string;
  onPinClick: (pinId: string) => void;
  replayEnabled: boolean;
}

function DiamondPinMesh({ pin, color, onPinClick, replayEnabled }: DiamondPinMeshProps): JSX.Element {
  const handleClick = (e: ThreeEvent<MouseEvent>) => {
    e.stopPropagation();
    if (replayEnabled) {
      onPinClick(pin.id);
    }
  };

  return (
    <group
      key={pin.id}
      data-pin-id={pin.id}
      position={pin.worldPosition}
      scale={[0.8, 0.8, 0.8]}
      onClick={handleClick}
    >
      {/* Upper cone — point up */}
      <mesh>
        <coneGeometry args={[0.25, 0.5, 6]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={0.6}
        />
      </mesh>
      {/* Lower cone — rotated to point down, forming a diamond */}
      <mesh position={[0, -0.5, 0]} rotation={[Math.PI, 0, 0]}>
        <coneGeometry args={[0.25, 0.5, 6]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={0.6}
        />
      </mesh>
    </group>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ReplayAnnotationLayer({
  annotationPins,
  replayEnabled,
  onDropPin,
  spiritAccentColor,
}: ReplayAnnotationLayerProps): JSX.Element | null {
  const [editingPinId, setEditingPinId] = useState<string | null>(null);

  // Stable ref to avoid re-creating the ground material on each render
  const groundMaterialRef = useRef(
    new THREE.MeshBasicMaterial({ visible: false, side: THREE.DoubleSide }),
  );

  const pinColor = spiritAccentColor ?? DEFAULT_PIN_COLOR;

  // ---------------------------------------------------------------------------
  // Ground plane click handler
  // ---------------------------------------------------------------------------

  function handleGroundPointerDown(e: ThreeEvent<PointerEvent>) {
    if (!replayEnabled) {
      return;
    }
    e.stopPropagation();
    // Close any open edit overlay when clicking empty space
    setEditingPinId(null);
    const { x, y, z } = e.point;
    onDropPin([x, y, z]);
  }

  // ---------------------------------------------------------------------------
  // Pin interaction handlers
  // ---------------------------------------------------------------------------

  function handlePinClick(pinId: string) {
    setEditingPinId((prev) => (prev === pinId ? null : pinId));
  }

  function handleNoteConfirm(pin: ObservatoryAnnotationPin, inputValue: string) {
    const store = useObservatoryStore.getState();
    store.actions.removeAnnotationPin(pin.id);
    store.actions.addAnnotationPin({ ...pin, note: inputValue });
    setEditingPinId(null);
  }

  function handleDeletePin(pinId: string) {
    const store = useObservatoryStore.getState();
    store.actions.removeAnnotationPin(pinId);
    setEditingPinId(null);
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <>
      {/* Invisible ground plane for click-to-drop */}
      <mesh
        rotation={[-Math.PI / 2, 0, 0]}
        position={[0, 0, 0]}
        material={groundMaterialRef.current}
        visible={false}
        onPointerDown={handleGroundPointerDown}
        data-ground-plane
      >
        <planeGeometry args={[200, 200]} />
      </mesh>

      {/* Annotation pins */}
      {annotationPins.map((pin) => (
        <group key={pin.id}>
          {/* Diamond marker */}
          <DiamondPinMesh
            pin={pin}
            color={pinColor}
            onPinClick={handlePinClick}
            replayEnabled={replayEnabled}
          />

          {/* Floating label above pin */}
          <Text
            position={[pin.worldPosition[0], pin.worldPosition[1] + LABEL_Y_OFFSET, pin.worldPosition[2]]}
            fontSize={0.35}
            maxWidth={4}
            anchorX="center"
            anchorY="bottom"
            color="white"
            outlineWidth={0.02}
            outlineColor="#000"
            depthTest={false}
          >
            {pin.note.trim() !== "" ? pin.note : "Pin"}
          </Text>

          {/* Glassmorphism edit overlay — shown when this pin is being edited */}
          {editingPinId === pin.id && (
            <Html
              transform
              sprite
              distanceFactor={EDIT_DISTANCE_FACTOR}
              position={[pin.worldPosition[0], pin.worldPosition[1] + EDIT_OVERLAY_Y_OFFSET, pin.worldPosition[2]]}
            >
              <EditOverlay
                pin={pin}
                onConfirm={(value) => handleNoteConfirm(pin, value)}
                onDelete={() => handleDeletePin(pin.id)}
              />
            </Html>
          )}
        </group>
      ))}
    </>
  );
}

// ---------------------------------------------------------------------------
// Edit overlay (rendered as DOM via drei Html)
// ---------------------------------------------------------------------------

interface EditOverlayProps {
  pin: ObservatoryAnnotationPin;
  onConfirm: (value: string) => void;
  onDelete: () => void;
}

function EditOverlay({ pin, onConfirm, onDelete }: EditOverlayProps): JSX.Element {
  const inputRef = useRef<HTMLInputElement>(null);

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      onConfirm(inputRef.current?.value ?? "");
    }
    if (e.key === "Escape") {
      onConfirm(pin.note);
    }
  }

  function handleBlur() {
    onConfirm(inputRef.current?.value ?? "");
  }

  return (
    <div
      style={{
        background: "var(--hud-bg, rgba(8, 12, 24, 0.75))",
        border: "var(--hud-border, 1px solid rgba(255, 255, 255, 0.06))",
        backdropFilter: "var(--hud-blur, blur(12px))",
        borderRadius: 8,
        padding: 8,
        display: "flex",
        alignItems: "center",
        gap: 6,
        minWidth: 180,
      }}
    >
      <input
        ref={inputRef}
        type="text"
        // eslint-disable-next-line jsx-a11y/no-autofocus
        autoFocus
        defaultValue={pin.note}
        placeholder="Add note..."
        onKeyDown={handleKeyDown}
        onBlur={handleBlur}
        style={{
          fontSize: 12,
          color: "var(--hud-text, rgba(255, 255, 255, 0.85))",
          background: "rgba(255, 255, 255, 0.06)",
          border: "none",
          borderRadius: 4,
          padding: "4px 8px",
          width: 160,
          outline: "none",
        }}
      />
      <button
        type="button"
        onClick={onDelete}
        title="Delete pin"
        style={{
          fontSize: 10,
          color: "var(--hud-text-muted, rgba(255, 255, 255, 0.45))",
          background: "transparent",
          border: "none",
          cursor: "pointer",
          padding: "2px 4px",
          borderRadius: 3,
        }}
      >
        ×
      </button>
    </div>
  );
}
