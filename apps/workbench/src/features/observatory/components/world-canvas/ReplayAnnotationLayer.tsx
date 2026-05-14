import { useEffect, useRef, useState, type JSX } from "react";
import { Html, Text } from "@react-three/drei";
import * as THREE from "three";
import type { ThreeEvent } from "@react-three/fiber";
import type { ObservatoryAnnotationPin } from "../../types";
import { useObservatoryStore } from "../../stores/observatory-store";

const DEFAULT_PIN_COLOR = "#00d4ff";

export interface ReplayAnnotationLayerProps {
  annotationPins: ObservatoryAnnotationPin[];
  replayEnabled: boolean;
  replayFrameIndex: number;
  replayFrameMs: number | null;
  spiritAccentColor: string | null;
  onDropPin: (worldPosition: [number, number, number]) => void;
}

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
      <mesh>
        <coneGeometry args={[0.25, 0.5, 6]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.6} />
      </mesh>
      <mesh position={[0, -0.5, 0]} rotation={[Math.PI, 0, 0]}>
        <coneGeometry args={[0.25, 0.5, 6]} />
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.6} />
      </mesh>
    </group>
  );
}

export function ReplayAnnotationLayer({
  annotationPins,
  replayEnabled,
  onDropPin,
  spiritAccentColor,
}: ReplayAnnotationLayerProps): JSX.Element | null {
  const [editingPinId, setEditingPinId] = useState<string | null>(null);

  const groundMaterialRef = useRef<THREE.MeshBasicMaterial | null>(null);
  if (!groundMaterialRef.current) {
    groundMaterialRef.current = new THREE.MeshBasicMaterial({ visible: false, side: THREE.DoubleSide });
  }

  useEffect(() => {
    return () => {
      groundMaterialRef.current?.dispose();
    };
  }, []);

  const pinColor = spiritAccentColor ?? DEFAULT_PIN_COLOR;

  function handleGroundPointerDown(e: ThreeEvent<PointerEvent>) {
    if (!replayEnabled) return;
    e.stopPropagation();
    setEditingPinId(null);
    const { x, y, z } = e.point;
    onDropPin([x, y, z]);
  }

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
    useObservatoryStore.getState().actions.removeAnnotationPin(pinId);
    setEditingPinId(null);
  }

  return (
    <>
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

      {annotationPins.map((pin) => (
        <group key={pin.id}>
          <DiamondPinMesh
            pin={pin}
            color={pinColor}
            onPinClick={handlePinClick}
            replayEnabled={replayEnabled}
          />

          <Text
            position={[pin.worldPosition[0], pin.worldPosition[1] + 1.2, pin.worldPosition[2]]}
            fontSize={0.35}
            maxWidth={4}
            anchorX="center"
            anchorY="bottom"
            color="white"
            outlineWidth={0.02}
            outlineColor="#000"
            material-depthTest={false}
          >
            {pin.note.trim() !== "" ? pin.note : "Pin"}
          </Text>

          {editingPinId === pin.id && (
            <Html
              transform
              sprite
              distanceFactor={60}
              position={[pin.worldPosition[0], pin.worldPosition[1] + 2, pin.worldPosition[2]]}
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
        onBlur={() => onConfirm(inputRef.current?.value ?? "")}
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
