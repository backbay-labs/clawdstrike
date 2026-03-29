import type * as THREE from "three";

/**
 * Mirrors the internal wawa-vfx VFXEmitterRef interface (v1.2.10).
 * The package declares but does not export this type.
 * Centralised here; update if wawa-vfx exports it in a future version.
 */
export interface VFXEmitterRef extends THREE.Object3D {
  startEmitting: (reset?: boolean) => void;
  stopEmitting: () => void;
  emitAtPos: (position: THREE.Vector3 | null, reset?: boolean) => void;
}
