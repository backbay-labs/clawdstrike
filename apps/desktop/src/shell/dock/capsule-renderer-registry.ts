/**
 * CapsuleRendererRegistry - Registry mapping CapsuleKind strings to React
 * components that render capsule content.
 *
 * Replaces the switch statement in getCapsuleContent() with registry-based
 * dispatch, allowing plugins to register custom capsule renderers without
 * modifying DockSystem.tsx.
 */
import type { ComponentType } from "react";
import type { CapsuleContentProps } from "./types";

const rendererMap = new Map<string, ComponentType<CapsuleContentProps>>();

/**
 * Register a capsule content renderer for a given CapsuleKind.
 * Returns a dispose function to unregister.
 * Throws if a renderer for the given kind is already registered.
 */
export function registerCapsuleRenderer(
  kind: string,
  component: ComponentType<CapsuleContentProps>,
): () => void {
  if (rendererMap.has(kind)) {
    throw new Error(
      `Capsule renderer for kind "${kind}" is already registered`,
    );
  }
  rendererMap.set(kind, component);
  return () => {
    if (rendererMap.get(kind) === component) {
      rendererMap.delete(kind);
    }
  };
}

/**
 * Unregister a capsule renderer by kind. No-op if not found.
 */
export function unregisterCapsuleRenderer(kind: string): void {
  rendererMap.delete(kind);
}

/**
 * Get the renderer component for a given CapsuleKind.
 * Returns undefined if no renderer is registered for that kind.
 */
export function getCapsuleRenderer(
  kind: string,
): ComponentType<CapsuleContentProps> | undefined {
  return rendererMap.get(kind);
}

/**
 * Get all registered capsule kinds.
 */
export function getRegisteredCapsuleKinds(): string[] {
  return Array.from(rendererMap.keys());
}

/** Convenience object for import ergonomics. */
export const capsuleRendererRegistry = {
  register: registerCapsuleRenderer,
  unregister: unregisterCapsuleRenderer,
  get: getCapsuleRenderer,
  kinds: getRegisteredCapsuleKinds,
};
