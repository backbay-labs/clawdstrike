import { describe, it, expect, afterEach } from "vitest";
import {
  registerCapsuleRenderer,
  unregisterCapsuleRenderer,
  getCapsuleRenderer,
  getRegisteredCapsuleKinds,
} from "../capsule-renderer-registry";

// Simple functional components for testing (no React rendering needed)
function TestRendererA() {
  return null;
}
function TestRendererB() {
  return null;
}

describe("capsule-renderer-registry", () => {
  const disposers: Array<() => void> = [];

  afterEach(() => {
    for (const d of disposers) d();
    disposers.length = 0;
  });

  // NOTE: Built-in renderers are registered at module load in DockSystem.tsx.
  // These tests focus on the registry CRUD mechanics using custom test renderers.

  it("registers and retrieves a renderer by kind", () => {
    disposers.push(registerCapsuleRenderer("test-kind", TestRendererA));
    const renderer = getCapsuleRenderer("test-kind");
    expect(renderer).toBe(TestRendererA);
  });

  it("returns undefined for unregistered kind", () => {
    const renderer = getCapsuleRenderer("nonexistent-kind");
    expect(renderer).toBeUndefined();
  });

  it("returns dispose function that removes renderer", () => {
    const dispose = registerCapsuleRenderer("disposable-kind", TestRendererA);
    expect(getCapsuleRenderer("disposable-kind")).toBe(TestRendererA);

    dispose();
    expect(getCapsuleRenderer("disposable-kind")).toBeUndefined();
  });

  it("stale dispose does not remove a newer renderer registration", () => {
    const staleDispose = registerCapsuleRenderer("hmr-kind", TestRendererA);
    expect(getCapsuleRenderer("hmr-kind")).toBe(TestRendererA);

    unregisterCapsuleRenderer("hmr-kind");
    disposers.push(registerCapsuleRenderer("hmr-kind", TestRendererB));

    staleDispose();
    expect(getCapsuleRenderer("hmr-kind")).toBe(TestRendererB);
  });

  it("throws on duplicate kind registration", () => {
    disposers.push(registerCapsuleRenderer("dup-kind", TestRendererA));
    expect(() => registerCapsuleRenderer("dup-kind", TestRendererB)).toThrow(
      'Capsule renderer for kind "dup-kind" is already registered',
    );
  });

  it("unregisterCapsuleRenderer is no-op for unknown kind", () => {
    expect(() => unregisterCapsuleRenderer("unknown-kind")).not.toThrow();
  });

  it("getRegisteredCapsuleKinds returns all registered kinds", () => {
    disposers.push(registerCapsuleRenderer("kind-alpha", TestRendererA));
    disposers.push(registerCapsuleRenderer("kind-beta", TestRendererB));

    const kinds = getRegisteredCapsuleKinds();
    expect(kinds).toContain("kind-alpha");
    expect(kinds).toContain("kind-beta");
  });
});
