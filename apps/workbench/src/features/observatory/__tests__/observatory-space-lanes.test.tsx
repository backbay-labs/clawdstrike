import { describe, expect, it, vi } from "vitest";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";

// ---------------------------------------------------------------------------
// Mocks — R3F and wawa-vfx run in a canvas context not available in jsdom
// ---------------------------------------------------------------------------

vi.mock("@react-three/fiber", () => ({
  useFrame: vi.fn(),
  extend: vi.fn(),
}));

vi.mock("@react-three/drei", () => ({
  Line: () => null,
}));

vi.mock("wawa-vfx", () => ({
  VFXEmitter: (_props: unknown) => null,
  VFXParticles: (_props: unknown) => null,
  RenderMode: { StretchBillboard: "StretchBillboard", Billboard: "Billboard" },
}));

vi.mock("three", async () => {
  const actual = await vi.importActual<typeof import("three")>("three");
  return {
    ...actual,
    TubeGeometry: class TubeGeometry {
      dispose = vi.fn();
    },
    ShaderMaterial: class ShaderMaterial {
      uniforms = { dashOffset: { value: 0 }, color: { value: null } };
      dispose = vi.fn();
    },
  };
});

// ---------------------------------------------------------------------------
// Test: module exports a named component
// ---------------------------------------------------------------------------

describe("ObservatorySpaceLanes", () => {
  it("exports a named React component", async () => {
    const mod = await import(
      "@/features/observatory/components/world-canvas/ObservatorySpaceLanes"
    );
    expect(typeof mod.ObservatorySpaceLanes).toBe("function");
  });

  it("renders without crashing (smoke test)", async () => {
    const { ObservatorySpaceLanes } = await import(
      "@/features/observatory/components/world-canvas/ObservatorySpaceLanes"
    );
    const Wrapper = ({ children }: { children: ReactNode }) => <>{children}</>;
    expect(() => render(<Wrapper><ObservatorySpaceLanes /></Wrapper>)).not.toThrow();
  });
});
